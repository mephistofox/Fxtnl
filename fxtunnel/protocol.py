"""
Framed protocol with AES-256-GCM encryption.
"""

import os
import struct
import asyncio
import hashlib
import secrets
from enum import IntEnum
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MsgType(IntEnum):
    """Message types."""
    SERVER_IDENTITY = 0 # Server sends identity fingerprint
    AUTH = 1           # Client requests auth (sends client_id)
    AUTH_CHALLENGE = 2 # Server sends challenge
    AUTH_RESPONSE = 3  # Client sends HMAC response
    AUTH_OK = 4        # Auth successful
    AUTH_FAIL = 5      # Auth failed
    OPEN_PORT = 10     # Request to open port (client -> server)
    PORT_OPENED = 11   # Port opened successfully (server -> client)
    PORT_ERROR = 12    # Failed to open port (server -> client)
    NEW_CONN = 20      # New incoming connection (server -> client for reverse tunnel)
    CONN_READY = 22    # Client ready to handle connection (client -> server)
    CONN_CLOSED = 21   # Connection closed
    DATA = 30          # Data packet
    PING = 40          # Heartbeat ping
    PONG = 41          # Heartbeat pong
    SHUTDOWN = 50      # Graceful shutdown notification


def generate_key() -> bytes:
    """Generate a new 256-bit key."""
    return secrets.token_bytes(32)


def key_to_hex(key: bytes) -> str:
    """Convert key to hex string."""
    return key.hex()


def hex_to_key(hex_str: str) -> bytes:
    """Convert hex string to key."""
    return bytes.fromhex(hex_str)


class Cipher:
    """AES-256-GCM cipher for message encryption."""

    def __init__(self, key: bytes):
        self.aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data. Returns nonce + ciphertext."""
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data. Input is nonce + ciphertext."""
        nonce = data[:12]
        ciphertext = data[12:]
        return self.aesgcm.decrypt(nonce, ciphertext, None)


class FramedProtocol:
    """
    Framed protocol handler.

    Frame format:
    [4 bytes: length][encrypted payload]

    Payload format (after decryption):
    [1 byte: msg_type][4 bytes: conn_id][data]
    """

    HEADER_SIZE = 4
    MAX_FRAME_SIZE = 1024 * 1024  # 1 MB

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cipher: Optional[Cipher] = None):
        self.reader = reader
        self.writer = writer
        self.cipher = cipher
        self._buffer = b""

    def set_cipher(self, cipher: Cipher):
        """Set cipher after initial handshake."""
        self.cipher = cipher

    async def send(self, msg_type: MsgType, conn_id: int, data: bytes = b""):
        """Send a framed message."""
        payload = struct.pack("!BI", msg_type, conn_id) + data

        if self.cipher:
            payload = self.cipher.encrypt(payload)

        frame = struct.pack("!I", len(payload)) + payload
        self.writer.write(frame)
        await self.writer.drain()

    async def recv(self) -> Optional[tuple[MsgType, int, bytes]]:
        """
        Receive a framed message.
        Returns (msg_type, conn_id, data) or None on EOF.
        """
        # Read header
        header = await self._read_exact(self.HEADER_SIZE)
        if header is None:
            return None

        length = struct.unpack("!I", header)[0]

        if length > self.MAX_FRAME_SIZE:
            raise ValueError(f"Frame too large: {length}")

        # Read payload
        payload = await self._read_exact(length)
        if payload is None:
            return None

        # Decrypt if cipher is set
        if self.cipher:
            try:
                payload = self.cipher.decrypt(payload)
            except Exception as e:
                raise ValueError(f"Decryption failed: {e}")

        # Parse payload
        if len(payload) < 5:
            raise ValueError("Payload too small")

        msg_type = MsgType(payload[0])
        conn_id = struct.unpack("!I", payload[1:5])[0]
        data = payload[5:]

        return msg_type, conn_id, data

    async def _read_exact(self, n: int) -> Optional[bytes]:
        """Read exactly n bytes."""
        while len(self._buffer) < n:
            chunk = await self.reader.read(4096)
            if not chunk:
                return None
            self._buffer += chunk

        result = self._buffer[:n]
        self._buffer = self._buffer[n:]
        return result

    def close(self):
        """Close the connection."""
        self.writer.close()

    async def wait_closed(self):
        """Wait for connection to close."""
        await self.writer.wait_closed()


# Message builders for convenience

def build_open_port_msg(port: int, mode: str) -> bytes:
    """Build OPEN_PORT message data."""
    return struct.pack("!H", port) + mode.encode("utf-8")


def parse_open_port_msg(data: bytes) -> tuple[int, str]:
    """Parse OPEN_PORT message data."""
    port = struct.unpack("!H", data[:2])[0]
    mode = data[2:].decode("utf-8")
    return port, mode


def build_port_opened_msg(port: int) -> bytes:
    """Build PORT_OPENED message data."""
    return struct.pack("!H", port)


def parse_port_opened_msg(data: bytes) -> int:
    """Parse PORT_OPENED message data."""
    return struct.unpack("!H", data[:2])[0]


def build_new_conn_msg(port: int, is_udp: bool = False) -> bytes:
    """Build NEW_CONN message data."""
    flags = 1 if is_udp else 0
    return struct.pack("!HB", port, flags)


def parse_new_conn_msg(data: bytes) -> tuple[int, bool]:
    """Parse NEW_CONN message data. Returns (port, is_udp)."""
    if len(data) >= 3:
        port, flags = struct.unpack("!HB", data[:3])
        is_udp = bool(flags & 1)
    else:
        # Legacy format without flags
        port = struct.unpack("!H", data[:2])[0]
        is_udp = False
    return port, is_udp


# Challenge-response authentication helpers

CHALLENGE_SIZE = 32  # 256-bit challenge


def generate_challenge() -> bytes:
    """Generate a random challenge for authentication."""
    return secrets.token_bytes(CHALLENGE_SIZE)


def compute_auth_response(key: bytes, challenge: bytes) -> bytes:
    """
    Compute HMAC-SHA256 response for challenge-response authentication.

    Args:
        key: The shared secret key (32 bytes)
        challenge: The random challenge from server (32 bytes)

    Returns:
        HMAC-SHA256 digest (32 bytes)
    """
    import hmac
    return hmac.new(key, challenge, hashlib.sha256).digest()


def verify_auth_response(key: bytes, challenge: bytes, response: bytes) -> bool:
    """
    Verify HMAC-SHA256 response for challenge-response authentication.

    Args:
        key: The shared secret key (32 bytes)
        challenge: The random challenge sent to client (32 bytes)
        response: The HMAC response from client (32 bytes)

    Returns:
        True if response is valid, False otherwise
    """
    import hmac
    expected = hmac.new(key, challenge, hashlib.sha256).digest()
    return hmac.compare_digest(expected, response)
