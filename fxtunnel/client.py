"""
Tunnel client - connects to server and manages tunnels.

Client generates key on first run, sends all configuration to server.
"""

import asyncio
import hashlib
import os
import random
import signal
import stat
from enum import Enum
from pathlib import Path
from typing import Optional, Literal

from .protocol import (
    FramedProtocol, Cipher, MsgType,
    generate_key, hex_to_key, key_to_hex,
    build_new_conn_msg,
    compute_auth_response
)
from .logging import get_logger, bind_context, clear_context
from .config import get_data_dir


class ConnectionState(Enum):
    """Client connection states."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    AUTHENTICATING = "authenticating"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    SHUTTING_DOWN = "shutting_down"

logger = get_logger(__name__)

# Paths
DATA_DIR = get_data_dir()
KEY_FILE = DATA_DIR / "key"
KNOWN_HOSTS_FILE = DATA_DIR / "known_hosts"

# Reconnect backoff with jitter
MAX_RECONNECT_DELAY = 30
INITIAL_RECONNECT_DELAY = 1


def get_backoff_delay(attempt: int) -> float:
    """Calculate backoff delay with jitter."""
    base_delay = min(2 ** attempt, MAX_RECONNECT_DELAY)
    jitter = random.uniform(0, base_delay * 0.1)  # 10% jitter
    return base_delay + jitter


def load_known_hosts() -> dict[str, str]:
    """Load known hosts from file."""
    known_hosts = {}
    if KNOWN_HOSTS_FILE.exists():
        for line in KNOWN_HOSTS_FILE.read_text().strip().split('\n'):
            if line and ' ' in line:
                host, fingerprint = line.split(' ', 1)
                known_hosts[host] = fingerprint
    return known_hosts


def save_known_host(host: str, fingerprint: str):
    """Save a host fingerprint to known_hosts file."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    known_hosts = load_known_hosts()
    known_hosts[host] = fingerprint

    lines = [f"{h} {fp}" for h, fp in sorted(known_hosts.items())]
    KNOWN_HOSTS_FILE.write_text('\n'.join(lines) + '\n')
    os.chmod(KNOWN_HOSTS_FILE, stat.S_IRUSR | stat.S_IWUSR)


def compute_fingerprint(key: bytes) -> str:
    """Compute SHA256 fingerprint of a key."""
    digest = hashlib.sha256(key).hexdigest()
    return ':'.join(digest[i:i+2] for i in range(0, 16, 2))


class TunnelClient:
    """Tunnel client."""

    def __init__(self, server_ip: str, server_port: int = 9000, bind_address: str = "localhost", accept_new_host: bool = False):
        self.server_ip = server_ip
        self.server_port = server_port
        self.bind_address = bind_address
        self.accept_new_host = accept_new_host
        self.key: Optional[bytes] = None
        self.protocol: Optional[FramedProtocol] = None
        self.tunnels: list[tuple[int, int, str]] = []  # (local_port, remote_port, mode)
        self.connections: dict[int, tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self.udp_proxies: dict[int, 'UDPLocalProxy'] = {}  # conn_id -> proxy
        self.local_servers: list[asyncio.Server] = []

        # State machine
        self._state = ConnectionState.DISCONNECTED
        self._state_lock = asyncio.Lock()

        self._reconnect_attempt = 0
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._recv_task: Optional[asyncio.Task] = None
        self._conn_counter = 0
        self._tasks: list[asyncio.Task] = []

        # Statistics
        self.bytes_sent = 0
        self.bytes_received = 0
        self.connections_total = 0

    @property
    def state(self) -> ConnectionState:
        """Get current connection state."""
        return self._state

    @property
    def is_running(self) -> bool:
        """Check if client is running (not shutting down)."""
        return self._state != ConnectionState.SHUTTING_DOWN

    @property
    def is_connected(self) -> bool:
        """Check if client is connected."""
        return self._state == ConnectionState.CONNECTED

    async def _set_state(self, new_state: ConnectionState):
        """Thread-safe state transition."""
        async with self._state_lock:
            old_state = self._state
            self._state = new_state
            logger.debug(f"State: {old_state.value} -> {new_state.value}")

    def load_or_generate_key(self):
        """Load existing key or generate new one."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        if KEY_FILE.exists():
            hex_key = KEY_FILE.read_text().strip()
            self.key = hex_to_key(hex_key)
            logger.info("Loaded existing key")
            logger.debug(f"Key fingerprint: {compute_fingerprint(self.key)}")
        else:
            self.key = generate_key()
            KEY_FILE.write_text(key_to_hex(self.key))
            # Set secure permissions (owner read/write only)
            os.chmod(KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)
            logger.info(f"Generated new key (saved to {KEY_FILE})")
            logger.info(f"Key fingerprint: {compute_fingerprint(self.key)}")

    def add_tunnel(self, local_port: int, remote_port: int, mode: str = "tcp"):
        """Add a tunnel configuration."""
        self.tunnels.append((local_port, remote_port, mode))

    async def connect(self) -> bool:
        """Connect to tunnel server."""
        await self._set_state(ConnectionState.CONNECTING)

        try:
            logger.info(f"Connecting to {self.server_ip}:{self.server_port}...")

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.server_ip, self.server_port),
                timeout=30
            )

            self.protocol = FramedProtocol(reader, writer)

            await self._set_state(ConnectionState.AUTHENTICATING)

            # Receive server identity first
            msg = await asyncio.wait_for(self.protocol.recv(), timeout=30)
            if msg is None:
                logger.error("Server closed connection before identity")
                await self._set_state(ConnectionState.DISCONNECTED)
                return False

            msg_type, _, data = msg
            if msg_type != MsgType.SERVER_IDENTITY:
                logger.error(f"Expected SERVER_IDENTITY, got {msg_type}")
                await self._set_state(ConnectionState.DISCONNECTED)
                return False

            server_fingerprint = data.decode()
            host_key = f"{self.server_ip}:{self.server_port}"
            known_hosts = load_known_hosts()

            if host_key in known_hosts:
                # Verify fingerprint matches
                if known_hosts[host_key] != server_fingerprint:
                    logger.error("=" * 60)
                    logger.error("WARNING: SERVER IDENTITY HAS CHANGED!")
                    logger.error("=" * 60)
                    logger.error(f"Host: {host_key}")
                    logger.error(f"Expected: {known_hosts[host_key]}")
                    logger.error(f"Received: {server_fingerprint}")
                    logger.error("")
                    logger.error("This could indicate a man-in-the-middle attack!")
                    logger.error("If you trust this server, remove the old entry from:")
                    logger.error(f"  {KNOWN_HOSTS_FILE}")
                    logger.error("=" * 60)
                    await self._set_state(ConnectionState.DISCONNECTED)
                    return False
                logger.debug(f"Server fingerprint verified: {server_fingerprint}")
            else:
                # New host
                if self.accept_new_host:
                    save_known_host(host_key, server_fingerprint)
                    logger.info(f"Added server to known hosts: {server_fingerprint}")
                else:
                    logger.info("=" * 60)
                    logger.info("NEW SERVER IDENTITY")
                    logger.info("=" * 60)
                    logger.info(f"Host: {host_key}")
                    logger.info(f"Fingerprint: {server_fingerprint}")
                    logger.info("")
                    logger.info("This is the first time connecting to this server.")
                    logger.info("To accept automatically, use --accept-new-host")
                    logger.info("=" * 60)

                    # For now, auto-accept with warning (TOFU behavior)
                    save_known_host(host_key, server_fingerprint)
                    logger.info(f"Added server to known hosts")

            # Send AUTH with key fingerprint (for identification)
            fingerprint = compute_fingerprint(self.key)
            await self.protocol.send(MsgType.AUTH, 0, fingerprint.encode())

            # Wait for challenge from server
            msg = await asyncio.wait_for(self.protocol.recv(), timeout=30)
            if msg is None:
                logger.error("Server closed connection during auth")
                await self._set_state(ConnectionState.DISCONNECTED)
                return False

            msg_type, _, challenge = msg

            if msg_type == MsgType.AUTH_FAIL:
                error_msg = challenge.decode() if challenge else "Unknown error"
                logger.error(f"Authentication failed: {error_msg}")
                await self._set_state(ConnectionState.DISCONNECTED)
                return False

            if msg_type != MsgType.AUTH_CHALLENGE:
                logger.error(f"Unexpected response: {msg_type}")
                await self._set_state(ConnectionState.DISCONNECTED)
                return False

            # Check if this is TOFU mode
            if challenge == b"TOFU":
                # Server needs full key (first connection)
                logger.info("First connection - sending key for registration")
                await self.protocol.send(MsgType.AUTH_RESPONSE, 0, self.key)
            else:
                # Compute HMAC response to challenge
                response = compute_auth_response(self.key, challenge)
                await self.protocol.send(MsgType.AUTH_RESPONSE, 0, response)

            # Wait for AUTH_OK or AUTH_FAIL
            msg = await asyncio.wait_for(self.protocol.recv(), timeout=30)
            if msg is None:
                logger.error("Server closed connection during auth")
                await self._set_state(ConnectionState.DISCONNECTED)
                return False

            msg_type, _, data = msg

            if msg_type == MsgType.AUTH_FAIL:
                error_msg = data.decode() if data else "Unknown error"
                logger.error(f"Authentication failed: {error_msg}")
                await self._set_state(ConnectionState.DISCONNECTED)
                return False

            if msg_type != MsgType.AUTH_OK:
                logger.error(f"Unexpected response: {msg_type}")
                await self._set_state(ConnectionState.DISCONNECTED)
                return False

            # Set up encryption
            cipher = Cipher(self.key)
            self.protocol.set_cipher(cipher)

            logger.info("Connected and authenticated")
            self._reconnect_attempt = 0
            await self._set_state(ConnectionState.CONNECTED)
            return True

        except asyncio.TimeoutError:
            logger.error("Connection timed out - server may be unreachable")
            await self._set_state(ConnectionState.DISCONNECTED)
            return False
        except ConnectionRefusedError:
            logger.error(f"Connection refused - is server running on {self.server_ip}:{self.server_port}?")
            await self._set_state(ConnectionState.DISCONNECTED)
            return False
        except OSError as e:
            if e.errno == 111:  # Connection refused
                logger.error(f"Connection refused - is server running on {self.server_ip}:{self.server_port}?")
            elif e.errno == 113:  # No route to host
                logger.error(f"No route to host {self.server_ip}")
            elif e.errno == 101:  # Network unreachable
                logger.error("Network unreachable - check your network connection")
            else:
                logger.error(f"Connection failed: {e}")
            await self._set_state(ConnectionState.DISCONNECTED)
            return False
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            await self._set_state(ConnectionState.DISCONNECTED)
            return False

    async def start_local_listeners(self):
        """Start local port listeners."""
        for local_port, remote_port, mode in self.tunnels:
            try:
                if mode == "tcp":
                    server = await asyncio.start_server(
                        lambda r, w, rp=remote_port: self._handle_local_connection(r, w, rp),
                        self.bind_address, local_port
                    )
                    self.local_servers.append(server)
                    logger.info(f"Listening on {self.bind_address}:{local_port} -> remote:{remote_port}")

                elif mode == "udp":
                    # UDP support
                    loop = asyncio.get_event_loop()
                    proxy = UDPLocalProxy(self, remote_port)
                    transport, _ = await loop.create_datagram_endpoint(
                        lambda p=proxy: p,
                        local_addr=(self.bind_address, local_port)
                    )
                    self.local_servers.append(transport)
                    # Store proxy for data routing (will be registered when connections are made)
                    proxy._client_ref = self
                    logger.info(f"UDP listening on {self.bind_address}:{local_port} -> remote:{remote_port}")

            except PermissionError:
                logger.error(f"Permission denied for port {local_port} - try a port > 1024 or run as root")
                return False
            except OSError as e:
                if e.errno == 98:  # Address already in use
                    logger.error(f"Port {local_port} is already in use")
                else:
                    logger.error(f"Failed to listen on port {local_port}: {e}")
                return False
            except Exception as e:
                logger.error(f"Failed to listen on port {local_port}: {e}")
                return False

        return True

    async def _handle_local_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, remote_port: int):
        """Handle new local TCP connection."""
        self._conn_counter += 1
        self.connections_total += 1
        conn_id = self._conn_counter

        addr = writer.get_extra_info('peername')
        logger.debug(f"New local connection {conn_id} from {addr}")

        self.connections[conn_id] = (reader, writer)

        try:
            # Tell server to open connection to remote port
            await self.protocol.send(MsgType.NEW_CONN, conn_id, build_new_conn_msg(remote_port))

            # Read from local and forward to tunnel
            while self.is_running and self.is_connected:
                data = await reader.read(4096)
                if not data:
                    break
                self.bytes_sent += len(data)
                await self.protocol.send(MsgType.DATA, conn_id, data)

        except ConnectionResetError:
            logger.debug(f"Connection {conn_id} reset by peer")
        except BrokenPipeError:
            logger.debug(f"Connection {conn_id} broken pipe")
        except Exception as e:
            logger.debug(f"Local connection {conn_id} error: {e}")
        finally:
            # Notify server
            if self.is_connected and self.protocol:
                try:
                    await self.protocol.send(MsgType.CONN_CLOSED, conn_id)
                except Exception:
                    pass

            self.connections.pop(conn_id, None)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.debug(f"Local connection {conn_id} closed")

    async def run(self):
        """Main client loop with auto-reconnect."""
        # Start local listeners first
        if not await self.start_local_listeners():
            logger.error("Failed to start local listeners")
            return

        while self.is_running:
            if await self.connect():
                # Start tasks
                self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
                self._recv_task = asyncio.create_task(self._receive_loop())

                # Wait for disconnect
                try:
                    await self._recv_task
                except asyncio.CancelledError:
                    pass

                await self._disconnect()

            if not self.is_running:
                break

            # Set reconnecting state
            await self._set_state(ConnectionState.RECONNECTING)

            # Reconnect with exponential backoff and jitter
            delay = get_backoff_delay(self._reconnect_attempt)
            self._reconnect_attempt += 1

            logger.info(f"Reconnecting in {delay:.1f}s...")
            await asyncio.sleep(delay)

        # Cleanup local servers
        await self._cleanup_local()

    async def _receive_loop(self):
        """Receive and handle messages from server."""
        while self.is_running and self.is_connected:
            try:
                msg = await asyncio.wait_for(self.protocol.recv(), timeout=60)
                if msg is None:
                    logger.warning("Server disconnected")
                    break

                msg_type, conn_id, data = msg
                await self._handle_message(msg_type, conn_id, data)

            except asyncio.TimeoutError:
                logger.warning("Server timeout - no response for 60s")
                break
            except Exception as e:
                logger.error(f"Receive error: {e}")
                break

    async def _handle_message(self, msg_type: MsgType, conn_id: int, data: bytes):
        """Handle message from server."""
        if msg_type == MsgType.DATA:
            self.bytes_received += len(data)
            await self._forward_to_local(conn_id, data)

        elif msg_type == MsgType.CONN_CLOSED:
            await self._close_local_connection(conn_id)

        elif msg_type == MsgType.PING:
            await self.protocol.send(MsgType.PONG, 0)

        elif msg_type == MsgType.PONG:
            pass

        elif msg_type == MsgType.SHUTDOWN:
            logger.info("Server requested graceful shutdown")
            # Don't reconnect when server shuts down gracefully
            await self._set_state(ConnectionState.SHUTTING_DOWN)

    async def _forward_to_local(self, conn_id: int, data: bytes):
        """Forward data to local connection (TCP or UDP)."""
        # Check UDP proxy first
        if conn_id in self.udp_proxies:
            self.udp_proxies[conn_id].send_to_client(conn_id, data)
            return

        # TCP connection
        if conn_id not in self.connections:
            return

        _, writer = self.connections[conn_id]
        try:
            writer.write(data)
            await writer.drain()
        except Exception as e:
            logger.debug(f"Forward error: {e}")

    async def _close_local_connection(self, conn_id: int):
        """Close local connection."""
        if conn_id not in self.connections:
            return

        _, writer = self.connections.pop(conn_id)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    async def _heartbeat_loop(self):
        """Send periodic heartbeats."""
        while self.is_running and self.is_connected:
            try:
                await asyncio.sleep(15)
                await self.protocol.send(MsgType.PING, 0)
            except asyncio.CancelledError:
                break
            except Exception:
                break

    async def _disconnect(self):
        """Disconnect from server."""
        await self._set_state(ConnectionState.DISCONNECTED)

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        # Cancel all tasks
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

        # Close protocol
        if self.protocol:
            self.protocol.close()
            try:
                await self.protocol.wait_closed()
            except Exception:
                pass
            self.protocol = None

    async def _cleanup_local(self):
        """Cleanup local servers and connections."""
        # Close local servers
        for server in self.local_servers:
            if hasattr(server, 'close'):
                server.close()
                if hasattr(server, 'wait_closed'):
                    try:
                        await server.wait_closed()
                    except Exception:
                        pass
        self.local_servers.clear()

        # Close connections
        for conn_id in list(self.connections.keys()):
            await self._close_local_connection(conn_id)

    async def stop(self):
        """Stop the client gracefully."""
        logger.info("Shutting down...")
        await self._set_state(ConnectionState.SHUTTING_DOWN)

        # Send shutdown notification to server
        if self.protocol and self.is_connected:
            try:
                await self.protocol.send(MsgType.SHUTDOWN, 0)
                logger.debug("Sent shutdown notification to server")
            except Exception as e:
                logger.debug(f"Failed to send shutdown: {e}")

        if self._recv_task:
            self._recv_task.cancel()

    def stop_sync(self):
        """Synchronous stop for signal handlers."""
        # Create task to run async stop
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(self.stop())
        else:
            loop.run_until_complete(self.stop())


class UDPLocalProxy(asyncio.DatagramProtocol):
    """Local UDP proxy."""

    def __init__(self, client: TunnelClient, remote_port: int):
        self.client = client
        self.remote_port = remote_port
        self.transport = None
        self.clients: dict[tuple, int] = {}  # addr -> conn_id
        self.conn_to_addr: dict[int, tuple] = {}  # conn_id -> addr

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if not self.client.is_connected:
            return

        if addr not in self.clients:
            self.client._conn_counter += 1
            self.client.connections_total += 1
            conn_id = self.client._conn_counter
            self.clients[addr] = conn_id
            self.conn_to_addr[conn_id] = addr
            # Register this proxy for the conn_id
            self.client.udp_proxies[conn_id] = self
            # Send NEW_CONN with UDP flag
            asyncio.create_task(
                self.client.protocol.send(
                    MsgType.NEW_CONN,
                    conn_id,
                    build_new_conn_msg(self.remote_port, is_udp=True)
                )
            )
            logger.debug(f"New UDP client {addr} -> conn {conn_id}")

        conn_id = self.clients[addr]
        self.client.bytes_sent += len(data)
        asyncio.create_task(
            self.client.protocol.send(MsgType.DATA, conn_id, data)
        )

    def send_to_client(self, conn_id: int, data: bytes):
        """Send data back to the UDP client."""
        if conn_id in self.conn_to_addr:
            addr = self.conn_to_addr[conn_id]
            self.transport.sendto(data, addr)


async def run_client(
    server_ip: str,
    tunnels: list[tuple[int, int, Literal['tcp', 'udp']]],
    server_port: int = 9000,
    bind: str = "localhost",
    verbose: bool = False,
    accept_new_host: bool = False
):
    """Run the tunnel client."""
    bind_context(server=f"{server_ip}:{server_port}")
    client = TunnelClient(server_ip, server_port, bind, accept_new_host)
    client.load_or_generate_key()

    for local_port, remote_port, mode in tunnels:
        client.add_tunnel(local_port, remote_port, mode)

    # Set up signal handlers
    loop = asyncio.get_event_loop()

    def signal_handler():
        client.stop_sync()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    await client.run()

    # Print statistics on exit
    if client.bytes_sent > 0 or client.bytes_received > 0:
        sent_mb = client.bytes_sent / (1024 * 1024)
        recv_mb = client.bytes_received / (1024 * 1024)
        logger.info(
            "Client statistics",
            bytes_sent_mb=round(sent_mb, 2),
            bytes_received_mb=round(recv_mb, 2),
            connections=client.connections_total
        )

    logger.info("Client stopped")
    clear_context()


if __name__ == "__main__":
    asyncio.run(run_client("127.0.0.1", [(5432, 5432, "tcp")]))
