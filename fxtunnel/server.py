"""
Tunnel server - reverse tunnel mode (like SSH -R).

Listens on port 9000 for tunnel client connection.
Client sends OPEN_PORT request, server starts listening on that port.
When external connections arrive, server notifies client to connect to local service.

Architecture:
[Internet] -> [Server:remote_port] -> [Tunnel] -> [Client] -> [localhost:local_port]
"""

import asyncio
import hashlib
import os
import signal
import stat
from pathlib import Path
from typing import Optional

from .protocol import (
    FramedProtocol, Cipher, MsgType,
    generate_key, hex_to_key, key_to_hex,
    parse_open_port_msg,
    build_new_conn_msg,
    generate_challenge, verify_auth_response
)
from .logging import get_logger, bind_context, clear_context
from .config import get_data_dir

logger = get_logger(__name__)

# Default tunnel port
TUNNEL_PORT = 9000

# Paths
DATA_DIR = get_data_dir()
KEY_FILE = DATA_DIR / "authorized_key"
SERVER_KEY_FILE = DATA_DIR / "server_key"


def compute_fingerprint(key: bytes) -> str:
    """Compute SHA256 fingerprint of a key."""
    digest = hashlib.sha256(key).hexdigest()
    return ':'.join(digest[i:i+2] for i in range(0, 16, 2))


class ClientSession:
    """Per-client session state."""

    def __init__(self, addr: tuple, protocol: FramedProtocol):
        self.addr = addr
        self.protocol = protocol
        # Connections from external clients (conn_id -> streams)
        self.connections: dict[int, tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        # Pending connections waiting for client CONN_READY
        self.pending_connections: dict[int, tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        # Public-facing servers (remote_port -> (server, local_port))
        self.public_servers: dict[int, tuple[asyncio.Server, int]] = {}
        self.udp_transports: dict[int, asyncio.DatagramTransport] = {}
        self.running = False
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._tasks: list[asyncio.Task] = []
        self._conn_counter = 0

        # Statistics
        self.bytes_sent = 0
        self.bytes_received = 0
        self.connections_total = 0


class TunnelServer:
    """Main tunnel server for reverse tunneling."""

    def __init__(self, max_clients: int = 10, allowed_ports: list[int] | None = None):
        self.authorized_key: Optional[bytes] = None
        self.server_identity_key: Optional[bytes] = None
        self.max_clients = max_clients
        self.allowed_ports = set(allowed_ports) if allowed_ports else None  # None = all allowed
        self.sessions: dict[tuple, ClientSession] = {}
        self._sessions_lock = asyncio.Lock()

    def is_port_allowed(self, port: int) -> bool:
        """Check if port is allowed."""
        if self.allowed_ports is None:
            return True
        return port in self.allowed_ports

    def load_or_generate_server_key(self):
        """Load or generate server identity key."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        if SERVER_KEY_FILE.exists():
            hex_key = SERVER_KEY_FILE.read_text().strip()
            self.server_identity_key = hex_to_key(hex_key)
            logger.info("Loaded server identity key")
        else:
            self.server_identity_key = generate_key()
            SERVER_KEY_FILE.write_text(key_to_hex(self.server_identity_key))
            os.chmod(SERVER_KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)
            logger.info(f"Generated new server identity key (saved to {SERVER_KEY_FILE})")

        fingerprint = compute_fingerprint(self.server_identity_key)
        logger.info(f"Server fingerprint: {fingerprint}")

    def load_key(self):
        """Load authorized key from file."""
        if KEY_FILE.exists():
            hex_key = KEY_FILE.read_text().strip()
            self.authorized_key = hex_to_key(hex_key)
            logger.info("Loaded authorized key")
            logger.debug(f"Key fingerprint: {compute_fingerprint(self.authorized_key)}")
        else:
            logger.info("No authorized key - will accept first connection (TOFU)")

    def save_key(self, key: bytes):
        """Save authorized key to file."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        KEY_FILE.write_text(key_to_hex(key))
        # Set secure permissions (owner read/write only)
        os.chmod(KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)
        self.authorized_key = key
        logger.info(f"Saved authorized key to {KEY_FILE}")
        logger.info(f"Key fingerprint: {compute_fingerprint(key)}")

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming tunnel client connection."""
        addr = writer.get_extra_info('peername')
        client_ip = f"{addr[0]}:{addr[1]}" if addr else "unknown"
        bind_context(client=client_ip)
        logger.info("Client connected", client=client_ip)

        # Check max clients
        async with self._sessions_lock:
            if len(self.sessions) >= self.max_clients:
                logger.warning("Max clients reached, rejecting", max_clients=self.max_clients, client=client_ip)
                writer.close()
                await writer.wait_closed()
                clear_context()
                return

        protocol = FramedProtocol(reader, writer)
        session = ClientSession(addr, protocol)

        try:
            # Send server identity first
            server_fingerprint = compute_fingerprint(self.server_identity_key)
            await protocol.send(MsgType.SERVER_IDENTITY, 0, server_fingerprint.encode())

            # Wait for AUTH message (client initiates auth)
            msg = await asyncio.wait_for(protocol.recv(), timeout=30)
            if msg is None:
                logger.warning(f"Client {addr} disconnected before auth")
                return

            msg_type, _, key_fingerprint = msg

            if msg_type != MsgType.AUTH:
                logger.warning(f"Expected AUTH from {addr}, got {msg_type}")
                await protocol.send(MsgType.AUTH_FAIL, 0, b"Expected AUTH")
                return

            # Client sends key fingerprint for identification
            client_fingerprint = key_fingerprint.decode() if key_fingerprint else ""

            # Check if we have an authorized key
            if self.authorized_key is None:
                # TOFU mode - we need the full key from client
                logger.info(f"TOFU mode: waiting for key from {addr}")
                await protocol.send(MsgType.AUTH_CHALLENGE, 0, b"TOFU")

                # Wait for full key
                msg = await asyncio.wait_for(protocol.recv(), timeout=30)
                if msg is None:
                    logger.warning(f"Client {addr} disconnected during TOFU")
                    return

                msg_type, _, client_key = msg
                if msg_type != MsgType.AUTH_RESPONSE:
                    logger.warning(f"Expected AUTH_RESPONSE from {addr}, got {msg_type}")
                    await protocol.send(MsgType.AUTH_FAIL, 0, b"Expected AUTH_RESPONSE")
                    return

                # Save the key (TOFU)
                self.save_key(client_key)
                logger.info(f"First client {addr} authorized (trust on first use)")

                # Auth successful - send AUTH_OK unencrypted, then enable encryption
                await protocol.send(MsgType.AUTH_OK, 0)
                cipher = Cipher(client_key)
                protocol.set_cipher(cipher)
                logger.info(f"Client {addr} authenticated")
            else:
                # Challenge-response authentication
                challenge = generate_challenge()
                await protocol.send(MsgType.AUTH_CHALLENGE, 0, challenge)

                # Wait for HMAC response
                msg = await asyncio.wait_for(protocol.recv(), timeout=30)
                if msg is None:
                    logger.warning(f"Client {addr} disconnected during challenge-response")
                    return

                msg_type, _, response = msg
                if msg_type != MsgType.AUTH_RESPONSE:
                    logger.warning(f"Expected AUTH_RESPONSE from {addr}, got {msg_type}")
                    await protocol.send(MsgType.AUTH_FAIL, 0, b"Expected AUTH_RESPONSE")
                    return

                # Verify HMAC response
                if not verify_auth_response(self.authorized_key, challenge, response):
                    logger.warning(f"Invalid auth response from {addr}")
                    await protocol.send(MsgType.AUTH_FAIL, 0, b"Invalid key")
                    return

                # Auth successful - send AUTH_OK unencrypted, then enable encryption
                await protocol.send(MsgType.AUTH_OK, 0)
                cipher = Cipher(self.authorized_key)
                protocol.set_cipher(cipher)
                logger.info(f"Client {addr} authenticated")

            # Register session
            async with self._sessions_lock:
                self.sessions[addr] = session
            session.running = True

            # Start heartbeat
            session._heartbeat_task = asyncio.create_task(self._heartbeat_loop(session))

            # Main message loop
            await self._message_loop(session)

        except asyncio.TimeoutError:
            logger.warning(f"Client {addr} timed out during handshake")
        except ConnectionResetError:
            logger.warning(f"Client {addr} reset connection")
        except BrokenPipeError:
            logger.warning(f"Client {addr} broken pipe")
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            session.running = False

            if session._heartbeat_task:
                session._heartbeat_task.cancel()
                try:
                    await session._heartbeat_task
                except asyncio.CancelledError:
                    pass

            # Cancel all tasks
            for task in session._tasks:
                task.cancel()
            if session._tasks:
                await asyncio.gather(*session._tasks, return_exceptions=True)
            session._tasks.clear()

            # Close all connections and public servers
            await self._cleanup_session(session)

            # Send shutdown notification to client
            try:
                await protocol.send(MsgType.SHUTDOWN, 0)
                logger.debug("Sent shutdown notification to client")
            except Exception:
                pass

            protocol.close()
            try:
                await protocol.wait_closed()
            except Exception:
                pass

            # Remove session
            async with self._sessions_lock:
                self.sessions.pop(addr, None)

            # Print statistics
            if session.bytes_sent > 0 or session.bytes_received > 0:
                sent_mb = session.bytes_sent / (1024 * 1024)
                recv_mb = session.bytes_received / (1024 * 1024)
                logger.info(
                    "Session statistics",
                    bytes_sent_mb=round(sent_mb, 2),
                    bytes_received_mb=round(recv_mb, 2),
                    connections=session.connections_total
                )

            logger.info("Client disconnected")
            clear_context()

    async def _message_loop(self, session: ClientSession):
        """Main message processing loop."""
        while session.running:
            try:
                msg = await asyncio.wait_for(session.protocol.recv(), timeout=60)
                if msg is None:
                    logger.info(f"Client {session.addr} disconnected")
                    break

                msg_type, conn_id, data = msg
                await self._handle_message(session, msg_type, conn_id, data)

            except asyncio.TimeoutError:
                logger.warning(f"Client {session.addr} timeout - no messages for 60s")
                break
            except Exception as e:
                logger.error(f"Error in message loop for {session.addr}: {e}")
                break

    async def _handle_message(self, session: ClientSession, msg_type: MsgType, conn_id: int, data: bytes):
        """Handle a single message."""
        if msg_type == MsgType.OPEN_PORT:
            # Client requests to open a public port for reverse tunnel
            port, mode = parse_open_port_msg(data)
            if mode == "udp":
                await self._open_public_udp_port(session, port)
            else:
                await self._open_public_port(session, port)

        elif msg_type == MsgType.CONN_READY:
            # Client is ready to handle connection - move from pending to active
            if conn_id in session.pending_connections:
                reader, writer = session.pending_connections.pop(conn_id)
                session.connections[conn_id] = (reader, writer)
                # Start reading from external client
                task = asyncio.create_task(self._read_from_external(session, conn_id, reader))
                session._tasks.append(task)
                logger.debug(f"Connection {conn_id} activated")
            else:
                logger.warning(f"CONN_READY for unknown connection {conn_id}")

        elif msg_type == MsgType.DATA:
            session.bytes_received += len(data)
            await self._forward_to_external(session, conn_id, data)

        elif msg_type == MsgType.CONN_CLOSED:
            await self._close_external_connection(session, conn_id)

        elif msg_type == MsgType.PING:
            await session.protocol.send(MsgType.PONG, 0)

        elif msg_type == MsgType.PONG:
            pass

        elif msg_type == MsgType.SHUTDOWN:
            logger.info(f"Client {session.addr} requested graceful shutdown")
            session.running = False

    async def _open_public_port(self, session: ClientSession, port: int):
        """Open a public-facing TCP port for incoming connections."""
        # Check port access
        if not self.is_port_allowed(port):
            logger.warning("Port not allowed", port=port)
            await session.protocol.send(MsgType.PORT_ERROR, 0, f"Port {port} not allowed".encode())
            return

        # Check if already listening on this port
        if port in session.public_servers:
            logger.warning("Already listening on port", port=port)
            await session.protocol.send(MsgType.PORT_ERROR, 0, f"Already listening on {port}".encode())
            return

        try:
            # Create handler that captures session and port
            async def handle_external_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
                await self._handle_external_connection(session, reader, writer, port)

            server = await asyncio.start_server(
                handle_external_conn,
                '0.0.0.0', port
            )

            session.public_servers[port] = (server, port)
            logger.info("Listening on public port", port=port)
            await session.protocol.send(MsgType.PORT_OPENED, 0, build_new_conn_msg(port))

        except PermissionError:
            error_msg = f"Permission denied for port {port}"
            logger.error(error_msg)
            await session.protocol.send(MsgType.PORT_ERROR, 0, error_msg.encode())
        except OSError as e:
            if e.errno == 98:  # Address already in use
                error_msg = f"Port {port} is already in use"
            else:
                error_msg = f"Failed to listen on port {port}: {e}"
            logger.error(error_msg)
            await session.protocol.send(MsgType.PORT_ERROR, 0, error_msg.encode())
        except Exception as e:
            error_msg = f"Failed to open port {port}: {e}"
            logger.error(error_msg)
            await session.protocol.send(MsgType.PORT_ERROR, 0, error_msg.encode())

    async def _open_public_udp_port(self, session: ClientSession, port: int):
        """Open a public-facing UDP port for incoming datagrams."""
        # Check port access
        if not self.is_port_allowed(port):
            logger.warning(f"UDP port {port} not allowed")
            await session.protocol.send(MsgType.PORT_ERROR, 0, f"Port {port} not allowed".encode())
            return

        try:
            loop = asyncio.get_event_loop()

            class UDPServerProtocol(asyncio.DatagramProtocol):
                def __init__(self, session, port):
                    self.session = session
                    self.port = port
                    self.transport = None
                    self.clients: dict[tuple, int] = {}  # addr -> conn_id
                    self.conn_to_addr: dict[int, tuple] = {}  # conn_id -> addr

                def connection_made(self, transport):
                    self.transport = transport

                def datagram_received(self, data, addr):
                    if not self.session.running:
                        return

                    if addr not in self.clients:
                        self.session._conn_counter += 1
                        self.session.connections_total += 1
                        conn_id = self.session._conn_counter
                        self.clients[addr] = conn_id
                        self.conn_to_addr[conn_id] = addr
                        # Register for data routing
                        self.session.udp_transports[conn_id] = self.transport
                        logger.debug(f"New UDP client from {addr} -> conn {conn_id}")

                    conn_id = self.clients[addr]
                    self.session.bytes_sent += len(data)
                    asyncio.create_task(
                        self.session.protocol.send(MsgType.DATA, conn_id, data)
                    )

                def error_received(self, exc):
                    logger.debug(f"UDP error on port {self.port}: {exc}")

            transport, protocol = await loop.create_datagram_endpoint(
                lambda: UDPServerProtocol(session, port),
                local_addr=('0.0.0.0', port)
            )

            # Store protocol for sending responses
            session.public_servers[port] = (transport, port)
            logger.info(f"UDP listening on public port {port}")
            await session.protocol.send(MsgType.PORT_OPENED, 0, build_new_conn_msg(port, is_udp=True))

        except Exception as e:
            error_msg = f"Failed to open UDP port {port}: {e}"
            logger.error(error_msg)
            await session.protocol.send(MsgType.PORT_ERROR, 0, error_msg.encode())

    async def _handle_external_connection(self, session: ClientSession, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int):
        """Handle new connection from external client on public port."""
        if not session.running:
            writer.close()
            await writer.wait_closed()
            return

        # Assign connection ID
        session._conn_counter += 1
        session.connections_total += 1
        conn_id = session._conn_counter

        addr = writer.get_extra_info('peername')
        logger.debug(f"External connection {conn_id} from {addr} on port {port}")

        # Store as pending until client sends CONN_READY
        session.pending_connections[conn_id] = (reader, writer)

        try:
            # Notify client about new incoming connection
            await session.protocol.send(MsgType.NEW_CONN, conn_id, build_new_conn_msg(port))

            # Wait for client to respond with CONN_READY (with timeout)
            # The actual handling happens in _handle_message when CONN_READY arrives
            # If client doesn't respond, the connection will be cleaned up on session close

        except Exception as e:
            logger.error(f"Failed to notify client of connection {conn_id}: {e}")
            # Clean up pending connection
            if conn_id in session.pending_connections:
                _, w = session.pending_connections.pop(conn_id)
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass

    async def _read_from_external(self, session: ClientSession, conn_id: int, reader: asyncio.StreamReader):
        """Read from external connection and forward to tunnel client."""
        try:
            while session.running:
                data = await reader.read(4096)
                if not data:
                    break
                session.bytes_sent += len(data)
                await session.protocol.send(MsgType.DATA, conn_id, data)
        except ConnectionResetError:
            logger.debug(f"Connection {conn_id} reset by external client")
        except BrokenPipeError:
            logger.debug(f"Connection {conn_id} broken pipe")
        except Exception as e:
            logger.debug(f"Read error for conn {conn_id}: {e}")
        finally:
            # Remove task from list
            task = asyncio.current_task()
            if task in session._tasks:
                session._tasks.remove(task)

            # Connection closed
            if conn_id in session.connections:
                await self._close_external_connection(session, conn_id)
                try:
                    await session.protocol.send(MsgType.CONN_CLOSED, conn_id)
                except Exception:
                    pass

    async def _forward_to_external(self, session: ClientSession, conn_id: int, data: bytes):
        """Forward data from tunnel client to external connection."""
        # Check UDP first
        if conn_id in session.udp_transports:
            transport = session.udp_transports[conn_id]
            try:
                # For UDP we need to find the client address
                # This is handled by the UDPServerProtocol
                transport.sendto(data)
            except Exception as e:
                logger.debug(f"Failed to forward UDP to conn {conn_id}: {e}")
            return

        # TCP connection
        if conn_id not in session.connections:
            logger.debug(f"Unknown connection {conn_id}")
            return

        _, writer = session.connections[conn_id]
        try:
            writer.write(data)
            await writer.drain()
        except Exception as e:
            logger.debug(f"Failed to forward to conn {conn_id}: {e}")
            await self._close_external_connection(session, conn_id)

    async def _close_external_connection(self, session: ClientSession, conn_id: int):
        """Close an external connection."""
        # Check pending first
        if conn_id in session.pending_connections:
            _, writer = session.pending_connections.pop(conn_id)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.debug(f"Closed pending connection {conn_id}")
            return

        if conn_id not in session.connections:
            return

        _, writer = session.connections.pop(conn_id)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        logger.debug(f"Closed connection {conn_id}")

    async def _heartbeat_loop(self, session: ClientSession):
        """Send periodic heartbeats."""
        while session.running:
            try:
                await asyncio.sleep(15)
                await session.protocol.send(MsgType.PING, 0)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Heartbeat error: {e}")
                break

    async def _cleanup_session(self, session: ClientSession):
        """Clean up session resources."""
        # Close all public servers
        for port, (server, _) in list(session.public_servers.items()):
            if hasattr(server, 'close'):
                server.close()
                if hasattr(server, 'wait_closed'):
                    try:
                        await server.wait_closed()
                    except Exception:
                        pass
            logger.debug(f"Closed public server on port {port}")
        session.public_servers.clear()

        # Close pending connections
        for conn_id in list(session.pending_connections.keys()):
            _, writer = session.pending_connections.pop(conn_id)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        # Close TCP connections
        for conn_id in list(session.connections.keys()):
            await self._close_external_connection(session, conn_id)

        # Close UDP transports
        for conn_id, transport in list(session.udp_transports.items()):
            transport.close()
            logger.debug(f"Closed UDP connection {conn_id}")
        session.udp_transports.clear()


async def run_server(
    port: int = TUNNEL_PORT,
    bind: str = "0.0.0.0",
    verbose: bool = False,
    max_clients: int = 10,
    allowed_ports: list[int] | None = None
):
    """Run the tunnel server."""
    server = TunnelServer(max_clients=max_clients, allowed_ports=allowed_ports)
    server.load_or_generate_server_key()
    server.load_key()

    if allowed_ports:
        logger.info(f"Allowed ports: {sorted(allowed_ports)}")

    # Set up signal handlers
    loop = asyncio.get_event_loop()
    stop_event = asyncio.Event()

    def signal_handler():
        logger.info("Shutdown signal received")
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    # Start server
    tcp_server = await asyncio.start_server(
        server.handle_client,
        bind, port
    )

    logger.info(f"Tunnel server listening on {bind}:{port}")
    logger.info("Waiting for client connection...")

    async with tcp_server:
        await stop_event.wait()

    logger.info("Server stopped")


if __name__ == "__main__":
    asyncio.run(run_server())
