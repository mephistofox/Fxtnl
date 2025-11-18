"""Integration tests for fxTunnel.

These tests create actual server and client connections to verify
end-to-end functionality.
"""

import asyncio
import pytest
import tempfile
from pathlib import Path

from fxtunnel.protocol import (
    FramedProtocol, Cipher, MsgType,
    generate_key, build_new_conn_msg
)


class TestFramedProtocol:
    """Integration tests for FramedProtocol."""

    @pytest.fixture
    async def echo_server(self):
        """Create a simple echo server."""
        clients = []

        async def handle_client(reader, writer):
            protocol = FramedProtocol(reader, writer)
            clients.append(protocol)

            try:
                while True:
                    msg = await protocol.recv()
                    if msg is None:
                        break
                    msg_type, conn_id, data = msg
                    # Echo back
                    await protocol.send(msg_type, conn_id, data)
            except Exception:
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handle_client, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]

        yield server, port, clients

        server.close()
        await server.wait_closed()

    async def test_send_recv_unencrypted(self, echo_server):
        """Unencrypted messages should round-trip correctly."""
        server, port, _ = echo_server

        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        protocol = FramedProtocol(reader, writer)

        # Send message
        await protocol.send(MsgType.DATA, 123, b"Hello, World!")

        # Receive echo
        msg = await protocol.recv()
        assert msg is not None
        msg_type, conn_id, data = msg

        assert msg_type == MsgType.DATA
        assert conn_id == 123
        assert data == b"Hello, World!"

        protocol.close()
        await protocol.wait_closed()

    async def test_send_recv_encrypted(self, echo_server):
        """Encrypted messages should round-trip correctly."""
        server, port, clients = echo_server

        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        protocol = FramedProtocol(reader, writer)

        # Set up encryption on both sides
        key = generate_key()
        cipher = Cipher(key)
        protocol.set_cipher(cipher)

        # Wait for server to accept connection
        await asyncio.sleep(0.01)

        # Set cipher on server side too
        if clients:
            clients[0].set_cipher(Cipher(key))

        # Send encrypted message
        await protocol.send(MsgType.DATA, 456, b"Secret message")

        # Receive echo
        msg = await protocol.recv()
        assert msg is not None
        msg_type, conn_id, data = msg

        assert msg_type == MsgType.DATA
        assert conn_id == 456
        assert data == b"Secret message"

        protocol.close()
        await protocol.wait_closed()

    async def test_multiple_messages(self, echo_server):
        """Multiple messages should all arrive correctly."""
        server, port, _ = echo_server

        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        protocol = FramedProtocol(reader, writer)

        messages = [
            (MsgType.DATA, 1, b"First"),
            (MsgType.DATA, 2, b"Second"),
            (MsgType.DATA, 3, b"Third"),
        ]

        # Send all messages
        for msg_type, conn_id, data in messages:
            await protocol.send(msg_type, conn_id, data)

        # Receive all echoes
        for expected_type, expected_id, expected_data in messages:
            msg = await protocol.recv()
            assert msg is not None
            msg_type, conn_id, data = msg
            assert msg_type == expected_type
            assert conn_id == expected_id
            assert data == expected_data

        protocol.close()
        await protocol.wait_closed()

    async def test_large_message(self, echo_server):
        """Large messages should transfer correctly."""
        server, port, _ = echo_server

        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        protocol = FramedProtocol(reader, writer)

        # 100 KB message
        large_data = b"x" * 100000

        await protocol.send(MsgType.DATA, 1, large_data)

        msg = await protocol.recv()
        assert msg is not None
        msg_type, conn_id, data = msg

        assert msg_type == MsgType.DATA
        assert data == large_data

        protocol.close()
        await protocol.wait_closed()


class TestHealthEndpoint:
    """Integration tests for health check endpoint."""

    async def test_health_endpoint(self):
        """Health endpoint should return healthy status."""
        from fxtunnel.health import HealthServer
        import aiohttp

        server = HealthServer(port=0)  # Random port
        await server.start()

        # Get actual port
        port = server._site._server.sockets[0].getsockname()[1]

        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{port}/health") as resp:
                assert resp.status == 200
                data = await resp.json()
                assert data["status"] == "healthy"
                assert "uptime_seconds" in data

        await server.stop()

    async def test_metrics_endpoint(self):
        """Metrics endpoint should return metrics."""
        from fxtunnel.health import HealthServer
        import aiohttp

        server = HealthServer(port=0)
        await server.start()

        port = server._site._server.sockets[0].getsockname()[1]

        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{port}/metrics") as resp:
                assert resp.status == 200
                data = await resp.json()
                assert "uptime_seconds" in data
                assert "clients_connected" in data

        await server.stop()


class TestTunnelConnection:
    """Integration tests for tunnel connections."""

    @pytest.fixture
    async def tcp_echo_service(self):
        """Create a TCP echo service to tunnel to."""
        async def handle_client(reader, writer):
            try:
                while True:
                    data = await reader.read(1024)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except Exception:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        server = await asyncio.start_server(handle_client, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]

        yield port

        server.close()
        await server.wait_closed()

    async def test_tcp_echo_service_works(self, tcp_echo_service):
        """Echo service should echo data back."""
        port = tcp_echo_service

        reader, writer = await asyncio.open_connection('127.0.0.1', port)

        writer.write(b"Hello")
        await writer.drain()

        data = await reader.read(1024)
        assert data == b"Hello"

        writer.close()
        await writer.wait_closed()


class TestLogging:
    """Tests for structured logging."""

    def test_configure_logging(self):
        """configure_logging should not raise errors."""
        from fxtunnel.logging import configure_logging

        # Test basic configuration
        configure_logging(verbose=False)

        # Test verbose mode
        configure_logging(verbose=True)

        # Test JSON output
        configure_logging(json_output=True)

    def test_get_logger(self):
        """get_logger should return a logger."""
        from fxtunnel.logging import get_logger

        logger = get_logger("test")
        assert logger is not None

        # Should be able to log without errors
        logger.info("Test message")
        logger.debug("Debug message")
        logger.warning("Warning message")

    def test_context_binding(self):
        """Context binding should work."""
        from fxtunnel.logging import (
            get_logger, bind_context, unbind_context, clear_context
        )

        logger = get_logger("test")

        # Bind context
        bind_context(client="192.168.1.100", session_id="abc123")
        logger.info("Message with context")

        # Unbind specific keys
        unbind_context("session_id")
        logger.info("Message without session_id")

        # Clear all context
        clear_context()
        logger.info("Message without any context")
