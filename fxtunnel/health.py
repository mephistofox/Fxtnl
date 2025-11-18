"""
Health check HTTP endpoint for fxTunnel server.
"""

import asyncio
import time
from typing import Any

from aiohttp import web

from .logging import get_logger

logger = get_logger(__name__)


class HealthServer:
    """HTTP server for health checks and metrics."""

    def __init__(self, port: int = 8080, bind: str = "127.0.0.1"):
        self.port = port
        self.bind = bind
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._start_time = time.time()

        # Metrics
        self._metrics: dict[str, Any] = {
            "clients_connected": 0,
            "clients_total": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "connections_total": 0,
        }

        # Reference to tunnel server for live metrics
        self._tunnel_server = None

    def set_tunnel_server(self, server) -> None:
        """Set reference to tunnel server for live metrics."""
        self._tunnel_server = server

    def update_metrics(self, **kwargs) -> None:
        """Update metrics values."""
        for key, value in kwargs.items():
            if key in self._metrics:
                self._metrics[key] = value

    def increment_metric(self, key: str, value: int = 1) -> None:
        """Increment a metric by value."""
        if key in self._metrics:
            self._metrics[key] += value

    async def _handle_health(self, request: web.Request) -> web.Response:
        """Handle /health endpoint - basic liveness check."""
        return web.json_response({
            "status": "healthy",
            "uptime_seconds": int(time.time() - self._start_time)
        })

    async def _handle_ready(self, request: web.Request) -> web.Response:
        """Handle /ready endpoint - readiness check."""
        # Check if tunnel server is running and accepting connections
        is_ready = True
        details = {}

        if self._tunnel_server:
            # Could add more sophisticated checks here
            is_ready = True
            details["server"] = "running"
        else:
            is_ready = False
            details["server"] = "not_initialized"

        status_code = 200 if is_ready else 503
        return web.json_response({
            "status": "ready" if is_ready else "not_ready",
            "details": details
        }, status=status_code)

    async def _handle_metrics(self, request: web.Request) -> web.Response:
        """Handle /metrics endpoint - return metrics."""
        metrics = dict(self._metrics)

        # Add live metrics from tunnel server
        if self._tunnel_server:
            metrics["clients_connected"] = len(self._tunnel_server.sessions)

            # Aggregate session metrics
            total_sent = 0
            total_recv = 0
            total_conns = 0
            for session in self._tunnel_server.sessions.values():
                total_sent += session.bytes_sent
                total_recv += session.bytes_received
                total_conns += session.connections_total

            metrics["bytes_sent"] = total_sent
            metrics["bytes_received"] = total_recv
            metrics["connections_total"] = total_conns

        # Add uptime
        metrics["uptime_seconds"] = int(time.time() - self._start_time)

        return web.json_response(metrics)

    async def start(self) -> None:
        """Start the health check server."""
        self._app = web.Application()
        self._app.router.add_get("/health", self._handle_health)
        self._app.router.add_get("/ready", self._handle_ready)
        self._app.router.add_get("/metrics", self._handle_metrics)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()

        self._site = web.TCPSite(self._runner, self.bind, self.port)
        await self._site.start()

        logger.info("Health check server started", bind=self.bind, port=self.port)

    async def stop(self) -> None:
        """Stop the health check server."""
        if self._runner:
            await self._runner.cleanup()
            logger.info("Health check server stopped")


async def run_health_server(
    port: int = 8080,
    bind: str = "127.0.0.1",
    tunnel_server=None
) -> HealthServer:
    """
    Create and start a health check server.

    Args:
        port: HTTP port to listen on
        bind: Address to bind to
        tunnel_server: Reference to TunnelServer for live metrics

    Returns:
        Running HealthServer instance
    """
    server = HealthServer(port=port, bind=bind)
    if tunnel_server:
        server.set_tunnel_server(tunnel_server)
    await server.start()
    return server
