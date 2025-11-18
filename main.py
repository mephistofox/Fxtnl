#!/usr/bin/env python3
"""
fxTunnel - Reverse tunnel system (like SSH -R).

Expose local services to the internet via a remote server.

Server: fxtunnel server
Client: fxtunnel client --ip <server_ip> -L <local>:<remote> [-L ...]
Connect: fxtunnel connect <profile>

Architecture:
[Internet] -> [Server:remote_port] -> [Tunnel] -> [Client] -> [localhost:local_port]
"""

import argparse
import asyncio
import sys
from pathlib import Path

from fxtunnel import __version__
from fxtunnel.logging import configure_logging


def parse_tunnel_spec(spec: str) -> tuple[int, int, str]:
    """
    Parse tunnel specification for reverse tunneling.

    Formats:
      - "8001:80" -> (8001, 80, "tcp") - expose localhost:8001 on server:80
      - "8001:80:tcp" -> (8001, 80, "tcp")
      - "53:53:udp" -> (53, 53, "udp")

    The format is LOCAL:REMOTE where:
      - LOCAL = port of your local service (e.g., 8001)
      - REMOTE = port to open on server (e.g., 80)
    """
    parts = spec.split(':')
    if len(parts) == 2:
        local_port = int(parts[0])
        remote_port = int(parts[1])
        mode = "tcp"
    elif len(parts) == 3:
        local_port = int(parts[0])
        remote_port = int(parts[1])
        mode = parts[2].lower()
        if mode not in ("tcp", "udp"):
            raise ValueError(f"Invalid mode: {mode}. Use 'tcp' or 'udp'")
    else:
        raise ValueError(f"Invalid tunnel spec: {spec}. Use 'local:remote' or 'local:remote:mode'")

    if not (1 <= local_port <= 65535) or not (1 <= remote_port <= 65535):
        raise ValueError("Port must be between 1 and 65535")

    return local_port, remote_port, mode


def main():
    parser = argparse.ArgumentParser(
        description="fxTunnel - Reverse tunnel system (like SSH -R)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Expose local services to the internet via a remote server.

Architecture:
  [Internet] -> [Server:remote_port] -> [Tunnel] -> [Client] -> [localhost:local_port]

Examples:
  Server (no config needed):
    fxtunnel server
    fxtunnel server --port 9000 --allowed-ports 80,443,8080

  Client (expose local web app on port 8001 as server:80):
    fxtunnel client --ip your-server.com -L 8001:80

  Client (expose multiple services):
    fxtunnel client --ip your-server.com -L 8001:80 -L 3000:3000 -L 5432:5432

  Client (UDP mode):
    fxtunnel client --ip your-server.com -L 53:53:udp

  Connect using profile:
    fxtunnel connect dev
    fxtunnel connect prod --verbose

  Configuration:
    fxtunnel config init
    fxtunnel config show
"""
    )

    parser.add_argument(
        "--version", action="version",
        version=f"fxTunnel {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Server command
    server_parser = subparsers.add_parser(
        "server",
        help="Run tunnel server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic server (all ports allowed)
  fxtunnel server

  # Custom port with health check
  fxtunnel server --port 8000 --health-port 8080

  # Production: restricted ports, JSON logs
  fxtunnel server --allowed-ports 5432,6379 --log-json --health-port 8080

  # Docker deployment
  docker run -p 9000:9000 -p 8080:8080 fxtunnel server --health-port 8080
"""
    )
    server_parser.add_argument(
        "--port", type=int,
        help="Tunnel port (default: 9000)"
    )
    server_parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output"
    )
    server_parser.add_argument(
        "--bind",
        help="Bind address (default: 0.0.0.0)"
    )
    server_parser.add_argument(
        "--max-clients", type=int,
        help="Maximum concurrent clients (default: 10)"
    )
    server_parser.add_argument(
        "--allowed-ports", type=str,
        help="Comma-separated list of ports that clients can expose (e.g., 80,443,8080)"
    )
    server_parser.add_argument(
        "--log-json", action="store_true",
        help="Output logs as JSON (for production)"
    )
    server_parser.add_argument(
        "--log-file", type=str,
        help="Write logs to file"
    )
    server_parser.add_argument(
        "--health-port", type=int,
        help="Enable health check endpoint on specified port (e.g., 8080)"
    )

    # Client command
    client_parser = subparsers.add_parser(
        "client",
        help="Run tunnel client (expose local services)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Expose local services to the internet via a remote server.

Tunnel format: -L LOCAL:REMOTE[:MODE]
  LOCAL  = port of your local service (e.g., 8001)
  REMOTE = port to open on server (e.g., 80)
  MODE   = tcp (default) or udp

Examples:
  # Expose local web app (localhost:8001) on server port 80
  fxtunnel client --ip your-server.com -L 8001:80

  # Expose multiple services
  fxtunnel client --ip your-server.com -L 8001:80 -L 3000:3000

  # UDP tunnel
  fxtunnel client --ip your-server.com -L 53:53:udp

  # Auto-accept new server
  fxtunnel client --ip your-server.com -L 8001:80 --accept-new-host
"""
    )
    client_parser.add_argument(
        "--ip", required=True,
        help="Server IP address"
    )
    client_parser.add_argument(
        "--port", type=int, default=9000,
        help="Server tunnel port (default: 9000)"
    )
    client_parser.add_argument(
        "-L", action="append", dest="tunnels", metavar="LOCAL:REMOTE[:MODE]",
        help="Expose LOCAL port on server's REMOTE port (can be used multiple times)"
    )
    # Legacy single tunnel options
    client_parser.add_argument(
        "--local", type=int,
        help="Local service port to expose (legacy, use -L instead)"
    )
    client_parser.add_argument(
        "--remote", type=int,
        help="Server port to open (legacy, use -L instead)"
    )
    client_parser.add_argument(
        "--udp", action="store_true",
        help="Use UDP mode for legacy --local/--remote"
    )
    client_parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output"
    )
    client_parser.add_argument(
        "--bind", default="localhost",
        help="Local bind address (default: localhost)"
    )
    client_parser.add_argument(
        "--accept-new-host", action="store_true",
        help="Automatically accept new server host keys"
    )
    client_parser.add_argument(
        "--log-json", action="store_true",
        help="Output logs as JSON (for production)"
    )
    client_parser.add_argument(
        "--log-file", type=str,
        help="Write logs to file"
    )

    # Connect command (profile-based)
    connect_parser = subparsers.add_parser(
        "connect",
        help="Connect using profile from config",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Connect using profile
  fxtunnel connect dev

  # Override settings
  fxtunnel connect dev --verbose --bind 0.0.0.0

  # Auto-accept new server
  fxtunnel connect prod --accept-new-host
"""
    )
    connect_parser.add_argument(
        "profile",
        help="Profile name from config.yaml"
    )
    connect_parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output"
    )
    connect_parser.add_argument(
        "--bind",
        help="Override bind address"
    )
    connect_parser.add_argument(
        "--accept-new-host", action="store_true",
        help="Automatically accept new server host keys"
    )
    connect_parser.add_argument(
        "--log-json", action="store_true",
        help="Output logs as JSON (for production)"
    )
    connect_parser.add_argument(
        "--log-file", type=str,
        help="Write logs to file"
    )

    # Config command
    config_parser = subparsers.add_parser("config", help="Configuration management")
    config_subparsers = config_parser.add_subparsers(dest="config_command")

    # config init
    config_init = config_subparsers.add_parser("init", help="Create config file template")
    config_init.add_argument(
        "--force", action="store_true",
        help="Overwrite existing config"
    )

    # config show
    config_subparsers.add_parser("show", help="Show current configuration")

    # Status command
    subparsers.add_parser("status", help="Show tunnel status")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    # Server command
    if args.command == "server":
        from fxtunnel.config import get_server_config

        # Configure logging
        log_file = Path(args.log_file) if args.log_file else None
        configure_logging(
            verbose=args.verbose,
            json_output=args.log_json,
            log_file=log_file
        )

        # Load config defaults
        server_config = get_server_config()

        # CLI args override config
        port = args.port if args.port else server_config['port']
        bind = args.bind if args.bind else server_config['bind']
        max_clients = args.max_clients if args.max_clients else server_config['max_clients']

        # Parse allowed ports
        allowed_ports = None
        if args.allowed_ports:
            allowed_ports = [int(p.strip()) for p in args.allowed_ports.split(',')]
        elif server_config.get('allowed_ports'):
            allowed_ports = server_config['allowed_ports']

        async def run_with_health():
            from fxtunnel.server import TunnelServer
            from fxtunnel.health import run_health_server
            import signal

            server = TunnelServer(max_clients=max_clients, allowed_ports=allowed_ports)
            server.load_or_generate_server_key()
            server.load_key()

            # Start health server if requested
            health_server = None
            if args.health_port:
                health_server = await run_health_server(
                    port=args.health_port,
                    tunnel_server=server
                )

            if allowed_ports:
                from fxtunnel.logging import get_logger
                logger = get_logger(__name__)
                logger.info("Allowed ports configured", ports=sorted(allowed_ports))

            # Set up signal handlers
            loop = asyncio.get_event_loop()
            stop_event = asyncio.Event()

            def signal_handler():
                from fxtunnel.logging import get_logger
                logger = get_logger(__name__)
                logger.info("Shutdown signal received")
                stop_event.set()

            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, signal_handler)

            # Start tunnel server
            tcp_server = await asyncio.start_server(
                server.handle_client,
                bind, port
            )

            from fxtunnel.logging import get_logger
            logger = get_logger(__name__)
            logger.info("Tunnel server listening", bind=bind, port=port)
            logger.info("Waiting for client connection...")

            async with tcp_server:
                await stop_event.wait()

            # Cleanup
            if health_server:
                await health_server.stop()

            logger.info("Server stopped")

        asyncio.run(run_with_health())

    # Client command
    elif args.command == "client":
        from fxtunnel.client import run_client

        # Configure logging
        log_file = Path(args.log_file) if args.log_file else None
        configure_logging(
            verbose=args.verbose,
            json_output=args.log_json,
            log_file=log_file
        )

        tunnels = []

        # Parse -L tunnel specifications
        if args.tunnels:
            for spec in args.tunnels:
                try:
                    tunnels.append(parse_tunnel_spec(spec))
                except ValueError as e:
                    print(f"Error: {e}", file=sys.stderr)
                    sys.exit(1)

        # Legacy --local/--remote support
        if args.local and args.remote:
            mode = "udp" if args.udp else "tcp"
            tunnels.append((args.local, args.remote, mode))

        if not tunnels:
            print("Error: No tunnels specified. Use -L local:remote or --local/--remote", file=sys.stderr)
            sys.exit(1)

        asyncio.run(run_client(
            server_ip=args.ip,
            server_port=args.port,
            tunnels=tunnels,
            bind=args.bind,
            verbose=args.verbose,
            accept_new_host=args.accept_new_host
        ))

    # Connect command
    elif args.command == "connect":
        from fxtunnel.client import run_client
        from fxtunnel.config import get_profile, get_tunnels_from_profile, ConfigError

        # Configure logging
        log_file = Path(args.log_file) if args.log_file else None
        configure_logging(
            verbose=args.verbose,
            json_output=args.log_json,
            log_file=log_file
        )

        try:
            profile = get_profile(args.profile)
        except ConfigError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        # Get server info
        server_ip = profile.get('server')
        if not server_ip:
            print(f"Error: Profile '{args.profile}' has no server address", file=sys.stderr)
            sys.exit(1)

        server_port = profile.get('port', 9000)

        # Get tunnels
        try:
            tunnels = get_tunnels_from_profile(profile)
        except ConfigError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        if not tunnels:
            print(f"Error: Profile '{args.profile}' has no tunnels defined", file=sys.stderr)
            sys.exit(1)

        # CLI overrides
        bind = args.bind if args.bind else profile.get('bind', 'localhost')
        verbose = args.verbose or profile.get('verbose', False)
        accept_new_host = args.accept_new_host or profile.get('accept_new_host', False)

        asyncio.run(run_client(
            server_ip=server_ip,
            server_port=server_port,
            tunnels=tunnels,
            bind=bind,
            verbose=verbose,
            accept_new_host=accept_new_host
        ))

    # Config command
    elif args.command == "config":
        from fxtunnel.config import init_config, load_config, CONFIG_FILE, ConfigError

        if args.config_command == "init":
            try:
                path = init_config(force=args.force)
                print(f"Created config file: {path}")
                print("Edit this file to add your connection profiles.")
            except ConfigError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

        elif args.config_command == "show":
            import yaml

            if not CONFIG_FILE.exists():
                print(f"No config file found at {CONFIG_FILE}")
                print("Run 'fxtunnel config init' to create one.")
                sys.exit(0)

            try:
                config = load_config()
                print(f"# Config: {CONFIG_FILE}\n")
                print(yaml.dump(config, default_flow_style=False, allow_unicode=True))
            except ConfigError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

        else:
            config_parser.print_help()
            sys.exit(1)

    # Status command
    elif args.command == "status":
        from fxtunnel.config import CONFIG_FILE, list_profiles, get_data_dir
        from fxtunnel.protocol import hex_to_key

        # Import paths from client and server
        DATA_DIR = get_data_dir()
        KEY_FILE = DATA_DIR / "key"
        KNOWN_HOSTS_FILE = DATA_DIR / "known_hosts"
        SERVER_KEY_FILE = DATA_DIR / "server_key"

        print("fxTunnel Status")
        print("=" * 50)

        # Config file
        print(f"\nConfig file: {CONFIG_FILE}")
        if CONFIG_FILE.exists():
            print("  Status: exists")
            profiles = list_profiles()
            if profiles:
                print(f"  Profiles: {', '.join(profiles)}")
            else:
                print("  Profiles: none defined")
        else:
            print("  Status: not found")
            print("  Run 'fxtunnel config init' to create")

        # Client key
        print(f"\nClient key: {KEY_FILE}")
        if KEY_FILE.exists():
            try:
                import hashlib
                hex_key = KEY_FILE.read_text().strip()
                key = hex_to_key(hex_key)
                digest = hashlib.sha256(key).hexdigest()
                fingerprint = ':'.join(digest[i:i+2] for i in range(0, 16, 2))
                print(f"  Status: exists")
                print(f"  Fingerprint: {fingerprint}")
            except Exception as e:
                print(f"  Status: error - {e}")
        else:
            print("  Status: not generated")
            print("  Will be created on first client connection")

        # Known hosts
        print(f"\nKnown hosts: {KNOWN_HOSTS_FILE}")
        if KNOWN_HOSTS_FILE.exists():
            known_hosts = {}
            for line in KNOWN_HOSTS_FILE.read_text().strip().split('\n'):
                if line and ' ' in line:
                    host, fp = line.split(' ', 1)
                    known_hosts[host] = fp
            if known_hosts:
                print(f"  Count: {len(known_hosts)}")
                for host, fp in sorted(known_hosts.items()):
                    print(f"    {host}: {fp}")
            else:
                print("  Count: 0")
        else:
            print("  Status: not found")

        # Server key (if exists)
        print(f"\nServer key: {SERVER_KEY_FILE}")
        if SERVER_KEY_FILE.exists():
            try:
                import hashlib
                hex_key = SERVER_KEY_FILE.read_text().strip()
                key = hex_to_key(hex_key)
                digest = hashlib.sha256(key).hexdigest()
                fingerprint = ':'.join(digest[i:i+2] for i in range(0, 16, 2))
                print(f"  Status: exists")
                print(f"  Fingerprint: {fingerprint}")
            except Exception as e:
                print(f"  Status: error - {e}")
        else:
            print("  Status: not generated")
            print("  Will be created on first server start")

        print("\n" + "=" * 50)
        sys.exit(0)


if __name__ == "__main__":
    main()
