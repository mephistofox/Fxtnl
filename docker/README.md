# Docker Deployment

Detailed documentation for running fxTunnel in Docker containers.

## Building the Image

```bash
# Standard build
docker build -t fxtunnel .

# With specific tag
docker build -t fxtunnel:v0.3.0 .
```

## Running the Server

### Basic Usage

```bash
docker run -d \
  --name fxtunnel-server \
  -p 9000:9000 \
  -p 8080:8080 \
  -v fxtunnel-data:/data \
  fxtunnel
```

### Production Configuration

```bash
docker run -d \
  --name fxtunnel-server \
  --restart unless-stopped \
  -p 9000:9000 \
  -p 8080:8080 \
  -v fxtunnel-data:/data \
  --memory 256m \
  --cpus 0.5 \
  fxtunnel server \
  --health-port 8080 \
  --allowed-ports 5432,6379,80,443 \
  --max-clients 20 \
  --log-json
```

### With Bind Mount (for easy key access)

```bash
mkdir -p ~/fxtunnel-data

docker run -d \
  --name fxtunnel-server \
  -p 9000:9000 \
  -p 8080:8080 \
  -v ~/fxtunnel-data:/data \
  fxtunnel
```

## Docker Compose

### Basic docker-compose.yml

```yaml
services:
  fxtunnel-server:
    build: .
    ports:
      - "9000:9000"
      - "8080:8080"
    volumes:
      - fxtunnel-data:/data
    restart: unless-stopped

volumes:
  fxtunnel-data:
```

### Usage

```bash
# Start
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down

# Rebuild after changes
docker-compose up -d --build
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FXTUNNEL_DATA_DIR` | `/data` | Directory for keys and config |
| `PYTHONUNBUFFERED` | `1` | Disable Python output buffering |

## Ports

| Port | Description |
|------|-------------|
| 9000 | Tunnel server port |
| 8080 | Health check HTTP endpoint |

## Health Checks

The container includes a built-in health check that queries the `/health` endpoint.

```bash
# Manual check
curl http://localhost:8080/health

# Check container status
docker inspect --format='{{.State.Health.Status}}' fxtunnel-server
```

## Persistent Data

The `/data` directory contains:

- `server_key` - Server identity key (generated on first start)
- `authorized_key` - Client authorization key (after first connection)

**Important:** Always use volumes to persist this data, otherwise:
- Server will get new identity on restart
- Clients will see "SERVER IDENTITY HAS CHANGED" warning
- Client authorization will be lost

## Security Best Practices

### 1. Non-root User

The container runs as user `fxtunnel` (UID 1000) by default.

### 2. Read-only Filesystem

```bash
docker run -d \
  --name fxtunnel-server \
  --read-only \
  -v fxtunnel-data:/data \
  -p 9000:9000 \
  fxtunnel
```

### 3. Drop Capabilities

```bash
docker run -d \
  --name fxtunnel-server \
  --cap-drop ALL \
  -p 9000:9000 \
  -v fxtunnel-data:/data \
  fxtunnel
```

### 4. Resource Limits

```bash
docker run -d \
  --name fxtunnel-server \
  --memory 256m \
  --cpus 0.5 \
  -p 9000:9000 \
  -v fxtunnel-data:/data \
  fxtunnel
```

## Kubernetes Deployment

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fxtunnel
spec:
  replicas: 1
  selector:
    matchLabels:
      app: fxtunnel
  template:
    metadata:
      labels:
        app: fxtunnel
    spec:
      containers:
      - name: fxtunnel
        image: fxtunnel:latest
        args: ["server", "--health-port", "8080", "--log-json"]
        ports:
        - containerPort: 9000
          name: tunnel
        - containerPort: 8080
          name: health
        volumeMounts:
        - name: data
          mountPath: /data
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        resources:
          limits:
            memory: 256Mi
            cpu: 500m
          requests:
            memory: 128Mi
            cpu: 100m
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: fxtunnel-data
```

### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: fxtunnel
spec:
  selector:
    app: fxtunnel
  ports:
  - name: tunnel
    port: 9000
    targetPort: 9000
  - name: health
    port: 8080
    targetPort: 8080
  type: LoadBalancer
```

## Troubleshooting

### Container won't start

Check logs:
```bash
docker logs fxtunnel-server
```

### Health check failing

```bash
# Check if server is running
docker exec fxtunnel-server ps aux

# Check health endpoint manually
docker exec fxtunnel-server curl -s http://127.0.0.1:8080/health
```

### Permission issues

If using bind mounts, ensure the host directory is writable:
```bash
sudo chown -R 1000:1000 ~/fxtunnel-data
```

### Keys not persisting

Ensure volume is mounted correctly:
```bash
docker inspect fxtunnel-server | grep -A 10 Mounts
```
