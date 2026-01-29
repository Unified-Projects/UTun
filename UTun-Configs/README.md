# UTun Production Deployment

This guide covers deploying UTun to forward port 80 between two servers using a post-quantum secure tunnel.

## Server Details

| Role | IP Address | Description |
|------|------------|-------------|
| SOURCE | 20.117.185.77 | Public-facing server (clients connect here) |
| DEST | 37.187.159.141 | Backend server running the actual web service |

## Architecture

```
[Clients] --> [20.117.185.77:80] ===tunnel:5983===> [37.187.159.141] --> [Web Service:80]
```

- **SOURCE Server (20.117.185.77)**: Receives client connections on port 80, tunnels them to DEST
- **DEST Server (37.187.159.141)**: Receives tunneled traffic on port 5983, forwards to local port 80

## Prerequisites

- Docker and Docker Compose on both servers

## Deployment

### 1. Copy Files to Servers

```bash
# To SOURCE server (20.117.185.77)
scp -r source/ user@20.117.185.77:/opt/utun/

# To DEST server (37.187.159.141)
scp -r dest/ user@37.187.159.141:/opt/utun/
```

### 2. Configure UFW Firewall

#### On SOURCE Server (20.117.185.77)

```bash
# Allow SSH (important - do this first!)
sudo ufw allow 22/tcp

# Allow client connections to port 80
sudo ufw allow 80/tcp

# Allow tunnel traffic ONLY to/from DEST server
sudo ufw allow out to 37.187.159.141 port 5983 proto tcp
sudo ufw allow in from 37.187.159.141 port 5983 proto tcp

# Enable UFW
sudo ufw enable
sudo ufw status verbose
```

#### On DEST Server (37.187.159.141)

```bash
# Allow SSH (important - do this first!)
sudo ufw allow 22/tcp

# Allow tunnel traffic ONLY from SOURCE server
sudo ufw allow in from 20.117.185.77 to any port 5983 proto tcp

# Enable UFW
sudo ufw enable
sudo ufw status verbose
```

### 3. Start the Services

On each server:

```bash
cd /opt/utun
docker compose up -d
```

### 4. Verify

Check logs:
```bash
docker compose logs -f
```

Check health:
```bash
# On SOURCE (20.117.185.77)
curl http://localhost:9090/health

# On DEST (37.187.159.141)
curl http://localhost:9091/health
```

Test the tunnel (from any client):
```bash
curl http://20.117.185.77/
```

## UFW Rules Summary

### SOURCE Server (20.117.185.77)

| Rule | Direction | Port | Protocol | Source/Dest | Purpose |
|------|-----------|------|----------|-------------|---------|
| ALLOW | IN | 22 | TCP | Anywhere | SSH access |
| ALLOW | IN | 80 | TCP | Anywhere | Client connections |
| ALLOW | OUT | 5983 | TCP | 37.187.159.141 | Tunnel outbound |
| ALLOW | IN | 5983 | TCP | 37.187.159.141 | Tunnel return traffic |

### DEST Server (37.187.159.141)

| Rule | Direction | Port | Protocol | Source/Dest | Purpose |
|------|-----------|------|----------|-------------|---------|
| ALLOW | IN | 22 | TCP | Anywhere | SSH access |
| ALLOW | IN | 5983 | TCP | 20.117.185.77 | Tunnel inbound |

## Configuration Reference

### Source Config (`source/config.toml`)

| Setting | Value | Description |
|---------|-------|-------------|
| `listen_port` | 80 | Port clients connect to |
| `dest_host` | 37.187.159.141 | DEST server IP address |
| `dest_tunnel_port` | 5983 | Tunnel port on DEST |
| `max_connections` | 10000 | Max concurrent connections |

### Dest Config (`dest/config.toml`)

| Setting | Value | Description |
|---------|-------|-------------|
| `tunnel_port` | 5983 | Tunnel listening port |
| `target_ip` | 127.0.0.1 | Backend service IP |
| `target_port` | 80 | Backend service port |
| `allowed_source_ips` | 20.117.185.77/32 | SOURCE server IP |

## Troubleshooting

### Connection refused on SOURCE:80

1. Check if container is running: `docker compose ps`
2. Check logs: `docker compose logs utun-source`
3. Verify UFW allows port 80: `sudo ufw status`

### Tunnel connection failed

1. Verify DEST server is reachable: `nc -zv 37.187.159.141 5983`
2. Check UFW on both servers
3. Verify certificates are valid: `openssl verify -CAfile certs/ca.crt certs/client.crt`

### Certificate errors

1. Ensure CA cert is the same on both servers
2. Check certificate expiry: `openssl x509 -in certs/server.crt -noout -dates`
3. Regenerate certificates if needed

### Health check failing

1. Check metrics endpoint: `curl http://localhost:9090/metrics`
2. Review container logs for errors
3. Ensure sufficient resources (the quantum handshake needs ~200MB RAM)

## Security Notes

- Keep `ca.key` secure - it can sign new certificates
- UFW rules restrict tunnel traffic to only the two servers
- mTLS ensures both ends authenticate each other
- Post-quantum cryptography protects against future quantum attacks
- Certificates expire after 365 days - plan for rotation

## File Structure

```
prod/
├── README.md              # This file
├── generate-certs.sh      # Certificate generator
├── ca.crt                 # Root CA certificate
├── ca.key                 # Root CA private key (KEEP SECURE)
├── source/
│   ├── docker-compose.yml
│   ├── config.toml
│   └── certs/
│       ├── ca.crt
│       ├── client.crt
│       └── client.key
└── dest/
    ├── docker-compose.yml
    ├── config.toml
    └── certs/
        ├── ca.crt
        ├── server.crt
        └── server.key
```
