# Multi-Service Configuration Guide

This guide explains how to configure UTun to expose multiple services and ports for various use cases including web services, databases, caches, message queues, and more.

## Overview

UTun supports exposing an unlimited number of services through the tunnel. Each service can be:
- **TCP or UDP protocol**
- Forwarded to **different target IPs and ports**
- Given a **descriptive name** for monitoring and logging
- Configured with **independent connection limits**

## Architecture

```
[Client] -> [Source Container:Multiple Ports]
              |
              v
        [Quantum-Safe Tunnel]
              |
              v
        [Dest Container] -> [Service 1: PostgreSQL]
                        -> [Service 2: Redis]
                        -> [Service 3: Web App]
                        -> [Service 4: RabbitMQ]
                        -> [Service N: ...]
```

## Configuration Structure

### Destination Configuration

The destination container configuration uses an array of service definitions:

```toml
[dest]
listen_ip = "0.0.0.0"
tunnel_port = 9443
max_connections_per_service = 100

# Define as many services as needed using [[dest.exposed_services]]
[[dest.exposed_services]]
name = "service-name"
port = 1234                    # Port on the tunnel
target_ip = "10.0.1.10"       # Where to forward connections
target_port = 5678             # Target port
protocol = "tcp"               # "tcp" or "udp"
description = "Service description"
```

### Source Configuration

The source container configuration defines which ports to expose:

```toml
[source]
listen_ip = "0.0.0.0"
listen_port = 8443
dest_host = "utun-dest"
dest_tunnel_port = 9443

# Define multiple exposed ports using [[source.exposed_ports]]
[[source.exposed_ports]]
port = 8443
protocol = "both"  # "tcp", "udp", or "both"

[[source.exposed_ports]]
port = 5432
protocol = "tcp"
```

## Common Service Examples

### Database Services

```toml
# PostgreSQL
[[dest.exposed_services]]
name = "postgresql"
port = 5432
target_ip = "10.0.2.10"
target_port = 5432
protocol = "tcp"
description = "PostgreSQL database"

# MySQL
[[dest.exposed_services]]
name = "mysql"
port = 3306
target_ip = "10.0.2.11"
target_port = 3306
protocol = "tcp"
description = "MySQL database"

# MongoDB
[[dest.exposed_services]]
name = "mongodb"
port = 27017
target_ip = "10.0.2.12"
target_port = 27017
protocol = "tcp"
description = "MongoDB database"

# Redis
[[dest.exposed_services]]
name = "redis"
port = 6379
target_ip = "10.0.3.10"
target_port = 6379
protocol = "tcp"
description = "Redis cache"
```

### Web Services

```toml
# HTTP
[[dest.exposed_services]]
name = "web-http"
port = 80
target_ip = "10.0.1.20"
target_port = 8080
protocol = "tcp"
description = "Web application HTTP"

# HTTPS
[[dest.exposed_services]]
name = "web-https"
port = 443
target_ip = "10.0.1.20"
target_port = 8443
protocol = "tcp"
description = "Web application HTTPS"

# REST API
[[dest.exposed_services]]
name = "api"
port = 3000
target_ip = "10.0.1.21"
target_port = 3000
protocol = "tcp"
description = "REST API server"

# GraphQL API
[[dest.exposed_services]]
name = "graphql"
port = 4000
target_ip = "10.0.1.22"
target_port = 4000
protocol = "tcp"
description = "GraphQL API"
```

### Message Queues

```toml
# RabbitMQ
[[dest.exposed_services]]
name = "rabbitmq"
port = 5672
target_ip = "10.0.4.10"
target_port = 5672
protocol = "tcp"
description = "RabbitMQ message queue"

# RabbitMQ Management UI
[[dest.exposed_services]]
name = "rabbitmq-mgmt"
port = 15672
target_ip = "10.0.4.10"
target_port = 15672
protocol = "tcp"
description = "RabbitMQ management"

# Apache Kafka
[[dest.exposed_services]]
name = "kafka"
port = 9092
target_ip = "10.0.4.11"
target_port = 9092
protocol = "tcp"
description = "Kafka broker"
```

### Monitoring & Observability

```toml
# Prometheus
[[dest.exposed_services]]
name = "prometheus"
port = 9090
target_ip = "10.0.6.10"
target_port = 9090
protocol = "tcp"
description = "Prometheus metrics"

# Grafana
[[dest.exposed_services]]
name = "grafana"
port = 3001
target_ip = "10.0.6.11"
target_port = 3000
protocol = "tcp"
description = "Grafana dashboards"

# Jaeger Tracing
[[dest.exposed_services]]
name = "jaeger"
port = 16686
target_ip = "10.0.6.12"
target_port = 16686
protocol = "tcp"
description = "Jaeger UI"
```

### UDP Services

```toml
# DNS
[[dest.exposed_services]]
name = "dns"
port = 53
target_ip = "10.0.7.1"
target_port = 53
protocol = "udp"
description = "DNS resolver"

# NTP
[[dest.exposed_services]]
name = "ntp"
port = 123
target_ip = "10.0.7.2"
target_port = 123
protocol = "udp"
description = "NTP time server"

# Syslog
[[dest.exposed_services]]
name = "syslog"
port = 514
target_ip = "10.0.7.3"
target_port = 514
protocol = "udp"
description = "Syslog server"
```

## Docker Compose Configuration

When exposing multiple services, update your `docker-compose.yml`:

```yaml
services:
  utun-source:
    ports:
      # Primary tunnel
      - "8443:8443"
      - "8443:8443/udp"

      # Web services
      - "80:80"
      - "443:443"
      - "3000:3000"

      # Databases
      - "3306:3306"    # MySQL
      - "5432:5432"    # PostgreSQL
      - "6379:6379"    # Redis
      - "27017:27017"  # MongoDB

      # Message Queues
      - "5672:5672"    # RabbitMQ
      - "9092:9092"    # Kafka

      # Monitoring
      - "9090:9090"    # Prometheus/Metrics
      - "3001:3001"    # Grafana

      # UDP services
      - "53:53/udp"    # DNS
      - "123:123/udp"  # NTP

  utun-dest:
    ports:
      - "9443:9443"    # Tunnel endpoint
      - "9091:9091"    # Metrics
```

## Port Mapping Strategy

### Same Port Mapping
Most common - use the same port on both sides:

```toml
[[dest.exposed_services]]
name = "postgres"
port = 5432           # Tunnel port
target_port = 5432    # Target port (same)
```

### Different Port Mapping
Map different ports when you have conflicts or want to consolidate:

```toml
[[dest.exposed_services]]
name = "internal-web"
port = 8080           # Expose on tunnel as 8080
target_port = 3000    # But forward to app on port 3000
```

### Multiple Instances
Run multiple instances of the same service:

```toml
[[dest.exposed_services]]
name = "postgres-primary"
port = 5432
target_ip = "10.0.2.10"
target_port = 5432

[[dest.exposed_services]]
name = "postgres-replica"
port = 5433           # Different tunnel port
target_ip = "10.0.2.11"
target_port = 5432    # Same target port, different host
```

## Performance Tuning

### Connection Limits

Adjust per-service connection limits:

```toml
[dest]
max_connections_per_service = 100  # Default for all services
```

For high-traffic services, increase limits:

```toml
[dest]
max_connections_per_service = 1000  # Higher limit
```

### Timeouts

Configure timeouts based on service behavior:

```toml
[dest]
connection_timeout_ms = 15000        # Client connection timeout
target_connect_timeout_ms = 5000     # Target service timeout
```

For databases with long-running queries:

```toml
[dest]
connection_timeout_ms = 300000       # 5 minutes
```

## Security Considerations

### IP Filtering

Restrict which clients can connect:

```toml
[dest.connection_filter]
allowed_source_ips = [
    "172.28.1.10/32",   # Source container
    "10.0.0.0/8",        # Internal network only
]
```

### Network Isolation

Use Docker networks to isolate services:

```yaml
networks:
  tunnel-net:
    driver: bridge
  backend-net:
    driver: bridge
    internal: true    # No external access
```

### Service Separation

Group services by security level:

```toml
# Public-facing services
[[dest.exposed_services]]
name = "web"
port = 443
target_ip = "10.0.1.20"

# Internal-only services
[[dest.exposed_services]]
name = "admin-db"
port = 5433
target_ip = "10.0.2.99"
```

## Monitoring Multiple Services

Each service is monitored independently. Access metrics:

```bash
# Overall metrics
curl http://localhost:9090/metrics | grep service_

# Example metrics per service:
# - utun_service_connections{service="postgresql"}
# - utun_service_bytes_sent{service="redis"}
# - utun_service_bytes_received{service="web-app"}
# - utun_service_errors{service="rabbitmq"}
```

## Example Use Cases

### Full Stack Application

```toml
# Frontend
[[dest.exposed_services]]
name = "react-app"
port = 3000

# Backend API
[[dest.exposed_services]]
name = "api"
port = 8080

# Database
[[dest.exposed_services]]
name = "postgres"
port = 5432

# Cache
[[dest.exposed_services]]
name = "redis"
port = 6379
```

### Microservices Architecture

```toml
# Gateway
[[dest.exposed_services]]
name = "api-gateway"
port = 80

# Auth Service
[[dest.exposed_services]]
name = "auth-svc"
port = 3001

# User Service
[[dest.exposed_services]]
name = "user-svc"
port = 3002

# Order Service
[[dest.exposed_services]]
name = "order-svc"
port = 3003

# Shared Database
[[dest.exposed_services]]
name = "postgres"
port = 5432
```

### Development Environment

```toml
# All development tools accessible through one tunnel
[[dest.exposed_services]]
name = "vscode-server"
port = 8080

[[dest.exposed_services]]
name = "jupyter"
port = 8888

[[dest.exposed_services]]
name = "dev-db"
port = 5432

[[dest.exposed_services]]
name = "dev-redis"
port = 6379
```

## Troubleshooting

### Port Conflicts

If you get "port already in use" errors:

1. Check existing services: `docker ps`
2. Check host port usage: `netstat -tulpn | grep <port>`
3. Choose different ports in config or docker-compose

### Service Not Reachable

1. Verify service is in config: `grep <service-name> config.toml`
2. Check target IP is reachable from dest container
3. Verify firewall rules allow traffic
4. Check logs: `docker logs utun-dest`

### Connection Limits

If seeing "connection refused" under load:

1. Increase `max_connections_per_service`
2. Check target service connection limits
3. Monitor metrics for bottlenecks

## Complete Example Files

See the example configurations:

- `config-dest-multi-service.toml` - 20+ service configuration
- `config-source-multi-port.toml` - Multiple port exposure
- `docker-compose-multi-service.yml` - Full Docker setup

## Testing Your Configuration

```bash
# Validate config
./target/release/utun dest --config examples/config-dest-multi-service.toml --dry-run

# Start services
docker-compose -f examples/docker-compose-multi-service.yml up -d

# Test each service
nc -zv localhost 5432  # PostgreSQL
nc -zv localhost 6379  # Redis
nc -zv localhost 3000  # Web app

# Check metrics
curl http://localhost:9091/metrics | grep service_connections
```
