# CoreFlow360 V4 - Docker Enterprise Setup

This document provides comprehensive instructions for deploying CoreFlow360 V4 using Docker in an enterprise environment.

## 🏗️ Architecture Overview

The Docker setup provides a complete enterprise-grade deployment with:

- **Multi-stage builds** for optimized production images
- **Security hardening** with non-root users and minimal attack surface
- **Comprehensive monitoring** with Prometheus, Grafana, and Loki
- **Load balancing** with Nginx
- **Database clustering** with PostgreSQL and Redis
- **MCP server integration** for AI agent communication
- **Health checks** and automatic recovery
- **Resource limits** and scaling capabilities

## 📋 Prerequisites

### System Requirements
- Docker Engine 20.10+
- Docker Compose 2.0+
- 4GB RAM minimum (8GB recommended for production)
- 20GB disk space
- Linux/macOS/Windows with WSL2

### Required Software
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

## 🚀 Quick Start

### 1. Clone and Setup
```bash
git clone <repository-url>
cd coreflow360-v4
cp env.example .env
```

### 2. Configure Environment
Edit `.env` file with your configuration:
```bash
# Required: Update these values
POSTGRES_PASSWORD=your_secure_password
REDIS_PASSWORD=your_secure_password
JWT_SECRET=your_jwt_secret_minimum_32_characters
ENCRYPTION_KEY=your_encryption_key_32_characters
GRAFANA_PASSWORD=your_grafana_password
```

### 3. Deploy
```bash
# Development deployment
npm run docker:deploy

# Production deployment
npm run docker:deploy:prod
```

## 🏢 Enterprise Deployment

### Production Configuration

For production deployments, use the production compose file:

```bash
# Production deployment with monitoring
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# With resource limits and scaling
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --scale app=3
```

### Security Hardening

The production setup includes:

- **Non-root containers** with minimal privileges
- **Read-only filesystems** where possible
- **Security headers** via Nginx
- **Rate limiting** and DDoS protection
- **Encrypted communication** with TLS
- **Secrets management** via environment variables

### Monitoring and Observability

Access monitoring dashboards:

- **Grafana**: http://localhost:3002 (admin/admin)
- **Prometheus**: http://localhost:9090
- **Application Health**: http://localhost:3000/health

## 🔧 Service Architecture

### Core Services

| Service | Port | Description |
|---------|------|-------------|
| app | 3000 | Main application server |
| frontend | 3001 | React frontend |
| postgres | 5432 | PostgreSQL database |
| redis | 6379 | Redis cache |
| nginx | 80/443 | Load balancer & reverse proxy |

### Monitoring Services

| Service | Port | Description |
|---------|------|-------------|
| prometheus | 9090 | Metrics collection |
| grafana | 3002 | Dashboards & visualization |
| loki | 3100 | Log aggregation |

### MCP Services

| Service | Port | Description |
|---------|------|-------------|
| mcp-server | 8080 | MCP server for AI agents |

## 📊 Monitoring & Health Checks

### Health Check Endpoints

```bash
# Application health
curl http://localhost:3000/health

# Database health
docker-compose exec postgres pg_isready -U coreflow

# Redis health
docker-compose exec redis redis-cli ping

# All services status
docker-compose ps
```

### Log Management

```bash
# View all logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f app
docker-compose logs -f postgres

# View logs with timestamps
docker-compose logs -f -t
```

## 🔒 Security Configuration

### SSL/TLS Setup

1. **Generate SSL certificates**:
```bash
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem
```

2. **Update environment variables**:
```bash
ENABLE_SSL=true
SSL_CERT_PATH=/etc/nginx/ssl/cert.pem
SSL_KEY_PATH=/etc/nginx/ssl/key.pem
```

### Network Security

The setup uses isolated networks:
- `frontend`: Public-facing services
- `backend`: Internal application services
- `monitoring`: Monitoring and observability
- `mcp`: MCP server communication

### Secrets Management

For production, use a secrets management system:

```bash
# Using Docker Secrets (Swarm mode)
echo "your_secret" | docker secret create postgres_password -

# Using external secret management
# Update docker-compose.prod.yml to use external secrets
```

## 📈 Scaling and Performance

### Horizontal Scaling

```bash
# Scale application instances
docker-compose -f docker-compose.prod.yml up -d --scale app=5

# Scale with load balancer
docker-compose -f docker-compose.prod.yml up -d --scale app=3 --scale nginx=2
```

### Resource Limits

Production containers have resource limits:
- **App**: 1GB RAM, 1 CPU
- **PostgreSQL**: 2GB RAM, 2 CPU
- **Redis**: 512MB RAM, 0.5 CPU
- **Nginx**: 256MB RAM, 0.25 CPU

### Performance Tuning

```bash
# Database optimization
POSTGRES_SHARED_BUFFERS=256MB
POSTGRES_EFFECTIVE_CACHE_SIZE=1GB
POSTGRES_MAX_CONNECTIONS=200

# Redis optimization
REDIS_MAXMEMORY=400mb
REDIS_MAXMEMORY_POLICY=allkeys-lru
```

## 🛠️ Development Workflow

### Development Mode

```bash
# Start development environment
npm run docker:dev

# With hot reload
docker-compose up -d dev-app

# View development logs
docker-compose logs -f dev-app
```

### Testing

```bash
# Run tests in container
docker-compose run --rm test-runner

# Integration tests
docker-compose -f docker-compose.yml -f docker-compose.test.yml up --abort-on-container-exit
```

### Database Management

```bash
# Access database
docker-compose exec postgres psql -U coreflow -d coreflow360

# Run migrations
docker-compose exec app npm run db:migrate

# Backup database
docker-compose exec postgres pg_dump -U coreflow coreflow360 > backup.sql

# Restore database
docker-compose exec -T postgres psql -U coreflow -d coreflow360 < backup.sql
```

## 🔄 CI/CD Integration

### GitHub Actions Example

```yaml
name: Docker Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Deploy to production
        run: |
          npm run docker:deploy:prod
```

### Automated Deployment

```bash
# Deploy with health checks
./scripts/docker-deploy.sh production

# Rollback on failure
docker-compose -f docker-compose.yml -f docker-compose.prod.yml down
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --scale app=1
```

## 🐛 Troubleshooting

### Common Issues

1. **Port conflicts**:
```bash
# Check port usage
netstat -tulpn | grep :3000
# Kill conflicting processes
sudo kill -9 <PID>
```

2. **Permission issues**:
```bash
# Fix file permissions
sudo chown -R $USER:$USER .
chmod +x scripts/docker-deploy.sh
```

3. **Memory issues**:
```bash
# Check Docker memory usage
docker stats
# Clean up unused resources
docker system prune -a
```

### Debug Mode

```bash
# Enable debug logging
DEBUG=* docker-compose up

# Access container shell
docker-compose exec app sh
docker-compose exec postgres psql -U coreflow
```

## 📚 Additional Resources

- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Docker Security](https://docs.docker.com/engine/security/)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)

## 🆘 Support

For issues and questions:
- Check the logs: `docker-compose logs -f`
- Review health checks: `npm run docker:health`
- Contact the CoreFlow360 team

---

**Note**: This setup is designed for enterprise use. Ensure you have proper security measures, backups, and monitoring in place for production deployments.
