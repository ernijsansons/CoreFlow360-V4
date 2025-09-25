# CoreFlow360 V4 - Docker Setup Guide

This guide provides comprehensive instructions for setting up, building, and deploying CoreFlow360 V4 using Docker and Docker Compose.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Development Setup](#development-setup)
- [Production Deployment](#production-deployment)
- [CI/CD Pipeline](#cicd-pipeline)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

## 🚀 Prerequisites

Before you begin, ensure you have the following installed:

- **Docker** (version 20.10 or higher)
- **Docker Compose** (version 2.0 or higher)
- **Node.js** (version 18 or higher) - for local development
- **Git** - for version control

### Verify Installation

```bash
# Check Docker version
docker --version
docker-compose --version

# Check if Docker is running
docker info
```

## ⚡ Quick Start

### 1. Clone and Setup

```bash
# Clone the repository
git clone <your-repo-url>
cd coreflow360-v4

# Copy environment file
cp env.docker.example .env

# Edit environment variables
nano .env  # or use your preferred editor
```

### 2. Start Development Environment

```bash
# Start all services
docker-compose -f docker-compose.dev.yml up -d

# View logs
docker-compose -f docker-compose.dev.yml logs -f

# Check service status
docker-compose -f docker-compose.dev.yml ps
```

### 3. Access the Application

- **Backend API**: http://localhost:3000
- **Frontend**: http://localhost:3001
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

## 🛠 Development Setup

### Development Environment

The development setup includes hot reloading, debugging support, and development tools.

```bash
# Start development environment
docker-compose -f docker-compose.dev.yml up -d

# View logs for specific service
docker-compose -f docker-compose.dev.yml logs -f app

# Execute commands in running container
docker-compose -f docker-compose.dev.yml exec app npm run test

# Stop development environment
docker-compose -f docker-compose.dev.yml down
```

### Building Images Manually

```bash
# Build main application
docker build -t coreflow360v4-app:latest .

# Build frontend
docker build -t coreflow360v4-frontend:latest ./frontend

# Build design system
docker build -t design-system:latest ./design-system
```

### Running Tests

```bash
# Run all tests
docker-compose -f docker-compose.dev.yml exec app npm test

# Run frontend tests
docker-compose -f docker-compose.dev.yml exec frontend npm test

# Run with coverage
docker-compose -f docker-compose.dev.yml exec app npm run test:coverage
```

## 🚀 Production Deployment

### Using Docker Compose

```bash
# Start production environment
docker-compose up -d

# Scale services
docker-compose up -d --scale app=3

# Update services
docker-compose pull
docker-compose up -d
```

### Using Docker Images

```bash
# Pull images from registry
docker pull ernijsansons/coreflow360v4-app:latest
docker pull ernijsansons/coreflow360v4-frontend:latest

# Run with environment variables
docker run -d \
  --name coreflow360-app \
  -p 3000:3000 \
  -e NODE_ENV=production \
  -e DATABASE_URL=postgresql://user:pass@host:5432/db \
  ernijsansons/coreflow360v4-app:latest
```

### Health Checks

```bash
# Check application health
curl http://localhost:3000/health

# Check all services
docker-compose ps

# View health check logs
docker inspect coreflow360-app | grep -A 10 Health
```

## 🔄 CI/CD Pipeline

### GitHub Actions Setup

1. **Configure Secrets** in your GitHub repository:
   - `DOCKER_USERNAME`: Your Docker Hub username
   - `DOCKERHUB_TOKEN`: Your Docker Hub access token
   - `SLACK_WEBHOOK`: (Optional) Slack webhook for notifications

2. **Workflow Triggers**:
   - **Push to `main`**: Builds and deploys to production
   - **Push to `develop`**: Builds and deploys to staging
   - **Pull Requests**: Runs tests and security scans
   - **Tags**: Triggers production deployment

### Manual Deployment

```bash
# Build and push to registry
docker build -t ernijsansons/coreflow360v4-app:latest .
docker push ernijsansons/coreflow360v4-app:latest

# Deploy using docker-compose
docker-compose pull
docker-compose up -d
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Port Already in Use

```bash
# Check what's using the port
lsof -i :3000

# Stop conflicting services
docker-compose down
```

#### 2. Database Connection Issues

```bash
# Check database logs
docker-compose logs postgres

# Test database connection
docker-compose exec postgres pg_isready -U coreflow
```

#### 3. Permission Issues

```bash
# Fix file permissions
sudo chown -R $USER:$USER .

# Rebuild with no cache
docker-compose build --no-cache
```

#### 4. Out of Disk Space

```bash
# Clean up Docker resources
docker system prune -a

# Remove unused volumes
docker volume prune
```

### Debugging

```bash
# Access container shell
docker-compose exec app sh

# View container logs
docker-compose logs -f app

# Inspect container
docker inspect coreflow360-app
```

## 📚 Best Practices

### Security

1. **Use non-root users** in containers
2. **Scan images** for vulnerabilities
3. **Use secrets** for sensitive data
4. **Keep base images** updated
5. **Use multi-stage builds** to reduce image size

### Performance

1. **Use `.dockerignore`** to exclude unnecessary files
2. **Leverage layer caching** by ordering Dockerfile commands
3. **Use multi-stage builds** for smaller production images
4. **Enable BuildKit** for faster builds

### Development

1. **Use volume mounts** for development
2. **Separate dev/prod** configurations
3. **Use health checks** for service dependencies
4. **Implement proper logging**

### Monitoring

1. **Use structured logging**
2. **Implement health checks**
3. **Monitor resource usage**
4. **Set up alerts**

## 📁 File Structure

```
coreflow360-v4/
├── .dockerignore              # Docker ignore file
├── .github/
│   └── workflows/
│       ├── docker-build.yml   # Main CI/CD workflow
│       └── pr-check.yml       # PR validation workflow
├── docker-compose.yml         # Production compose
├── docker-compose.dev.yml     # Development compose
├── Dockerfile                 # Main application Dockerfile
├── frontend/
│   ├── Dockerfile            # Frontend Dockerfile
│   └── nginx.conf            # Nginx configuration
├── env.docker.example        # Environment template
└── DOCKER_README.md          # This file
```

## 🆘 Support

If you encounter issues:

1. Check the [troubleshooting section](#troubleshooting)
2. Review Docker and application logs
3. Ensure all environment variables are set correctly
4. Verify Docker and Docker Compose versions

For additional help, please refer to the main project documentation or create an issue in the repository.

---

**Happy Dockerizing! 🐳**