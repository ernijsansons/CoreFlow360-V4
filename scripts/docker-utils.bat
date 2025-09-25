@echo off
REM CoreFlow360 V4 - Docker Utilities (Windows)
REM Collection of helpful Docker management scripts

setlocal enabledelayedexpansion

REM Function to show help
:show_help
echo CoreFlow360 V4 - Docker Utilities
echo.
echo Usage: %0 [COMMAND]
echo.
echo Commands:
echo   dev          Start development environment
echo   prod         Start production environment
echo   stop         Stop all containers
echo   clean        Clean up Docker resources
echo   logs         Show logs for all services
echo   health       Check health of all services
echo   build        Build all images
echo   push         Push images to registry
echo   pull         Pull latest images
echo   backup       Backup database
echo   restore      Restore database from backup
echo   shell        Open shell in app container
echo   test         Run tests in containers
echo   help         Show this help message
echo.
goto :eof

REM Function to check if Docker is running
:check_docker
docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not running. Please start Docker and try again.
    exit /b 1
)
goto :eof

REM Function to check if docker-compose is available
:check_compose
docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] docker-compose is not installed. Please install it and try again.
    exit /b 1
)
goto :eof

REM Function to start development environment
:start_dev
echo [INFO] Starting development environment...
call :check_docker
call :check_compose

if not exist .env (
    echo [WARNING] .env file not found. Creating from template...
    copy env.docker.example .env
    echo [WARNING] Please edit .env file with your configuration before continuing.
    exit /b 1
)

docker-compose -f docker-compose.dev.yml up -d
echo [SUCCESS] Development environment started!
echo [INFO] Services available at:
echo   - Backend API: http://localhost:3000
echo   - Frontend: http://localhost:3001
echo   - PostgreSQL: localhost:5432
echo   - Redis: localhost:6379
goto :eof

REM Function to start production environment
:start_prod
echo [INFO] Starting production environment...
call :check_docker
call :check_compose

if not exist .env (
    echo [ERROR] .env file not found. Please create it from env.docker.example
    exit /b 1
)

docker-compose up -d
echo [SUCCESS] Production environment started!
goto :eof

REM Function to stop all containers
:stop_all
echo [INFO] Stopping all containers...
docker-compose -f docker-compose.dev.yml down 2>nul
docker-compose down 2>nul
echo [SUCCESS] All containers stopped!
goto :eof

REM Function to clean up Docker resources
:clean_docker
echo [INFO] Cleaning up Docker resources...

REM Stop all containers
call :stop_all

REM Remove unused containers, networks, images, and build cache
docker system prune -f

REM Remove unused volumes
docker volume prune -f

echo [SUCCESS] Docker cleanup completed!
goto :eof

REM Function to show logs
:show_logs
echo [INFO] Showing logs for all services...
docker-compose -f docker-compose.dev.yml logs -f
goto :eof

REM Function to check health
:check_health
echo [INFO] Checking health of all services...

REM Check if containers are running
docker-compose -f docker-compose.dev.yml ps

REM Check application health
curl -f http://localhost:3000/health >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Backend API is not responding
) else (
    echo [SUCCESS] Backend API is healthy
)

curl -f http://localhost:3001 >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Frontend is not responding
) else (
    echo [SUCCESS] Frontend is healthy
)
goto :eof

REM Function to build all images
:build_images
echo [INFO] Building all Docker images...

REM Build main application
docker build -t coreflow360v4-app:latest .

REM Build frontend
docker build -t coreflow360v4-frontend:latest ./frontend

REM Build design system
if exist "design-system" (
    docker build -t design-system:latest ./design-system
)

echo [SUCCESS] All images built successfully!
goto :eof

REM Function to push images
:push_images
echo [INFO] Pushing images to registry...

REM Tag and push main application
docker tag coreflow360v4-app:latest ernijsansons/coreflow360v4-app:latest
docker push ernijsansons/coreflow360v4-app:latest

REM Tag and push frontend
docker tag coreflow360v4-frontend:latest ernijsansons/coreflow360v4-frontend:latest
docker push ernijsansons/coreflow360v4-frontend:latest

echo [SUCCESS] Images pushed to registry!
goto :eof

REM Function to pull latest images
:pull_images
echo [INFO] Pulling latest images...

docker pull ernijsansons/coreflow360v4-app:latest
docker pull ernijsansons/coreflow360v4-frontend:latest

echo [SUCCESS] Latest images pulled!
goto :eof

REM Function to backup database
:backup_database
echo [INFO] Backing up database...

for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
set "YY=%dt:~2,2%" & set "YYYY=%dt:~0,4%" & set "MM=%dt:~4,2%" & set "DD=%dt:~6,2%"
set "HH=%dt:~8,2%" & set "Min=%dt:~10,2%" & set "Sec=%dt:~12,2%"
set "BACKUP_FILE=backup_%YYYY%%MM%%DD%_%HH%%Min%%Sec%.sql"

docker-compose -f docker-compose.dev.yml exec -T postgres pg_dump -U coreflow coreflow360 > "%BACKUP_FILE%"

echo [SUCCESS] Database backed up to %BACKUP_FILE%
goto :eof

REM Function to restore database
:restore_database
if "%2"=="" (
    echo [ERROR] Please provide backup file path
    echo Usage: %0 restore ^<backup_file.sql^>
    exit /b 1
)

echo [INFO] Restoring database from %2...

docker-compose -f docker-compose.dev.yml exec -T postgres psql -U coreflow -d coreflow360 < "%2"

echo [SUCCESS] Database restored from %2
goto :eof

REM Function to open shell in app container
:open_shell
echo [INFO] Opening shell in app container...
docker-compose -f docker-compose.dev.yml exec app sh
goto :eof

REM Function to run tests
:run_tests
echo [INFO] Running tests...

REM Run backend tests
docker-compose -f docker-compose.dev.yml exec app npm test

REM Run frontend tests
docker-compose -f docker-compose.dev.yml exec frontend npm test

echo [SUCCESS] All tests completed!
goto :eof

REM Main script logic
if "%1"=="dev" (
    call :start_dev
) else if "%1"=="prod" (
    call :start_prod
) else if "%1"=="stop" (
    call :stop_all
) else if "%1"=="clean" (
    call :clean_docker
) else if "%1"=="logs" (
    call :show_logs
) else if "%1"=="health" (
    call :check_health
) else if "%1"=="build" (
    call :build_images
) else if "%1"=="push" (
    call :push_images
) else if "%1"=="pull" (
    call :pull_images
) else if "%1"=="backup" (
    call :backup_database
) else if "%1"=="restore" (
    call :restore_database %2
) else if "%1"=="shell" (
    call :open_shell
) else if "%1"=="test" (
    call :run_tests
) else if "%1"=="help" (
    call :show_help
) else if "%1"=="--help" (
    call :show_help
) else if "%1"=="-h" (
    call :show_help
) else if "%1"=="" (
    call :show_help
) else (
    echo [ERROR] Unknown command: %1
    call :show_help
    exit /b 1
)
