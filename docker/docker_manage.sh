#!/bin/bash
# Docker Management Script for Crypto Hunter
# This script helps manage Docker containers for the Crypto Hunter project

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to display help
show_help() {
    echo -e "${YELLOW}Crypto Hunter Docker Management Script${NC}"
    echo "Usage: ./docker_manage.sh [command]"
    echo ""
    echo "Commands:"
    echo "  start                - Start all containers in detached mode"
    echo "  stop                 - Stop all containers"
    echo "  restart              - Restart all containers"
    echo "  status               - Show status of all containers"
    echo "  logs [svc] [lines]   - Show logs for a specific service or all services"
    echo "                         Optional: specify number of lines to show"
    echo "  build                - Rebuild all containers"
    echo "  clean                - Remove all containers, networks, and volumes"
    echo "  help                 - Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./docker_manage.sh start"
    echo "  ./docker_manage.sh logs web"
    echo "  ./docker_manage.sh logs web 100"
    echo "  ./docker_manage.sh logs all 50"
}

# Check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        echo -e "${RED}Error: Docker is not running or not installed.${NC}"
        echo "Please start Docker and try again."
        exit 1
    fi
}

# Start containers
start_containers() {
    echo -e "${GREEN}Starting Crypto Hunter containers...${NC}"

    # Check for existing containers with the same names
    if docker ps -a | grep -q "crypto-hunter"; then
        echo -e "${YELLOW}Found existing containers. Stopping and removing them...${NC}"
        docker stop $(docker ps -a | grep "crypto-hunter" | awk '{print $1}') 2>/dev/null || true
        docker rm $(docker ps -a | grep "crypto-hunter" | awk '{print $1}') 2>/dev/null || true
    fi

    # Start containers with the new project name and explicitly load .env file
    docker compose --env-file .env up -d
    echo -e "${GREEN}Containers started successfully!${NC}"
    echo ""
    docker compose --env-file .env ps
}

# Stop containers
stop_containers() {
    echo -e "${YELLOW}Stopping Crypto Hunter containers...${NC}"
    docker compose --env-file .env down
    echo -e "${GREEN}Containers stopped successfully!${NC}"
}

# Restart containers
restart_containers() {
    echo -e "${YELLOW}Restarting Crypto Hunter containers...${NC}"
    docker compose --env-file .env restart
    echo -e "${GREEN}Containers restarted successfully!${NC}"
    echo ""
    docker compose --env-file .env ps
}

# Show container status
show_status() {
    echo -e "${GREEN}Crypto Hunter container status:${NC}"
    docker compose --env-file .env ps
}

# Show logs
show_logs() {
    local service="$1"
    local lines="$2"
    local log_cmd="docker compose --env-file .env logs -f"

    # Handle service parameter
    if [ -n "$service" ] && [ "$service" != "all" ]; then
        log_cmd="$log_cmd $service"
    fi

    # Handle lines parameter
    if [ -n "$lines" ] && [[ "$lines" =~ ^[0-9]+$ ]]; then
        log_cmd="$log_cmd --tail=$lines"
    fi

    # Show what we're doing
    if [ -z "$service" ] || [ "$service" = "all" ]; then
        echo -e "${GREEN}Showing logs for all services:${NC}"
    else
        echo -e "${GREEN}Showing logs for $service:${NC}"
    fi

    # Execute the command
    eval "$log_cmd"
}

# Build containers
build_containers() {
    echo -e "${YELLOW}Building Crypto Hunter containers...${NC}"
    docker compose --env-file .env build
    echo -e "${GREEN}Containers built successfully!${NC}"
}

# Clean up
clean_up() {
    echo -e "${RED}WARNING: This will remove all containers, networks, and volumes!${NC}"
    read -p "Are you sure you want to continue? (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Cleaning up Crypto Hunter Docker resources...${NC}"
        docker compose --env-file .env down -v --remove-orphans
        echo -e "${GREEN}Cleanup completed successfully!${NC}"
    else
        echo -e "${YELLOW}Cleanup cancelled.${NC}"
    fi
}

# Make script executable
chmod +x "$0"

# Main script logic
check_docker

case "$1" in
    start)
        start_containers
        ;;
    stop)
        stop_containers
        ;;
    restart)
        restart_containers
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs "$2" "$3"
        ;;
    build)
        build_containers
        ;;
    clean)
        clean_up
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}Error: Unknown command '$1'${NC}"
        show_help
        exit 1
        ;;
esac

exit 0
