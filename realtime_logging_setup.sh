#!/bin/bash
# realtime_logs.sh - Real-time logging setup for your machine

echo "🔍 REAL-TIME DOCKER LOGGING SETUP"
echo "=================================="

# Function to show all container logs in real-time
show_all_logs() {
    echo "📋 Showing ALL container logs in real-time..."
    echo "Press Ctrl+C to stop"
    echo ""
    docker-compose logs -f
}

# Function to show specific container logs
show_container_logs() {
    local container=$1
    echo "📋 Showing logs for: $container"
    echo "Press Ctrl+C to stop"
    echo ""
    docker logs -f $container
}

# Function to show web app logs only
show_web_logs() {
    echo "🌐 Showing WEB APPLICATION logs..."
    echo "Press Ctrl+C to stop"
    echo ""
    docker logs -f hunter-web-1 2>&1 | while IFS= read -r line; do
        timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$timestamp] WEB: $line"
    done
}

# Function to show worker logs only
show_worker_logs() {
    echo "⚙️  Showing CELERY WORKER logs..."
    echo "Press Ctrl+C to stop"
    echo ""
    docker logs -f hunter-worker-1 2>&1 | while IFS= read -r line; do
        timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$timestamp] WORKER: $line"
    done
}

# Function to show formatted logs from all services
show_formatted_logs() {
    echo "📊 Showing FORMATTED logs from all services..."
    echo "Press Ctrl+C to stop"
    echo ""
    
    # Kill any existing background processes
    pkill -f "docker logs -f hunter-"
    
    # Start background log monitoring for each container
    docker logs -f hunter-web-1 2>&1 | sed 's/^/[WEB] /' &
    docker logs -f hunter-worker-1 2>&1 | sed 's/^/[WORKER] /' &
    docker logs -f hunter-beat-1 2>&1 | sed 's/^/[BEAT] /' &
    docker logs -f hunter-redis-1 2>&1 | sed 's/^/[REDIS] /' &
    
    # Wait for interrupt
    wait
}

# Function to set up persistent logging to files
setup_persistent_logging() {
    echo "💾 Setting up PERSISTENT LOGGING to files..."
    
    # Create logs directory
    mkdir -p logs
    
    # Start logging each container to separate files
    echo "Starting background logging processes..."
    
    # Web logs
    nohup docker logs -f hunter-web-1 > logs/web.log 2>&1 &
    echo $! > logs/web.pid
    
    # Worker logs  
    nohup docker logs -f hunter-worker-1 > logs/worker.log 2>&1 &
    echo $! > logs/worker.pid
    
    # Beat logs
    nohup docker logs -f hunter-beat-1 > logs/beat.log 2>&1 &
    echo $! > logs/beat.pid
    
    # Redis logs
    nohup docker logs -f hunter-redis-1 > logs/redis.log 2>&1 &
    echo $! > logs/redis.pid
    
    echo "✅ Persistent logging started!"
    echo "📁 Log files:"
    echo "   - logs/web.log (Web application)"
    echo "   - logs/worker.log (Celery worker)"
    echo "   - logs/beat.log (Celery beat)"
    echo "   - logs/redis.log (Redis)"
    echo ""
    echo "📋 To view logs in real-time:"
    echo "   tail -f logs/web.log"
    echo "   tail -f logs/worker.log"
    echo ""
    echo "🛑 To stop persistent logging:"
    echo "   ./realtime_logs.sh stop"
}

# Function to stop persistent logging
stop_persistent_logging() {
    echo "🛑 Stopping persistent logging..."
    
    if [ -d "logs" ]; then
        for pidfile in logs/*.pid; do
            if [ -f "$pidfile" ]; then
                pid=$(cat "$pidfile")
                kill $pid 2>/dev/null
                rm "$pidfile"
                echo "  ✅ Stopped process $pid"
            fi
        done
    fi
    
    echo "✅ All logging processes stopped"
}

# Function to show real-time tail of all log files
tail_all_logs() {
    echo "📊 Tailing ALL log files..."
    echo "Press Ctrl+C to stop"
    echo ""
    
    if [ ! -d "logs" ]; then
        echo "❌ No logs directory found. Run './realtime_logs.sh setup' first"
        exit 1
    fi
    
    # Use multitail if available, otherwise use regular tail
    if command -v multitail &> /dev/null; then
        multitail logs/web.log logs/worker.log logs/beat.log logs/redis.log
    else
        echo "💡 Tip: Install 'multitail' for better multi-file viewing"
        echo "   On Ubuntu: sudo apt install multitail"
        echo ""
        tail -f logs/*.log
    fi
}

# Main menu
case "${1:-menu}" in
    "all"|"a")
        show_all_logs
        ;;
    "web"|"w")
        show_web_logs
        ;;
    "worker"|"work")
        show_worker_logs
        ;;
    "formatted"|"f")
        show_formatted_logs
        ;;
    "setup"|"s")
        setup_persistent_logging
        ;;
    "stop")
        stop_persistent_logging
        ;;
    "tail"|"t")
        tail_all_logs
        ;;
    "menu"|*)
        echo "🔍 REAL-TIME LOGGING OPTIONS:"
        echo ""
        echo "📋 Basic Options:"
        echo "  ./realtime_logs.sh all       - Show all container logs"
        echo "  ./realtime_logs.sh web       - Show web application logs only"
        echo "  ./realtime_logs.sh worker    - Show celery worker logs only"
        echo ""
        echo "📊 Advanced Options:"
        echo "  ./realtime_logs.sh formatted - Show formatted logs from all services"
        echo "  ./realtime_logs.sh setup     - Set up persistent logging to files"
        echo "  ./realtime_logs.sh tail      - Tail all persistent log files"
        echo "  ./realtime_logs.sh stop      - Stop persistent logging"
        echo ""
        echo "🚀 Quick Commands:"
        echo "  docker-compose logs -f                    # All logs"
        echo "  docker logs -f hunter-web-1               # Web only"
        echo "  docker logs -f hunter-worker-1            # Worker only"
        echo "  docker logs --tail 100 hunter-web-1       # Last 100 lines"
        echo ""
        echo "💡 Pro Tips:"
        echo "  - Install 'multitail' for better log viewing"
        echo "  - Use './realtime_logs.sh setup' for background logging"
        echo "  - Check logs/web.log for persistent web logs"
        ;;
esac