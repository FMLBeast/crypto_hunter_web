#!/bin/bash
echo "🚀 Starting LOCAL development (fastest!)..."

# Start only Redis
docker run -d --name redis-dev -p 6379:6379 redis:7-alpine 2>/dev/null || docker start redis-dev

echo "✅ Redis ready on localhost:6379"
echo "🏃 Starting Python app locally..."

python run_local.py
