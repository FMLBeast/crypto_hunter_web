#!/bin/bash
echo "📺 Real-time logs (Ctrl+C to stop)"
docker compose -f docker-compose.dev.yml logs -f --tail=100
