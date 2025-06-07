# Makefile
IMAGE_NAME=crypto_hunter_web

.PHONY: build up down logs

build:
	docker compose build

up: build
	docker compose up -d

down:
	docker compose down

logs-web:
	docker compose logs -f web

logs-worker:
	docker compose logs -f worker

test:
	pytest --maxfail=1 --disable-warnings -q

ci: test
	docker compose build
