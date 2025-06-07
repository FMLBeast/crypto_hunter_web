#!/usr/bin/env python3
# celery_worker_entrypoint.py

from crypto_hunter_web import create_app
from crypto_hunter_web.services.celery_config import celery_app

# Instantiate your Flask app (create_app() already registers all blueprints)
app = create_app()

# Public health endpoint
from flask import jsonify
@app.route("/health")
def health():
    return jsonify(status="ok"), 200

# Allow direct run too
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
