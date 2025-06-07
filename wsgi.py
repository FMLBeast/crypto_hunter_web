from crypto_hunter_web import create_app

app = create_app()

if __name__ == "__main__":
    # for local debugging
    app.run(host="0.0.0.0", port=8000)
