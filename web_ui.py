from pathlib import Path
from flask import send_from_directory
from api.index import app

BASE_DIR = Path(__file__).resolve().parent
public_dir = BASE_DIR / "public"

@app.route('/')
@app.route('/<path:path>')
def serve_frontend(path=""):
    if path and (public_dir / path).exists():
        return send_from_directory(str(public_dir), path)
    return send_from_directory(str(public_dir), "index.html")

if __name__ == '__main__':
    print("=" * 60)
    print(" EASM Web Control Center — Ollama Light Theme ")
    print(" Running at: http://localhost:5000 ")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)
