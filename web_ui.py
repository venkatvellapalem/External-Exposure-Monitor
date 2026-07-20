import sys
from api.index import app

if __name__ == '__main__':
    print("=" * 60)
    print(" EASM Web Control Center — Ollama Light Theme ")
    print(" Running at: http://localhost:5000 ")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)
