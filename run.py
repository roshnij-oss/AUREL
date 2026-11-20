"""Start AUREL locally:  python run.py   ->  http://127.0.0.1:5000"""
import os
from aurel.server import create_app

if __name__ == "__main__":
    try:
        from dotenv import load_dotenv; load_dotenv()      # optional: keeps API keys in .env, never in code
    except ImportError:
        pass
    create_app().run(host="127.0.0.1", port=int(os.environ.get("AUREL_PORT", 5000)), debug=False, threaded=True)
