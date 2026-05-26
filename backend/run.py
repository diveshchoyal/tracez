"""TraceZ Backend — Uvicorn Runner Script."""

import uvicorn

if __name__ == "__main__":
    print("[*] Launching TraceZ Safe Browsing API on http://127.0.0.1:8000")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
