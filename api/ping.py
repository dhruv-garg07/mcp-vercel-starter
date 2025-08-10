# Minimal FastAPI function to prove detection
from fastapi import FastAPI
app = FastAPI()

@app.get("/")
def ok():
    return {"ok": True, "runtime": "python", "path": "/api/ping"}
