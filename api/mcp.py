from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import os

AUTH_TOKEN = os.getenv("AUTH_TOKEN", "devtoken")
PHONE_E164 = os.getenv("PHONE_E164", "919000000000")  # digits only

app = FastAPI(title="MCP on Vercel", version="1.0.0")

@app.get("/")
def manifest():
    return {
        "name": "basic-mcp",
        "version": "1.0.0",
        "tools": [
            {"name": "ping", "description": "Returns 'pong'.", "input_schema": {"type": "object", "properties": {}}},
            {"name": "echo", "description": "Echo back provided text.", "input_schema": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"]
            }}
        ],
    }

class ValidateRequest(BaseModel):
    token: Optional[str] = None

def _check_token(authorization: Optional[str], token_in_body: Optional[str]) -> None:
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
    elif token_in_body:
        token = token_in_body
    if token != AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/validate")
def validate(req: ValidateRequest, authorization: Optional[str] = Header(default=None, alias="Authorization")):
    _check_token(authorization, req.token)
    if not PHONE_E164.isdigit():
        raise HTTPException(status_code=400, detail="PHONE_E164 must be digits only, like 919876543210")
    return {"ok": True, "phone": PHONE_E164}

class RunRequest(BaseModel):
    tool: str
    args: Dict[str, Any] = {}

@app.post("/run")
def run_tool(req: RunRequest, authorization: Optional[str] = Header(default=None, alias="Authorization")):
    _check_token(authorization, None)
    if req.tool == "ping":
        return {"ok": True, "result": "pong"}
    if req.tool == "echo":
        return {"ok": True, "result": str(req.args.get("text", ""))}
    raise HTTPException(status_code=404, detail=f"Unknown tool: {req.tool}")