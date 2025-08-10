import os
from fastapi import FastAPI, Request, HTTPException, Body
from typing import Annotated, Any

# --- FastAPI App ---
# This is a standard ASGI application that Vercel understands perfectly.
app = FastAPI()

# --- Environment Variables ---
TOKEN = os.environ.get("AUTH_TOKEN")
MY_NUMBER = os.environ.get("MY_NUMBER")
if not TOKEN or not MY_NUMBER:
    raise RuntimeError("AUTH_TOKEN and MY_NUMBER must be set in Vercel.")

SERVER_ID = f"mcp.puch.ai:server:{MY_NUMBER}"


# --- MANIFEST ENDPOINT ---
# Returns a plain Python dictionary that has the structure of a valid manifest.
@app.get("/")
async def get_manifest() -> dict[str, Any]:
    return {
        "mcp_version": "1.0",
        "server_id": SERVER_ID,
        "name": "Final Working Vercel Server",
        "auth": {
            "auth_type": "http_bearer",
        },
        "tools": {
            "validate": {
                "description": "Validates the server connection.",
                "parameters": [],
                "returns": [{"type": "string"}]
            },
            "echo": {
                "description": "A simple tool that echoes back your message.",
                "parameters": [
                    {"name": "text", "type": "string", "description": "The text to echo.", "required": True}
                ],
                "returns": [{"type": "text"}]
            }
        }
    }


# --- VALIDATE TOOL ENDPOINT ---
# Puch calls this to validate your server after you connect.
@app.post("/run/validate")
async def run_validate(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or auth_header != f"Bearer {TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # On success, Puch expects your number as a raw string response
    return MY_NUMBER


# --- ECHO TOOL ENDPOINT ---
# A simple tool to prove the server is working end-to-end.
@app.post("/run/echo")
async def run_echo(request: Request, text: Annotated[str, Body(embed=True)]):
    auth_header = request.headers.get("Authorization")
    if not auth_header or auth_header != f"Bearer {TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")

    # The response must be a list containing one or more content objects (dicts).
    return [
        {
            "type": "text",
            "text": f"It works! You said: {text}"
        }
    ]