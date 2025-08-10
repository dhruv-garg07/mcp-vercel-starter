import os
from fastapi import FastAPI, Request, HTTPException, Body
from typing import Annotated, Any

# --- FastAPI App ---
app = FastAPI()

# --- Environment Variables ---
TOKEN = os.environ.get("AUTH_TOKEN")
MY_NUMBER = os.environ.get("MY_NUMBER")
if not TOKEN or not MY_NUMBER:
    raise RuntimeError("AUTH_TOKEN and MY_NUMBER must be set in Vercel.")

SERVER_ID = f"mcp.puch.ai:server:{MY_NUMBER}"


# --- MANIFEST ENDPOINT ---
#
# CRITICAL FIX: We change @app.get("/") to @app.api_route(...) to allow
# both GET (for browsers) and POST (for the Puch connect command).
#
@app.api_route("/", methods=["GET", "POST"])
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
@app.post("/run/validate")
async def run_validate(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or auth_header != f"Bearer {TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    return MY_NUMBER


# --- ECHO TOOL ENDPOINT ---
@app.post("/run/echo")
async def run_echo(request: Request, text: Annotated[str, Body(embed=True)]):
    auth_header = request.headers.get("Authorization")
    if not auth_header or auth_header != f"Bearer {TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")

    return [
        {
            "type": "text",
            "text": f"It works! You said: {text}"
        }
    ]