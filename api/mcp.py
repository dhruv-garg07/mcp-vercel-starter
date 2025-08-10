import os
from fastapi import FastAPI, Request, HTTPException, Body
from typing import Annotated

# NOTE: We are using the low-level MCP objects, not the FastMCP framework
from mcp.server.spec import Manifest, ToolSpec
from mcp.types import TextContent, Primitive, Parameter, ErrorData, INTERNAL_ERROR
from mcp.server.auth.spec import AuthSpec

# --- FastAPI App ---
# This is a standard ASGI application that Vercel understands perfectly.
app = FastAPI()

# --- Environment Variables ---
TOKEN = os.environ.get("AUTH_TOKEN")
MY_NUMBER = os.environ.get("MY_NUMBER")
if not TOKEN or not MY_NUMBER:
    raise RuntimeError("AUTH_TOKEN and MY_NUMBER must be set in Vercel.")

SERVER_ID = f"mcp.puch.ai:server:{MY_NUMBER}"

# --- Manually Define the Server Manifest ---
# We are creating the manifest object ourselves.
@app.get("/")
async def get_manifest() -> Manifest:
    return Manifest(
        mcp_version="1.0",
        server_id=SERVER_ID,
        name="My Minimal Working Vercel Server",
        auth=AuthSpec(
            auth_type="http_bearer", # Simple bearer token auth
        ),
        tools={
            "validate": ToolSpec(
                description="Validates the server connection.",
                parameters=[],
                returns=[Primitive(type="string")],
            ),
            "echo": ToolSpec(
                description="A simple tool that echoes back your message.",
                parameters=[
                    Parameter(name="text", type="string", description="The text to echo.", required=True)
                ],
                returns=[TextContent()],
            )
        }
    )

# --- Manually Define the 'validate' Tool ---
# This is the endpoint Puch will call to validate your server.
@app.post("/run/validate")
async def run_validate(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or auth_header != f"Bearer {TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # On successful validation, return your number as a simple string
    return MY_NUMBER


# --- Manually Define the 'echo' Tool ---
# This proves the server is working end-to-end.
@app.post("/run/echo")
async def run_echo(request: Request, text: Annotated[str, Body(embed=True)]):
    auth_header = request.headers.get("Authorization")
    if not auth_header or auth_header != f"Bearer {TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")

    return [TextContent(text=f"Echo: {text}")]