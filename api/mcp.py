import os
import logging
from fastapi import FastAPI, Request, HTTPException
from puch_mcp_server.protocol import Manifest, RunRequest, RunResponse, Message, Content

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# This is the variable Vercel will look for. It must be named 'app'.
app = FastAPI()

# --- Load Environment Variables ---
# Best practice to load them once at startup.
AUTH_TOKEN = os.environ.get("AUTH_TOKEN")
PHONE_E164 = os.environ.get("PHONE_E164")

if not AUTH_TOKEN or not PHONE_E164:
    # This will cause a 500 error on Vercel if vars are not set, which is good.
    # It prevents the server from running in an invalid state.
    raise RuntimeError("Missing required environment variables: AUTH_TOKEN and/or PHONE_E164")

# The server_id is derived from your phone number.
SERVER_ID = f"mcp.puch.ai:server:{PHONE_E164}"
logger.info(f"Server starting with ID: {SERVER_ID}")

# --- MCP Endpoints ---

@app.get("/")
async def get_manifest():
    """
    This is the MANIFEST endpoint. It tells Puch what your server can do.
    It will be accessible via GET https://<your-url>/mcp
    """
    logger.info("Manifest requested")
    return Manifest(
        server_id=SERVER_ID,
        name="My Minimal Vercel MCP Server",
        author="Your Name",
        description="A simple echo bot for the Puch AI Hackathon.",
        tags=["hackathon", "echo", "minimal"],
        auth_token=AUTH_TOKEN # This is required for validation
    )

@app.post("/validate")
async def validate(request: Request):
    """
    This is the VALIDATE endpoint. Puch calls this once to verify your server.
    It will be accessible via POST https://<your-url>/mcp/validate
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or auth_header != f"Bearer {AUTH_TOKEN}":
        logger.warning("Validation failed: Invalid or missing auth token")
        raise HTTPException(status_code=401, detail="Unauthorized")

    logger.info("Validation successful")
    return {"status": "ok"}

@app.post("/run")
async def run(run_request: RunRequest) -> RunResponse:
    """
    This is the RUN endpoint. It's called every time a user sends a message.
    It will be accessible via POST https://<your-url>/mcp/run
    """
    logger.info(f"Run request received: {run_request.model_dump_json()}")
    
    # Simple Echo Bot Logic
    user_message = run_request.message.content.text
    response_text = f"You said: {user_message}"

    return RunResponse(
        message=Message(
            content=Content(
                text=response_text
            )
        )
    )