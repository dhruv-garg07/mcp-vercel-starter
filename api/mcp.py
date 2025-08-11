import os
import asyncio
import logging
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth.providers.bearer import BearerAuthProvider, RSAKeyPair
from mcp.server.auth.provider import AccessToken
from pydantic import BaseModel
import yt_dlp
import assemblyai as aai

# --- Setup logging ---
logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] %(levelname)s - %(message)s"
)

# --- Load environment variables ---
load_dotenv()
TOKEN = os.getenv("AUTH_TOKEN")
MY_NUMBER = os.getenv("MY_NUMBER")
ASSEMBLY_KEY = os.getenv("ASSEMBLY_AI_API_KEY")

assert TOKEN, "Please set AUTH_TOKEN in your .env file"
assert MY_NUMBER, "Please set MY_NUMBER in your .env file"
assert ASSEMBLY_KEY, "Please set ASSEMBLY_AI_API_KEY in your .env file"

# --- Auth Provider ---
class SimpleBearerAuthProvider(BearerAuthProvider):
    def __init__(self, token: str):
        k = RSAKeyPair.generate()
        super().__init__(public_key=k.public_key, jwks_uri=None, issuer=None, audience=None)
        self.token = token

    async def load_access_token(self, token: str) -> AccessToken | None:
        if token == self.token:
            return AccessToken(
                token=token,
                client_id="puch-client",
                scopes=["*"],
                expires_at=None,
            )
        return None

# --- Rich Tool Description ---
class RichToolDescription(BaseModel):
    description: str
    use_when: str
    side_effects: str | None = None

youtube_summarizer = RichToolDescription(
    description="Summarizes, answers questions, or chats about YouTube video content by transcribing its audio.",
    use_when="When a YouTube link is provided and the user asks about its content.",
)

# --- MCP Server Setup ---
mcp = FastMCP(
    "YouTube Transcript MCP Server",
    auth=SimpleBearerAuthProvider(TOKEN),
)

# --- Tool: validate ---
@mcp.tool
async def validate() -> str:
    return MY_NUMBER

# --- Download Audio ---
def download_audio(link):
    logging.debug(f"Downloading audio from: {link}")
    try:
        os.makedirs("media", exist_ok=True)
        output_template = os.path.join("media", '%(id)s.%(ext)s')
        ydl_opts = {
            'format': 'bestaudio/best',
            'outtmpl': output_template,
            'postprocessors': [],
        }
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(link, download=True)
            file_ext = info.get('ext', 'webm')
            file_path = os.path.join("media", f"{info['id']}.{file_ext}")
            logging.debug(f"Audio downloaded to: {file_path}")
            return file_path
    except Exception as e:
        logging.error(f"Error downloading audio: {e}")
        return None

# --- Transcription ---
async def transcript(youtube_link: str) -> str:
    aai.settings.api_key = ASSEMBLY_KEY
    logging.info(f"Starting transcription for link: {youtube_link}")

    loop = asyncio.get_event_loop()
    audio_file = await loop.run_in_executor(None, download_audio, youtube_link)
    if not audio_file:
        return "Failed to download audio."

    try:
        logging.debug(f"Uploading {audio_file} to AssemblyAI...")
        transcriber = aai.Transcriber()
        transcript_obj = transcriber.transcribe(audio_file)
        logging.info("Transcription completed.")
        return transcript_obj.text if transcript_obj else "No transcript found."
    except Exception as e:
        logging.error(f"Error during transcription: {e}", exc_info=True)
        return f"Error during transcription: {e}"

# --- MCP Tool ---
@mcp.tool(description=youtube_summarizer.model_dump_json())
async def youtube_summarize(link: str):
    return await transcript(link)

# --- Run MCP Server ---
async def main():
    logging.info("🚀 Starting MCP server on http://0.0.0.0:8086")
    await mcp.run_async("streamable-http", host="0.0.0.0", port=8086)

if __name__ == "__main__":
    asyncio.run(main())