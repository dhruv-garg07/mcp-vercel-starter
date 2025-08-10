#
# This file contains the complete, Vercel-ready code for the official example.
# All indentation and syntax has been carefully checked.
#

import asyncio
import base64
import io
import os
from typing import Annotated

import httpx
import markdownify
import readabilipy
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth.providers.bearer import BearerAuthProvider, RSAKeyPair
from mcp import ErrorData, McpError
from mcp.server.auth.provider import AccessToken
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ImageContent, TextContent
from PIL import Image
from pydantic import AnyUrl, BaseModel, Field

# --- Load environment variables ---
load_dotenv()
TOKEN = os.environ.get("AUTH_TOKEN")
MY_NUMBER = os.environ.get("MY_NUMBER")
assert TOKEN is not None, "Please set AUTH_TOKEN in your Vercel Environment Variables"
assert MY_NUMBER is not None, "Please set MY_NUMBER in your Vercel Environment Variables"


# --- Auth Provider ---
class SimpleBearerAuthProvider(BearerAuthProvider):
    def __init__(self, token: str):
        k = RSAKeyPair.generate()
        super().__init__(public_key=k.public_key, jwks_uri=None, issuer=None, audience=None)
        self.token = token

    async def load_access_token(self, token: str) -> AccessToken | None:
        if token == self.token:
            return AccessToken(token=token, client_id="puch-client", scopes=["*"], expires_at=None)
        return None


# --- Models and Utility Classes ---
class RichToolDescription(BaseModel):
    description: str
    use_when: str
    side_effects: str | None = None


class Fetch:
    USER_AGENT = "Puch/1.0 (Autonomous)"

    @classmethod
    async def fetch_url(cls, url: str, user_agent: str, force_raw: bool = False) -> tuple[str, str]:
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url, follow_redirects=True, headers={"User-Agent": user_agent}, timeout=30)
            except httpx.HTTPError as e:
                raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Failed to fetch {url}: {e!r}"))
            if response.status_code >= 400:
                raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Failed to fetch {url} - status code {response.status_code}"))
            page_raw = response.text
            content_type = response.headers.get("content-type", "")
            is_page_html = "text/html" in content_type
            if is_page_html and not force_raw:
                return cls.extract_content_from_html(page_raw), ""
            return (page_raw, f"Content type {content_type} cannot be simplified to markdown, but here is the raw content:\n")

    @staticmethod
    def extract_content_from_html(html: str) -> str:
        ret = readabilipy.simple_json.simple_json_from_html_string(html, use_readability=True)
        if not ret or not ret.get("content"):
            return "<error>Page failed to be simplified from HTML</error>"
        content = markdownify.markdownify(ret["content"], heading_style=markdownify.ATX)
        return content

    @staticmethod
    async def Google_Search_links(query: str, num_results: int = 5) -> list[str]:
        ddg_url = f"https://html.duckduckgo.com/html/?q={query.replace(' ', '+')}"
        links = []
        async with httpx.AsyncClient() as client:
            resp = await client.get(ddg_url, headers={"User-Agent": Fetch.USER_AGENT})
            if resp.status_code != 200:
                return ["<error>Failed to perform search.</error>"]
        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.find_all("a", class_="result__a", href=True):
            href = a["href"]
            if "http" in href:
                links.append(href)
            if len(links) >= num_results:
                break
        return links or ["<error>No results found.</error>"]


# --- MCP SERVER SETUP (CRITICAL CHANGE) ---
# We rename 'mcp' to 'app' so Vercel can find it.
app = FastMCP(
    "Job Finder MCP Server",
    auth=SimpleBearerAuthProvider(TOKEN),
)


# --- Tools (CRITICAL CHANGE) ---
# We now use @app.tool instead of @mcp.tool
@app.tool
async def validate() -> str:
    return MY_NUMBER


JobFinderDescription = RichToolDescription(
    description="Smart job tool: analyze descriptions, fetch URLs, or search jobs based on free text.",
    use_when="Use this to evaluate job descriptions or search for jobs using freeform goals.",
    side_effects="Returns insights, fetched job descriptions, or relevant job links.",
)


@app.tool(description=JobFinderDescription.model_dump_json())
async def job_finder(
    user_goal: Annotated[str, Field(description="The user's goal (can be a description, intent, or freeform query)")],
    job_description: Annotated[str | None, Field(description="Full job description text, if available.")] = None,
    job_url: Annotated[AnyUrl | None, Field(description="A URL to fetch a job description from.")] = None,
    raw: Annotated[bool, Field(description="Return raw HTML content if True")] = False,
) -> str:
    if job_description:
        return (f"📝 **Job Description Analysis**\n\n---\n{job_description.strip()}\n---\n\nUser Goal: **{user_goal}**\n\n💡 Suggestions:\n- Tailor your resume.\n- Evaluate skill match.\n- Consider applying if relevant.")
    if job_url:
        content, _ = await Fetch.fetch_url(str(job_url), Fetch.USER_AGENT, force_raw=raw)
        return (f"🔗 **Fetched Job Posting from URL**: {job_url}\n\n---\n{content.strip()}\n---\n\nUser Goal: **{user_goal}**")
    if "look for" in user_goal.lower() or "find" in user_goal.lower():
        # THIS LINE IS NOW CORRECTED
        links = await Fetch.Google_Search_links(user_goal)
        return (f"🔍 **Search Results for**: _{user_goal}_\n\n" + "\n".join(f"- {link}" for link in links))
    raise McpError(ErrorData(code=INVALID_PARAMS, message="Please provide either a job description, a job URL, or a search query in user_goal."))


MAKE_IMG_BLACK_AND_WHITE_DESCRIPTION = RichToolDescription(
    description="Convert an image to black and white and save it.",
    use_when="Use this tool when the user provides an image URL and requests it to be converted to black and white.",
    side_effects="The image will be processed and saved in a black and white format.",
)


@app.tool(description=MAKE_IMG_BLACK_AND_WHITE_DESCRIPTION.model_dump_json())
async def make_img_black_and_white(
    puch_image_data: Annotated[str, Field(description="Base64-encoded image data to convert to black and white")] = None,
) -> list[TextContent | ImageContent]:
    try:
        image_bytes = base64.b64decode(puch_image_data)
        image = Image.open(io.BytesIO(image_bytes))
        bw_image = image.convert("L")
        buf = io.BytesIO()
        bw_image.save(buf, format="PNG")
        bw_bytes = buf.getvalue()
        bw_base64 = base64.b64encode(bw_bytes).decode("utf-8")
        return [ImageContent(type="image", mimeType="image/png", data=bw_base64)]
    except Exception as e:
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=str(e)))


# --- The if __name__ == '__main__' block has been REMOVED as it is not used by Vercel ---