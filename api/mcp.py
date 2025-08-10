import logging
from fastapi import FastAPI

# Set up logging so we can see messages in Vercel
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- THE TEST ---
# We will try to import the library.
# We are GUESSING the name is 'puchmcp'. If the real name is different,
# change it here.
PACKAGE_NAME_TO_TEST = "puchmcp" 

try:
    # Dynamically import to see if it works
    __import__(PACKAGE_NAME_TO_TEST)
    from puchmcp.protocol import Manifest
    logger.info(f"✅ SUCCESS: Successfully imported 'Manifest' from '{PACKAGE_NAME_TO_TEST}.protocol'")
    IMPORT_SUCCESSFUL = True
except ModuleNotFoundError:
    logger.error(f"❌ FAILURE: Module named '{PACKAGE_NAME_TO_TEST}' was not found.")
    IMPORT_SUCCESSFUL = False
except (ImportError, AttributeError) as e:
    logger.error(f"❌ FAILURE: Found module '{PACKAGE_NAME_TO_TEST}', but could not import 'Manifest' from it. Error: {e}")
    IMPORT_SUCCESSFUL = False

# --- Basic FastAPI App ---
app = FastAPI()

@app.get("/mcp")
def root_check():
    """
    A simple endpoint to prove the server is running.
    Check the logs to see the result of the import test.
    """
    if IMPORT_SUCCESSFUL:
        return {"status": "Server running", "import_test": "PASSED"}
    else:
        return {"status": "Server running", "import_test": "FAILED - Check Vercel logs for details."}