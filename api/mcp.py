# api/mcp.py

import os
import re
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Request, HTTPException, Body
from typing import Annotated, Any

# --- NEW: Import Firestore ---
from google.cloud import firestore
import google.auth.credentials
import base64
import json

# --- FastAPI App ---
app = FastAPI()

# --- Environment Variables ---
TOKEN = os.environ.get("AUTH_TOKEN")
MY_NUMBER = os.environ.get("MY_NUMBER")
# --- NEW: Firestore Credentials ---
# We'll get this from Vercel Environment Variables
FIRESTORE_CREDS_B64 = os.environ.get("FIRESTORE_CREDS_B64")

if not all([TOKEN, MY_NUMBER, FIRESTORE_CREDS_B64]):
    raise RuntimeError("AUTH_TOKEN, MY_NUMBER, and FIRESTORE_CREDS_B64 must be set.")

SERVER_ID = f"mcp.puch.ai:server:{MY_NUMBER}"

# --- NEW: Firestore Database Setup ---
try:
    # Decode the Base64 string back into JSON
    creds_json_str = base64.b64decode(FIRESTORE_CREDS_B64).decode('utf-8')
    creds_info = json.loads(creds_json_str)
    credentials = google.oauth2.service_account.Credentials.from_service_account_info(creds_info)
    db = firestore.Client(credentials=credentials)
    print("Firestore client initialized successfully.")
except Exception as e:
    print(f"CRITICAL: Failed to initialize Firestore client: {e}")
    db = None # Set db to None if initialization fails

# --- Helper Function to Parse Workout String ---
def parse_workout_string(log_string: str) -> dict | None:
    """
    Parses a string like "Incline 12.5x2x8" or "Squat 15x8x3".
    Returns a dictionary with the parsed data or None if it fails.
    """
    # Regex to find: (Exercise Name) (Weight)x(Sets)x(Reps)
    # It handles decimals in weight and optional "per side" (x2)
    pattern = re.compile(
        r"^(?P<name>[\w\s]+?)\s+"  # Exercise name (non-greedy)
        r"(?P<weight>[\d\.]+)"    # Weight (can be decimal)
        r"(?:\s*x\s*(?P<per_side>2))?"  # Optional 'x2' for per side
        r"\s*x\s*(?P<sets>[\d]+)"      # Sets
        r"\s*x\s*(?P<reps>[\d]+)$",    # Reps
        re.IGNORECASE
    )
    match = pattern.match(log_string.strip())
    if not match:
        # A simpler pattern for things like "Chest fly 44x8"
        simple_pattern = re.compile(
            r"^(?P<name>[\w\s]+?)\s+"
            r"(?P<weight>[\d\.]+)"
            r"\s*x\s*(?P<reps>[\d]+)$",
            re.IGNORECASE
        )
        match = simple_pattern.match(log_string.strip())
        if not match:
            return None # Could not parse
    
    data = match.groupdict()
    
    return {
        "name": data["name"].strip().title(),
        "weight": float(data["weight"]),
        "sets": int(data.get("sets") or 1), # Default to 1 set if not specified
        "reps": int(data["reps"]),
        "per_side": data.get("per_side") is not None
    }

# --- MANIFEST ENDPOINT ---
# We've updated the tools list
@app.api_route("/", methods=["GET", "POST"])
async def get_manifest() -> dict[str, Any]:
    return {
        "mcp_version": "1.0",
        "server_id": SERVER_ID,
        "name": "Workout Logger",
        "author": "You!",
        "description": "A server to log workouts and track progress over time.",
        "auth": {"auth_type": "http_bearer"},
        "tools": {
            "validate": {
                "description": "Validates the server connection.",
                "parameters": [],
                "returns": [{"type": "string"}]
            },
            "log_workout": {
                "description": "Logs a workout entry. E.g., 'Squat 100x5x5' or 'Incline Curl 12.5x2x8'.",
                "parameters": [
                    {"name": "entry", "type": "string", "description": "The workout string to log.", "required": True}
                ],
                "returns": [{"type": "text"}]
            },
            "view_progress": {
                "description": "Shows your last 5 logs for a specific exercise.",
                "parameters": [
                    {"name": "exercise", "type": "string", "description": "The name of the exercise to view.", "required": True}
                ],
                "returns": [{"type": "text"}]
            }
        }
    }

# --- VALIDATE TOOL ENDPOINT ---
@app.post("/run/validate")
async def run_validate(request: Request):
    # This remains the same
    auth_header = request.headers.get("Authorization")
    if not auth_header or auth_header != f"Bearer {TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")
    return MY_NUMBER

# --- NEW: LOG WORKOUT TOOL ---
@app.post("/run/log_workout")
async def run_log_workout(request: Request, entry: Annotated[str, Body(embed=True)]):
    auth_header = request.headers.get("Authorization")
    if not auth_header or auth_header != f"Bearer {TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")

    if not db:
        return [{"type": "text", "text": "Error: Database is not configured correctly."}]

    parsed_data = parse_workout_string(entry)

    if not parsed_data:
        return [{"type": "text", "text": f"Sorry, I couldn't understand that format. Try something like 'Bench Press 60x5x5'."}]

    # Add user ID and timestamp
    # For now, we use YOUR number as the user ID.
    user_id = f"whatsapp:{MY_NUMBER}"
    parsed_data["user_id"] = user_id
    parsed_data["timestamp"] = datetime.now(timezone.utc)

    try:
        # Add a new document to the 'workouts' collection
        doc_ref = db.collection("workouts").add(parsed_data)
        print(f"Logged workout with ID: {doc_ref[1].id}")
        
        # Format a nice confirmation message
        log_msg = (
            f"💪 Logged: {parsed_data['name']}!\n"
            f"- Weight: {parsed_data['weight']} kg"
            f"{' (per side)' if parsed_data['per_side'] else ''}\n"
            f"- Sets: {parsed_data['sets']}\n"
            f"- Reps: {parsed_data['reps']}"
        )
        return [{"type": "text", "text": log_msg}]
    except Exception as e:
        print(f"Error logging to Firestore: {e}")
        return [{"type": "text", "text": "Sorry, there was an error saving your workout."}]


# --- NEW: VIEW PROGRESS TOOL ---
@app.post("/run/view_progress")
async def run_view_progress(request: Request, exercise: Annotated[str, Body(embed=True)]):
    auth_header = request.headers.get("Authorization")
    if not auth_header or auth_header != f"Bearer {TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")

    if not db:
        return [{"type": "text", "text": "Error: Database is not configured correctly."}]

    user_id = f"whatsapp:{MY_NUMBER}"
    exercise_name = exercise.strip().title()

    try:
        # Query Firestore for the last 5 entries for this user and exercise
        docs = db.collection("workouts") \
            .where("user_id", "==", user_id) \
            .where("name", "==", exercise_name) \
            .order_by("timestamp", direction=firestore.Query.DESCENDING) \
            .limit(5) \
            .stream()

        logs = list(docs) # Convert generator to list

        if not logs:
            return [{"type": "text", "text": f"No logs found for '{exercise_name}'. Try logging one first!"}]

        response_text = f"📈 Progress for {exercise_name}:\n\n"
        
        # India Standard Time (IST) is UTC+5:30
        ist = timezone(timedelta(hours=5, minutes=30))

        for log in logs:
            data = log.to_dict()
            # Convert UTC timestamp from Firestore to IST for display
            timestamp_ist = data['timestamp'].astimezone(ist)
            date_str = timestamp_ist.strftime("%b %d, %Y")
            
            log_str = (
                f"- *{date_str}*: "
                f"{data['weight']}kg x {data['sets']} sets x {data['reps']} reps"
                f"{' (per side)' if data.get('per_side') else ''}"
            )
            response_text += log_str + "\n"
        
        return [{"type": "text", "text": response_text}]
    except Exception as e:
        print(f"Error querying Firestore: {e}")
        return [{"type": "text", "text": "Sorry, there was an error fetching your progress."}]

