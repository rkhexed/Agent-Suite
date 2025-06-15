import os
from app.Helper.helper_secret import access_secret_version

# Default GCP project ID
PROJECT_ID = os.environ.get("PROJECT_ID", "cyber-agent-463018")

GOOGLE_GENAI_API_KEY = access_secret_version(
    project_id = PROJECT_ID, secret_id = "google-genai-api-key"
)

