import os
from dotenv import load_dotenv

load_dotenv()

DB_SERVER_HOST = os.getenv("DB_SERVER_HOST", "127.0.0.1")
DB_SERVER_PORT = os.getenv("DB_SERVER_PORT", "8080")
SECURITY_DB = os.getenv("SECURITY_DB", "security_db")
SECURITY_COLLECTION = os.getenv("SECURITY_COLLECTION", "security_events")

USERS = {
    "admin": os.getenv("ADMIN_PASSWORD", "admin123"),
    "operator": os.getenv("OPERATOR_PASSWORD", "operator123")
}

dashboard_cache = {}