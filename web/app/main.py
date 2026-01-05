from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles  # Добавьте этот импорт
import logging
import uvicorn
import os

from .routes import router, log_requests
from .database import initialize_database_with_data
from .config import DB_SERVER_HOST, DB_SERVER_PORT, SECURITY_DB, SECURITY_COLLECTION

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SIEM Web Interface",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.middleware("http")(log_requests)

app.mount("/css", StaticFiles(directory="frontend/css"), name="css")
app.mount("/js", StaticFiles(directory="frontend/js"), name="js")
app.mount("/static", StaticFiles(directory="frontend"), name="static")

app.include_router(router)

if __name__ == "__main__":
    print("=" * 50)
    print("SIEM Web Server Starting...")
    print(f"Database: {DB_SERVER_HOST}:{DB_SERVER_PORT}")
    print(f"Security DB: {SECURITY_DB}.{SECURITY_COLLECTION}")
    print(f"Web Interface: http://localhost:8000")
    print("=" * 50)

    from .database import query_database
    print("Testing database connection...")
    test_response = query_database("find", SECURITY_COLLECTION, {})

    if test_response.get('status') == 'error':
        print(f"WARNING: Database connection failed: {test_response.get('message')}")
        print(f"Please ensure db_server is running on port {DB_SERVER_PORT}")
    else:
        event_count = test_response.get('count', 0)
        print(f"Database connection OK, found {event_count} events")

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        reload=False
    )