from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class LoginRequest(BaseModel):
    username: str
    password: str

class SearchRequest(BaseModel):
    query: Optional[Dict[str, Any]] = None
    search_text: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    severity: Optional[List[str]] = None
    event_type: Optional[List[str]] = None
    source: Optional[List[str]] = None

class ExportRequest(BaseModel):
    format: str = "json"
    query: Optional[Dict[str, Any]] = None