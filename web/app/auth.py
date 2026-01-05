from fastapi import HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import base64
from .config import USERS

security = HTTPBasic()

def verify_user(credentials: HTTPBasicCredentials = Depends(security)):
    """Basic Auth credentials"""
    correct_password = USERS.get(credentials.username)
    if not correct_password or credentials.password != correct_password:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username