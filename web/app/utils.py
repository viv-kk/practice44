import json
import re
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict
from .config import dashboard_cache

def parse_timestamp(timestamp_str):
    """timestamp"""
    if not timestamp_str:
        return None
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z", 
        "%Y-%m-%dT%H:%M:%S%z",    
        "%Y-%m-%dT%H:%M:%S",       
        "%Y-%m-%d %H:%M:%S",       
        "%Y-%m-%dT%H:%M:%S.%f",    
        "%Y-%m-%dT%H:%M:%S.%fZ",    
        "%Y-%m-%dT%H:%M:%SZ",      
        "%b %d %H:%M:%S",          
        "%Y-%m-%d",              
    ]

    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str, fmt)
        except:
            continue

    return None

def clean_json_string(json_str: str) -> str:
    """JSON"""
    if not json_str:
        return json_str
    json_str = json_str.replace('"', '"').replace('"', '"').replace("'", "'").replace("'", "'")
    import re
    json_str = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', json_str)
    json_str = json_str.replace('\\"', '"')
    json_str = re.sub(r',\s*}', '}', json_str)
    json_str = re.sub(r',\s*]', ']', json_str)
    return json_str

def get_cache_key(endpoint: str, params: dict = None) -> str:
    """Ключ кэша"""
    if params:
        import hashlib
        param_str = json.dumps(params, sort_keys=True)
        param_hash = hashlib.md5(param_str.encode()).hexdigest()[:8]
        return f"{endpoint}_{param_hash}"
    return endpoint

def cache_dashboard_data(cache_key: str, data: dict, ttl_seconds: int = 10):
    """Кэш данных"""
    dashboard_cache[cache_key] = {
        'timestamp': datetime.now(),
        'data': data,
        'ttl': ttl_seconds
    }

def get_cached_dashboard_data(cache_key: str):
    """Получение данных из кэша"""
    if cache_key in dashboard_cache:
        cached = dashboard_cache[cache_key]
        elapsed = (datetime.now() - cached['timestamp']).seconds
        if elapsed < cached.get('ttl', 10):  
            return cached['data']
        else:
            del dashboard_cache[cache_key]
    return None