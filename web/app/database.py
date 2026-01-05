import json
import socket
import asyncio
import random
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import logging
from concurrent.futures import ThreadPoolExecutor

from .config import DB_SERVER_PORT, SECURITY_DB, SECURITY_COLLECTION
from .utils import clean_json_string, parse_timestamp

logger = logging.getLogger(__name__)
executor = ThreadPoolExecutor(max_workers=10)

def query_database(
    operation: str,
    collection: str = SECURITY_COLLECTION,
    query: Optional[Dict] = None,
    data: Optional[List] = None,
) -> Dict:
    """Запрос к бд"""
    request_data = {
        "database": SECURITY_DB,
        "collection": collection,
        "operation": operation,
        "page": 1,
        "limit": 200
    }

    if query:
        if isinstance(query, dict):
            request_data["query"] = json.dumps(query)
        else:
            request_data["query"] = query

    if data:
        request_data["data"] = data

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(('localhost', int(DB_SERVER_PORT)))
        json_request = json.dumps(request_data)
        sock.sendall(json_request.encode('utf-8'))
        response_data = b""#чтение ответа
        sock.settimeout(3.0)
        while True:
            try:
                chunk = sock.recv(65536)
                if chunk:
                    response_data += chunk
                    if b'}' in chunk:
                        if response_data.count(b'{') == response_data.count(b'}'):
                            break
                else:
                    break
            except socket.timeout:
                break
            except Exception as e:
                break
        sock.close()

        if response_data:
            response_str = response_data.decode('utf-8', errors='ignore')
            json_start = response_str.find('{')
            json_end = response_str.rfind('}') + 1

            if json_start >= 0 and json_end > json_start:
                json_str = response_str[json_start:json_end]
                json_str = clean_json_string(json_str)

                try:
                    result = json.loads(json_str)
                    logger.info(f"DB response: status={result.get('status')}, count={result.get('count')}")
                    if "data" in result and isinstance(result["data"], list):
                        parsed_data = []
                        for item in result["data"]:
                            if isinstance(item, str):
                                try:
                                    parsed_item = json.loads(item)
                                    parsed_data.append(parsed_item)
                                except:
                                    parsed_data.append(item)
                            else:
                                parsed_data.append(item)
                        result["data"] = parsed_data

                    return result
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error: {e}")

        return {
            "status": "success",
            "message": "No data available",
            "data": [],
            "count": 0
        }

    except ConnectionRefusedError:
        logger.error("Database server is not running")
        return {
            "status": "error",
            "message": "Database server is not running",
            "data": [],
            "count": 0
        }
    except Exception as e:
        logger.error(f"Connection error: {e}")
        return {
            "status": "error",
            "message": f"Connection error: {str(e)}",
            "data": [],
            "count": 0
        }

def initialize_database_with_data():
    """Инициализация бд"""
    logger.info("Creating test data...")

    test_events = []
    now = datetime.now()

    for i in range(20):
        hours_ago = random.randint(0, 48)
        event_time = now - timedelta(hours=hours_ago)

        event = {
            "timestamp": event_time.isoformat(),
            "hostname": f"server-{random.randint(1, 5)}",
            "source": random.choice(['auditd', 'syslog', 'auth', 'bash_history']),
            "event_type": random.choice(['failed_login', 'successful_login', 'sudo_command', 'shell_command', 'file_access']),
            "severity": random.choice(['low', 'medium', 'high']),
            "user": random.choice(['root', 'admin', 'user', 'www-data']),
            "process": random.choice(['sshd', 'sudo', 'bash', 'nginx', 'systemd']),
            "command": f"command_{i}",
            "raw_log": f"Test log entry {i} at {event_time}",
            "agent_id": f"agent-{random.randint(1, 5)}"
        }

        test_events.append(json.dumps(event))
    try:
        request_data = {
            "database": SECURITY_DB,
            "collection": SECURITY_COLLECTION,
            "operation": "insert",
            "data": test_events
        }
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect(('localhost', int(DB_SERVER_PORT)))
        json_data = json.dumps(request_data)
        sock.sendall(json_data.encode('utf-8'))
        sock.close()
        logger.info(f"Added {len(test_events)} test events")

    except Exception as e:
        logger.error(f"Failed to add test data: {e}")

def build_search_query(
    search_text: Optional[str] = None,
    use_regex: bool = False,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    source: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
) -> Dict:
    """query для поиска в бд"""
    query = {}
    conditions = []
    if search_text:
        if use_regex:
            conditions.append({
                "$or": [
                    {"raw_log": {"$regex": search_text}},
                    {"user": {"$regex": search_text}},
                    {"process": {"$regex": search_text}},
                    {"command": {"$regex": search_text}},
                    {"hostname": {"$regex": search_text}}
                ]
            })
        else:
            conditions.append({
                "$or": [
                    {"raw_log": {"$like": f"%{search_text}%"}},
                    {"user": {"$like": f"%{search_text}%"}},
                    {"process": {"$like": f"%{search_text}%"}},
                    {"command": {"$like": f"%{search_text}%"}},
                    {"hostname": {"$like": f"%{search_text}%"}}
                ]
            })
    if severity:
        conditions.append({"severity": severity})

    if event_type:
        conditions.append({"event_type": event_type})

    if source:
        conditions.append({"source": source})
    if start_date and end_date:
        try:
            start_dt = datetime.strptime(start_date, "%Y-%m-%d")
            end_dt = datetime.strptime(end_date, "%Y-%m-%d")
            days_diff = (end_dt - start_dt).days
            if days_diff <= 30:
                date_patterns = []
                current_date = start_dt
                while current_date <= end_dt:
                    date_patterns.append({"timestamp": {"$like": f"{current_date.strftime('%Y-%m-%d')}%"}})
                    current_date += timedelta(days=1)
                
                if len(date_patterns) == 1:
                    conditions.append(date_patterns[0])
                else:
                    conditions.append({"$or": date_patterns})
            else:
                conditions.append({"timestamp": {"$like": f"{start_date}%"}})
        except ValueError:
            conditions.append({"timestamp": {"$like": f"{start_date}%"}})
    elif start_date:
        conditions.append({"timestamp": {"$like": f"{start_date}%"}})
    elif end_date:
        conditions.append({"timestamp": {"$like": f"{end_date}%"}})
    if conditions:
        if len(conditions) == 1:
            query = conditions[0]
        else:
            query = {"$and": conditions}

    logger.info(f"Final query for search: {json.dumps(query, indent=2)}")
    return query

async def query_database_async(operation: str, collection: str = SECURITY_COLLECTION,
                              query: Optional[Dict] = None, data: Optional[List] = None):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        executor,
        lambda: query_database(operation, collection, query, data)
    )