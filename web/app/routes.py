from fastapi import APIRouter, HTTPException, Depends, Request, Query
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse
from typing import Optional, List
import json
import csv
import io
import base64
import logging
from datetime import datetime, timedelta
import random

from .auth import verify_user
from .models import LoginRequest, SearchRequest, ExportRequest
from .database import (
    query_database_async, build_search_query,
    SECURITY_COLLECTION, initialize_database_with_data
)
from .config import USERS
from .config import USERS, dashboard_cache
from .utils import (
    get_cache_key, cache_dashboard_data, get_cached_dashboard_data,
    parse_timestamp
)

logger = logging.getLogger(__name__)
router = APIRouter()

async def log_requests(request: Request, call_next):
    start_time = datetime.now()
    response = await call_next(request)
    process_time = (datetime.now() - start_time).total_seconds() * 1000
    if not request.url.path.startswith('/css/') and not request.url.path.startswith('/js/'):
        logger.info(f"{request.method} {request.url.path} - {response.status_code} - {process_time:.2f}ms")
    return response

@router.post("/api/login")
async def login(login_data: LoginRequest):
    """Логин"""
    if login_data.username in USERS and USERS[login_data.username] == login_data.password:
        token = base64.b64encode(f"{login_data.username}:{login_data.password}".encode()).decode()
        return {
            "status": "success",
            "message": "Login successful",
            "token": token,
            "user": login_data.username
        }
    raise HTTPException(status_code=401, detail="Invalid credentials")

@router.post("/api/logout")
async def logout():
    return {"status": "success", "message": "Logged out"}

@router.get("/api/dashboard/agents")
async def get_active_agents(username: str = Depends(verify_user)):
    """Активные агенты"""
    cache_key = get_cache_key("agents")
    cached = get_cached_dashboard_data(cache_key)
    if cached:
        return cached

    query = {}
    response = await query_database_async("find", SECURITY_COLLECTION, query)

    if response.get("status") != "success":
        result = {"status": "error", "data": [], "count": 0}
        cache_dashboard_data(cache_key, result, 10)
        return result

    agents = {}
    for event in response.get("data", []):
        try:
            agent_id = event.get("agent_id", "unknown")
            if agent_id not in agents:
                agents[agent_id] = {
                    "agent_id": agent_id,
                    "hostname": event.get("hostname", "unknown"),
                    "last_activity": event.get("timestamp", ""),
                    "event_count": 0
                }
            agents[agent_id]["event_count"] += 1
            event_time = event.get("timestamp", "")
            last_time = agents[agent_id]["last_activity"]
            if event_time > last_time:
                agents[agent_id]["last_activity"] = event_time
        except Exception as e:
            continue
    agents_list = list(agents.values())
    agents_list.sort(key=lambda x: x["last_activity"] or "", reverse=True)
    result = {
        "status": "success",
        "data": agents_list[:20],
        "count": len(agents_list)
    }
    cache_dashboard_data(cache_key, result, 10)
    return result

@router.get("/api/dashboard/logins")
async def get_recent_logins(username: str = Depends(verify_user)):
    """Последние входы"""
    cache_key = get_cache_key("logins")
    cached = get_cached_dashboard_data(cache_key)
    if cached:
        return cached
    logger.info("Fetching all events to filter login events...")
    query = {}
    response = await query_database_async("find", SECURITY_COLLECTION, query)
    if response.get("status") != "success":
        logger.warning(f"Failed to query events: {response.get('message', 'Unknown error')}")
        result = {"status": "error", "data": [], "count": 0}
        cache_dashboard_data(cache_key, result, 10)
        return result
    all_events = response.get("data", [])
    logger.info(f"Total events in database: {len(all_events)}")
    events = []
    login_keywords = [
        "login", "password", "authenticat", "accepted", "failed password",
        "session opened", "session closed", "ssh", "sudo", "pam"
    ]
    for event in all_events:
        event_type = (event.get("event_type", "") or "").lower()
        raw_log = (event.get("raw_log", "") or "").lower()
        source = (event.get("source", "") or "").lower()
        is_login_event = False
        if any(keyword in event_type for keyword in ["login", "auth"]):
            is_login_event = True
        elif any(keyword in raw_log for keyword in login_keywords):
            is_login_event = True
        elif source in ["auth", "syslog"] and any(keyword in raw_log for keyword in ["login", "password", "accepted", "failed"]):
            is_login_event = True
        if is_login_event:
            events.append(event)
    logger.info(f"Found {len(events)} login events after filtering")
    if len(events) == 0 and len(all_events) > 0:
        logger.info("No login events found. Sample events for debugging:")
        for i, event in enumerate(all_events[:5]):
            logger.info(f"  Event {i+1}: type={event.get('event_type')}, source={event.get('source')}, "
                       f"raw_log_preview={str(event.get('raw_log', ''))[:100]}")
    for event in events:
        event_type = event.get("event_type", "").lower()
        raw_log = event.get("raw_log", "").lower()
        success_keywords = ["successful", "accepted", "succeeded", "authenticated", "success"]
        failure_keywords = ["failed", "failure", "invalid", "denied", "refused", "rejected"]
        is_successful = any(keyword in event_type or keyword in raw_log for keyword in success_keywords)
        is_failed = any(keyword in event_type or keyword in raw_log for keyword in failure_keywords)
        if "failed_login" in event_type or is_failed:
            event["success"] = False
        elif "successful_login" in event_type or is_successful:
            event["success"] = True
        else:
            event["success"] = True
    def get_event_time(event):
        timestamp_str = event.get("timestamp", "")
        if timestamp_str:
            try:
                for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
                    try:
                        return datetime.strptime(timestamp_str, fmt)
                    except ValueError:
                        continue
                return datetime.min
            except:
                return datetime.min
        return datetime.min

    events.sort(key=get_event_time, reverse=True)

    recent_events = events[:20]
    logger.info(f"Returning {len(recent_events)} recent login events (out of {len(events)} total)")
    if recent_events:
        logger.info(f"First event: user={recent_events[0].get('user')}, type={recent_events[0].get('event_type')}, timestamp={recent_events[0].get('timestamp')}")
    result = {
        "status": "success",
        "data": recent_events,
        "count": len(recent_events)
    }
    cache_dashboard_data(cache_key, result, 10)
    return result

@router.get("/api/dashboard/hosts")
async def get_hosts_stats(username: str = Depends(verify_user)):
    """Активные хосты"""
    cache_key = get_cache_key("hosts")
    cached = get_cached_dashboard_data(cache_key)
    if cached:
        return cached
    query = {}
    response = await query_database_async("find", SECURITY_COLLECTION, query)
    if response.get("status") != "success":
        result = {"status": "error", "data": [], "count": 0}
        cache_dashboard_data(cache_key, result, 10)
        return result
    hosts = {}
    for event in response.get("data", []):
        try:
            hostname = event.get("hostname", "unknown")
            if hostname not in hosts:
                hosts[hostname] = {
                    "hostname": hostname,
                    "event_count": 0,
                    "severity_counts": {"low": 0, "medium": 0, "high": 0, "critical": 0},
                    "sources": set()
                }
            hosts[hostname]["event_count"] += 1
            severity = event.get("severity", "low").lower()
            if severity in hosts[hostname]["severity_counts"]:
                hosts[hostname]["severity_counts"][severity] += 1
            hosts[hostname]["sources"].add(event.get("source", "unknown"))
        except Exception as e:
            continue
    result_list = []
    for hostname, data in hosts.items():
        data["sources"] = list(data["sources"])
        result_list.append(data)
    result = {
        "status": "success",
        "data": result_list[:20],
        "count": len(result_list)
    }
    cache_dashboard_data(cache_key, result, 10)
    return result

@router.get("/api/dashboard/events-by-type")
async def get_events_by_type(username: str = Depends(verify_user)):
    """Топ по типу"""
    cache_key = get_cache_key("events_by_type")
    cached = get_cached_dashboard_data(cache_key)
    if cached:
        return cached
    query = {}
    response = await query_database_async("find", SECURITY_COLLECTION, query)
    if response.get("status") != "success":
        result = {"status": "error", "labels": [], "data": []}
        cache_dashboard_data(cache_key, result, 10)
        return result
    type_counts = {}
    for event in response.get("data", []):
        try:
            event_type = event.get("event_type", "unknown")
            if event_type not in type_counts:
                type_counts[event_type] = 0
            type_counts[event_type] += 1
        except:
            continue
    sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
    labels = [item[0] for item in sorted_types]
    data = [item[1] for item in sorted_types]
    result = {
        "status": "success",
        "labels": labels[:10],
        "data": data[:10]
    }
    cache_dashboard_data(cache_key, result, 10)
    return result

@router.get("/api/dashboard/events-by-severity")
async def get_events_by_severity(username: str = Depends(verify_user)):
    """Распределение по критичности"""
    cache_key = get_cache_key("events_by_severity")
    cached = get_cached_dashboard_data(cache_key)
    if cached:
        return cached
    query = {}
    response = await query_database_async("find", SECURITY_COLLECTION, query)

    if response.get("status") != "success":
        total_count_all = response.get("total_count", 0)
        result = {
            "status": "success",
            "labels": ["low", "medium", "high", "critical", "unknown"],
            "data": [0, 0, 0, 0, 0],
            "total_count_24h": total_count_all
        }
        cache_dashboard_data(cache_key, result, 10)
        return result
    from datetime import timezone
    now = datetime.now(timezone.utc)
    time_24h_ago = now - timedelta(hours=24)
    
    filtered_events = []
    for event in response.get("data", []):
        try:
            timestamp_str = event.get("timestamp", "")
            if not timestamp_str:
                continue
            event_time = parse_timestamp(timestamp_str)
            if not event_time:
                continue
            if event_time.tzinfo is None:
                event_time = event_time.replace(tzinfo=timezone.utc)            
            if event_time >= time_24h_ago:
                filtered_events.append(event)
        except Exception as e:
            logger.debug(f"Error filtering event by time: {e}")
            continue
    severity_counts = {
        "low": 0, "medium": 0, "high": 0, "critical": 0, "unknown": 0
    }
    for event in filtered_events:
        try:
            severity = event.get("severity", "unknown").lower()

            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["unknown"] += 1
        except:
            continue
    labels = ["low", "medium", "high", "critical", "unknown"]
    data = [severity_counts[label] for label in labels]
    total_count_all = response.get("total_count")
    if total_count_all is None:
        total_count_all = len(response.get("data", []))
    result = {
        "status": "success",
        "labels": labels,
        "data": data,
        "total_count_24h": total_count_all  
    }
    cache_dashboard_data(cache_key, result, 10)
    return result

@router.get("/api/dashboard/top-users")
async def get_top_users(username: str = Depends(verify_user)):
    """Топ пользователей"""
    cache_key = get_cache_key("top_users")
    cached = get_cached_dashboard_data(cache_key)
    if cached:
        return cached
    query = {}
    response = await query_database_async("find", SECURITY_COLLECTION, query)
    if response.get("status") != "success":
        result = {"status": "error", "data": [], "count": 0}
        cache_dashboard_data(cache_key, result, 10)
        return result
    user_counts = {}
    for event in response.get("data", []):
        try:
            user = event.get("user", "unknown")
            if user != "unknown":
                if user not in user_counts:
                    user_counts[user] = {
                        "user": user,
                        "event_count": 0,
                        "event_types": set()
                    }
                user_counts[user]["event_count"] += 1
                user_counts[user]["event_types"].add(event.get("event_type", "unknown"))
        except:
            continue
    sorted_users = sorted(user_counts.items(), key=lambda x: x[1]["event_count"], reverse=True)
    result_list = []
    for user, data in sorted_users[:10]:
        data["event_types"] = list(data["event_types"])
        result_list.append(data)
    result = {
        "status": "success",
        "data": result_list,
        "count": len(result_list)
    }
    cache_dashboard_data(cache_key, result, 10)
    return result

@router.get("/api/dashboard/top-processes")
async def get_top_processes(username: str = Depends(verify_user)):
    """Топ процессов"""
    cache_key = get_cache_key("top_processes")
    cached = get_cached_dashboard_data(cache_key)
    if cached:
        return cached
    query = {}
    response = await query_database_async("find", SECURITY_COLLECTION, query)
    if response.get("status") != "success":
        result = {"status": "error", "data": [], "count": 0}
        cache_dashboard_data(cache_key, result, 10)
        return result
    process_counts = {}
    for event in response.get("data", []):
        try:
            process = event.get("process", "unknown")
            if process != "unknown":
                if process not in process_counts:
                    process_counts[process] = {
                        "process": process,
                        "event_count": 0,
                        "sources": set()
                    }
                process_counts[process]["event_count"] += 1
                process_counts[process]["sources"].add(event.get("source", "unknown"))
        except:
            continue

    sorted_processes = sorted(process_counts.items(), key=lambda x: x[1]["event_count"], reverse=True)

    result_list = []
    for process, data in sorted_processes[:10]:
        data["sources"] = list(data["sources"])
        result_list.append(data)
    result = {
        "status": "success",
        "data": result_list,
        "count": len(result_list)
    }
    cache_dashboard_data(cache_key, result, 10)
    return result

@router.get("/api/dashboard/events-timeline")
async def get_events_timeline(username: str = Depends(verify_user)):
    """График во времени"""
    cache_key = get_cache_key("events_timeline")
    cached = get_cached_dashboard_data(cache_key)
    if cached:
        return cached
    query = {}
    response = await query_database_async("find", SECURITY_COLLECTION, query)
    if response.get("status") != "success":
        hours = [f"{i:02d}:00" for i in range(24)]
        data = [random.randint(0, 20) for _ in range(24)]
        result = {
            "status": "success",
            "labels": hours,
            "data": data
        }
        cache_dashboard_data(cache_key, result, 10)
        return result
    hours_dict = {}
    all_events = response.get("data", [])
    timestamps = []
    for event in all_events:
        try:
            event_time_str = event.get("timestamp", "")
            if not event_time_str:
                continue
            event_time = parse_timestamp(event_time_str)
            if not event_time:
                continue
            timestamps.append(event_time)
        except:
            continue
    if not timestamps:
        now = datetime.now()
        for i in range(24):
            hour_time = now - timedelta(hours=i)
            hour_key = hour_time.strftime("%Y-%m-%d %H:00")
            hours_dict[hour_key] = 0
    else:
        min_time = min(timestamps)
        max_time = max(timestamps)
        current_time = min_time.replace(minute=0, second=0, microsecond=0)
        while current_time <= max_time:
            hour_key = current_time.strftime("%Y-%m-%d %H:00")
            hours_dict[hour_key] = 0
            current_time += timedelta(hours=1)
    for event in all_events:
        try:
            event_time_str = event.get("timestamp", "")
            if not event_time_str:
                continue
            event_time = parse_timestamp(event_time_str)
            if not event_time:
                continue
            hour_key = event_time.replace(minute=0, second=0, microsecond=0)
            hour_str = hour_key.strftime("%Y-%m-%d %H:00")
            if hour_str in hours_dict:
                hours_dict[hour_str] += 1
        except:
            continue
    sorted_hours = sorted(hours_dict.keys(), reverse=True)
    if len(sorted_hours) > 24:
        sorted_hours = sorted_hours[:24]
    labels = []
    for hour in sorted_hours:
        try:
            hour_time = datetime.strptime(hour, "%Y-%m-%d %H:00")
            labels.append(hour_time.strftime("%H:%M"))
        except:
            labels.append(hour[-5:])
    data = [hours_dict[hour] for hour in sorted_hours]
    result = {
        "status": "success",
        "labels": labels,
        "data": data
    }
    cache_dashboard_data(cache_key, result, 10)
    return result

@router.get("/api/events")
async def get_events(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    search: Optional[str] = None,
    use_regex: bool = Query(False),
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    source: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    username: str = Depends(verify_user)
):
    """С пагинацией"""
    logger.info(f"Events query params: page={page}, limit={limit}, "
                f"search={search}, use_regex={use_regex}, "
                f"severity={severity}, event_type={event_type}, "
                f"source={source}, start_date={start_date}, end_date={end_date}")
    query = build_search_query(
        search_text=search,
        use_regex=use_regex,
        severity=severity,
        event_type=event_type,
        source=source,
        start_date=start_date,
        end_date=end_date
    )
    logger.info(f"Built query: {json.dumps(query, indent=2)}")
    response = await query_database_async("find", SECURITY_COLLECTION, query)
    if response.get("status") != "success":
        return {
            "status": "error",
            "data": [],
            "pagination": {
                "page": page,
                "limit": limit,
                "total": 0,
                "pages": 0
            }
        }
    events = response.get("data", [])
    if start_date and end_date:
        try:
            start_dt = datetime.strptime(start_date, "%Y-%m-%d")
            end_dt = datetime.strptime(end_date, "%Y-%m-%d")
            end_dt = end_dt.replace(hour=23, minute=59, second=59)
            filtered_events = []
            for event in events:
                timestamp_str = event.get("timestamp", "")
                if timestamp_str:
                    try:
                        event_dt = None
                        for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
                            try:
                                event_dt = datetime.strptime(timestamp_str, fmt)
                                break
                            except ValueError:
                                continue
                        if event_dt and start_dt <= event_dt <= end_dt:
                            filtered_events.append(event)
                    except Exception:
                        pass
            events = filtered_events
        except (ValueError, Exception) as e:
            logger.warning(f"Failed to filter events by date range: {e}")
    def get_timestamp(event):
        timestamp_str = event.get("timestamp", "")
        if timestamp_str:
            try:
                from datetime import datetime
                for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
                    try:
                        return datetime.strptime(timestamp_str, fmt)
                    except ValueError:
                        continue
                return datetime.min
            except:
                from datetime import datetime
                return datetime.min
        else:
            from datetime import datetime
            return datetime.min

    events.sort(key=get_timestamp, reverse=True) 
    total_count = len(events)#пагинация
    total_pages = (total_count + limit - 1) 
    start_idx = (page - 1) * limit
    end_idx = min(start_idx + limit, total_count)
    paginated_events = events[start_idx:end_idx]
    return {
        "status": "success",
        "data": paginated_events,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total_count,
            "pages": total_pages,
            "current_page": page,
            "per_page": limit,
            "total_count": total_count
        }
    }

@router.post("/api/events/search")
async def search_events(
    search_request: SearchRequest,
    username: str = Depends(verify_user)
):
    """Поиск событий"""
    return await get_events(
        page=1,
        limit=50,
        search=search_request.search_text,
        severity=search_request.severity[0] if search_request.severity and len(search_request.severity) == 1 else None,
        event_type=search_request.event_type[0] if search_request.event_type and len(search_request.event_type) == 1 else None,
        source=search_request.source[0] if search_request.source and len(search_request.source) == 1 else None,
        start_date=search_request.start_date,
        end_date=search_request.end_date
    )

@router.get("/api/events/{event_id}")
async def get_event_by_id(event_id: str, username: str = Depends(verify_user)):
    """Событие по айди"""
    query = {"_id": event_id}
    response = await query_database_async("find", SECURITY_COLLECTION, query)
    try:
        event = response["data"][0]
        return {"status": "success", "data": event}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to parse event")

@router.post("/api/events/export/json")
async def export_events_json(
    export_request: ExportRequest,
    username: str = Depends(verify_user)
):
    """Сохранение в JSON"""
    query = export_request.query or {}
    response = await query_database_async("find", SECURITY_COLLECTION, query)
    if response.get("status") != "success":
        raise HTTPException(status_code=500, detail="Failed to fetch events")
    events = response.get("data", [])
    json_content = json.dumps(events, indent=2, ensure_ascii=False)
    return StreamingResponse(
        io.StringIO(json_content),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=siem_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        }
    )

@router.post("/api/events/export/csv")
async def export_events_csv(
    export_request: ExportRequest,
    username: str = Depends(verify_user)
):
    """Сохраненией в CSV"""
    query = export_request.query or {}
    response = await query_database_async("find", SECURITY_COLLECTION, query)
    if response.get("status") != "success":
        raise HTTPException(status_code=500, detail="Failed to fetch events")
    events = response.get("data", [])
    output = io.StringIO()#создаем цсв
    if events:
        all_fields = set()
        for event in events:
            all_fields.update(event.keys())
        fieldnames = sorted(all_fields)
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for event in events:
            row = {}
            for field in fieldnames:
                value = event.get(field, "")
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, ensure_ascii=False)
                row[field] = str(value) if value is not None else ""
            writer.writerow(row)
    return StreamingResponse(
        io.StringIO(output.getvalue()),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=siem_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        }
    )

@router.get("/", response_class=HTMLResponse)
async def serve_index():
    return HTMLResponse(content="""
    <html><head><meta http-equiv="refresh" content="0; url=/dashboard"></head>
    <body><p>Redirecting to <a href="/dashboard">dashboard</a>...</p></body></html>
    """)

@router.get("/login", response_class=HTMLResponse)
async def serve_login():
    try:
        with open("frontend/login.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except:
        return HTMLResponse(content="<h1>Login page not found</h1>")

@router.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    try:
        with open("frontend/dashboard.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except:
        return HTMLResponse(content="<h1>Dashboard not found</h1>")

@router.get("/events", response_class=HTMLResponse)
async def serve_events():
    try:
        with open("frontend/events.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except:
        return HTMLResponse(content="<h1>Events page not found</h1>")

@router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@router.post("/api/clear-cache")
async def clear_cache(username: str = Depends(verify_user)):
    global dashboard_cache
    count = len(dashboard_cache)
    dashboard_cache.clear()
    return {"status": "success", "message": f"Cache cleared ({count} items)"}

@router.get("/api/cache-stats")
async def cache_stats(username: str = Depends(verify_user)):
    global dashboard_cache
    return {
        "status": "success",
        "cache_size": len(dashboard_cache),
        "cache_keys": list(dashboard_cache.keys())
    }

@router.get("/api/debug/db-stats")
async def debug_db_stats(username: str = Depends(verify_user)):
    query = {}
    response = await query_database_async("find", SECURITY_COLLECTION, query)

    return {
        "status": "success",
        "total_events": response.get("count", 0),
        "server_time": datetime.now().isoformat()
    }