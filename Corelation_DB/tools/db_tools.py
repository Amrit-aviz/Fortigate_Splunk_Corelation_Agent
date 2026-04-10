from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import os
import re
import json
from datetime import datetime, timezone, timedelta

from ncp import tool as tool_decorator

try:
    import psycopg2
    import psycopg2.extras
except Exception:  # pragma: no cover
    psycopg2 = None  # type: ignore


# ---------------------------
# Config
# ---------------------------

DEFAULTS = {"hours": 24, "limit": 100}

FGT_HOST_DEFAULT = os.getenv("FGT_HOST", "").strip() or None

DEFAULT_DB_HOST = "10.4.4.174"
DEFAULT_DB_PORT = 15434
DEFAULT_DB_NAME = "metrics"
DEFAULT_DB_USER = "postgres"
DEFAULT_DB_SSLMODE = "prefer"
DEFAULT_DB_PASSWORD = "a5d37fcc78249f9802d3a118c45357b2aea23965"


# ---------------------------
# Helpers
# ---------------------------

_INT_RE = re.compile(r"(-?\d+)")
_FLOAT_RE = re.compile(r"(-?\d+(?:\.\d+)?)")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", re.IGNORECASE)

_WINDOW_RE = re.compile(
    r"\b(?:last|past)\s+(?P<n>\d+(?:\.\d+)?)\s*(?P<u>seconds?|secs?|minutes?|mins?|hours?|hrs?|days?)\b",
    re.IGNORECASE,
)

_CFGATTR_PAIR_RE = re.compile(r'(?P<k>[A-Za-z0-9_.-]+)\[(?P<v>[^\]]*)\]')


def _to_int(x: Any, default: int) -> int:
    try:
        if x is None or isinstance(x, bool):
            return default
        if isinstance(x, int):
            return x
        if isinstance(x, float):
            return int(x)
        s = str(x).strip().lower()
        m = _INT_RE.search(s)
        return int(m.group(1)) if m else default
    except Exception:
        return default


def _to_float(x: Any, default: float) -> float:
    try:
        if x is None or isinstance(x, bool):
            return default
        if isinstance(x, (int, float)):
            return float(x)
        s = str(x).strip().lower()
        m = _FLOAT_RE.search(s)
        return float(m.group(1)) if m else default
    except Exception:
        return default


def _clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _since_iso_seconds(seconds: int) -> str:
    return (_now_utc() - timedelta(seconds=seconds)).isoformat()


def _parse_window_seconds(text: str, fallback_seconds: int) -> int:
    if not text:
        return fallback_seconds
    m = _WINDOW_RE.search(text)
    if not m:
        return fallback_seconds

    n = float(m.group("n"))
    u = m.group("u").lower()

    if u.startswith(("sec", "second")):
        sec = int(n)
    elif u.startswith(("min", "minute")):
        sec = int(n * 60)
    elif u.startswith(("hr", "hour")):
        sec = int(n * 3600)
    elif u.startswith("day"):
        sec = int(n * 86400)
    else:
        sec = fallback_seconds

    return _clamp(sec, 1, 30 * 86400)


def _extract_kv(message: str, key: str) -> Optional[str]:
    m = re.search(rf'\b{re.escape(key)}\s*=\s*"([^"]+)"', message)
    if m:
        return m.group(1)
    m = re.search(rf"\b{re.escape(key)}\s*=\s*([^\s]+)", message)
    return m.group(1) if m else None


def _shorten(msg: str, max_len: int = 220) -> str:
    msg = (msg or "").strip()
    return msg if len(msg) <= max_len else msg[: max_len - 3] + "..."


def _parse_cfgattr(cfgattr: str) -> List[Dict[str, Optional[str]]]:
    out: List[Dict[str, Optional[str]]] = []
    if not cfgattr:
        return out

    for m in _CFGATTR_PAIR_RE.finditer(cfgattr):
        k = m.group("k")
        v = m.group("v")

        old: Optional[str] = None
        new: Optional[str] = None

        if "->" in v:
            parts = v.split("->", 1)
            old = parts[0] if parts[0] != "" else None
            new = parts[1] if parts[1] != "" else None
        else:
            old = v
            new = None

        out.append({"field": k, "old": old, "new": new})

    return out


def _rows_to_jsonable(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    parsed_fields = [
        "user", "ui", "srcip", "dstip", "action", "status", "policyid",
        "logdesc", "type", "subtype", "cfgpath", "cfgobj", "cfgattr"
    ]
    _ = parsed_fields

    for r in rows:
        rr = dict(r)

        for k in ("ts", "event_time", "created_at", "updated_at"):
            v = rr.get(k)
            if isinstance(v, datetime):
                rr[k] = v.isoformat()

        msg = rr.get("message")
        if isinstance(msg, str) and msg.strip():
            parsed = {
                "user": _extract_kv(msg, "user"),
                "ui": _extract_kv(msg, "ui"),
                "srcip": _extract_kv(msg, "srcip"),
                "dstip": _extract_kv(msg, "dstip"),
                "action": _extract_kv(msg, "action"),
                "status": _extract_kv(msg, "status"),
                "policyid": _extract_kv(msg, "policyid"),
                "logdesc": _extract_kv(msg, "logdesc"),
                "type": _extract_kv(msg, "type"),
                "subtype": _extract_kv(msg, "subtype"),
                "cfgpath": _extract_kv(msg, "cfgpath"),
                "cfgobj": _extract_kv(msg, "cfgobj"),
                "cfgattr": _extract_kv(msg, "cfgattr"),
            }

            for k, v in parsed.items():
                if rr.get(k) is None and v is not None:
                    rr[k] = v

        out.append(rr)

    return out


def _count_placeholders(sql: str) -> int:
    return len(re.findall(r"(?<!%)%s", sql))


# ---------------------------
# DB
# ---------------------------

@dataclass
class DBConfig:
    host: str
    port: int
    name: str
    user: str
    password: str
    sslmode: str = "prefer"


def _get_db_config() -> DBConfig:
    host = (os.getenv("SYSLOG_DB_HOST") or "").strip() or DEFAULT_DB_HOST
    port_s = (os.getenv("SYSLOG_DB_PORT") or "").strip()
    name = (os.getenv("SYSLOG_DB_NAME") or "").strip() or DEFAULT_DB_NAME
    user = (os.getenv("SYSLOG_DB_USER") or "").strip() or DEFAULT_DB_USER
    password = (os.getenv("SYSLOG_DB_PASSWORD") or "").strip() or DEFAULT_DB_PASSWORD
    sslmode = (os.getenv("SYSLOG_DB_SSLMODE") or "").strip() or DEFAULT_DB_SSLMODE

    port = DEFAULT_DB_PORT
    if port_s:
        port = int(port_s)

    if not host:
        raise RuntimeError("DB host is empty. Set SYSLOG_DB_HOST or update DEFAULT_DB_HOST.")
    if not password:
        raise RuntimeError("DB password is empty. Set SYSLOG_DB_PASSWORD or update DEFAULT_DB_PASSWORD.")
    return DBConfig(host=host, port=port, name=name, user=user, password=password, sslmode=sslmode)


def _connect():
    if psycopg2 is None:
        raise RuntimeError("psycopg2 is not installed. Add 'psycopg2-binary' to requirements.txt and redeploy.")
    cfg = _get_db_config()
    return psycopg2.connect(
        host=cfg.host,
        port=cfg.port,
        dbname=cfg.name,
        user=cfg.user,
        password=cfg.password,
        sslmode=cfg.sslmode,
        connect_timeout=5,
    )


# ---------------------------
# Internal callable impls
# ---------------------------

def _execute_sql_impl(sql: str, params: List[Any], limit: int) -> Dict[str, Any]:
    limit_i = _clamp(_to_int(limit, 100), 1, 500)
    conn = _connect()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            rows = cur.fetchmany(size=limit_i)
            return {
                "sql": sql,
                "params": params,
                "row_count": len(rows),
                "rows": _rows_to_jsonable(list(rows)),
            }
    finally:
        conn.close()


def _execute_sql_count_impl(sql: str, params: List[Any]) -> Dict[str, Any]:
    conn = _connect()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            val = cur.fetchone()[0]
            return {"sql": sql, "params": params, "count": int(val)}
    finally:
        conn.close()


# ---------------------------
# Tool: execute_sql_query
# ---------------------------

@tool_decorator
def execute_sql_query(sql: str, params_json: str = "[]", limit: int = 100) -> Dict[str, Any]:
    """Execute a SQL query against the Postgres DB. Use %s placeholders and params_json array."""
    limit_i = _clamp(_to_int(limit, 100), 1, 500)
    try:
        params = json.loads(params_json or "[]")
    except Exception as e:
        raise RuntimeError(f"params_json must be valid JSON array, got: {params_json!r}. Error: {e}")
    if not isinstance(params, list):
        raise RuntimeError("params_json must be a JSON array, e.g. [] or [\"10.0.0.1\"].")

    need = _count_placeholders(sql)
    if need > len(params):
        raise RuntimeError(
            f"SQL expects {need} parameter(s) (%s placeholders), but params_json has {len(params)}."
        )

    return _execute_sql_impl(sql, params, limit_i)


def _base_where(host: Optional[str]) -> Tuple[str, List[Any]]:
    params: List[Any] = []
    if not host:
        return "TRUE", params

    where = "(host = %s OR message ILIKE %s)"
    params.append(host)
    params.append(f"%{host}%")
    return where, params


def _query_syslog_events(
    match_all: List[str],
    match_any: List[str],
    seconds: int,
    limit: Any,
    host: Optional[str],
) -> Dict[str, Any]:
    limit_i = _clamp(_to_int(limit, 100), 1, 200)
    seconds_i = _clamp(_to_int(seconds, 3600), 1, 30 * 86400)

    base_where, base_params = _base_where(host or FGT_HOST_DEFAULT)

    clauses = [f"ts >= %s::timestamptz", f"({base_where})"]
    params: List[Any] = [_since_iso_seconds(seconds_i)] + base_params

    for pat in match_all:
        clauses.append("message ILIKE %s")
        params.append(pat)

    if match_any:
        any_sql = " OR ".join(["message ILIKE %s"] * len(match_any))
        clauses.append(f"({any_sql})")
        params.extend(match_any)

    where_sql = " AND ".join(clauses)

    sql = f"""
SELECT id, host, hostname, program, severity, syslog_pri, event_time, message, ts
FROM syslog_events
WHERE {where_sql}
ORDER BY ts DESC
LIMIT %s
""".strip()

    params.append(limit_i)
    return _execute_sql_impl(sql, params, limit_i)


# ---------------------------
# Correlation helper
# ---------------------------

def _traffic_impact_for_policy(policy_id: str, change_ts: Any, window_minutes: int, host: Optional[str]) -> Dict[str, Any]:
    if isinstance(change_ts, str):
        t0 = datetime.fromisoformat(change_ts.replace("Z", "+00:00"))
    elif isinstance(change_ts, datetime):
        t0 = change_ts
    else:
        return {"note": "unrecognized timestamp format"}

    win_m = _clamp(_to_int(window_minutes, 30), 1, 24 * 60)
    w = timedelta(minutes=win_m)

    before_start = (t0 - w).isoformat()
    before_end = t0.isoformat()
    after_start = t0.isoformat()
    after_end = (t0 + w).isoformat()

    base_where, base_params = _base_where(host or FGT_HOST_DEFAULT)

    def _count_between(start_iso: str, end_iso: str, action: Optional[str]) -> int:
        clauses = [
            "ts >= %s::timestamptz",
            "ts < %s::timestamptz",
            f"({base_where})",
            "message ILIKE %s",
            "message ILIKE %s",
        ]
        params: List[Any] = [start_iso, end_iso] + base_params
        params.append('%type="traffic"%')
        params.append(f"%policyid={policy_id}%")

        if action:
            clauses.append("message ILIKE %s")
            params.append(f'%action="{action}"%')

        sql = "SELECT COUNT(*) FROM syslog_events WHERE " + " AND ".join(clauses)
        return _execute_sql_count_impl(sql, params)["count"]

    before_accept = _count_between(before_start, before_end, "accept")
    before_deny = _count_between(before_start, before_end, "deny")
    after_accept = _count_between(after_start, after_end, "accept")
    after_deny = _count_between(after_start, after_end, "deny")

    return {
        "window_minutes": win_m,
        "before": {"accept": before_accept, "deny": before_deny},
        "after": {"accept": after_accept, "deny": after_deny},
        "note": "Best-effort correlation; requires traffic logs containing policyid=<n>.",
    }


# ---------------------------
# Policy inventory impl + tool
# ---------------------------

def _list_firewall_policies_impl(
    device_ip: Optional[str] = None,
    limit: Any = 200,
    include_disabled: bool = True,
    order_by: str = "name",
    action_filter: Optional[str] = None,
) -> Dict[str, Any]:
    ip = (device_ip or "").strip() or (FGT_HOST_DEFAULT or "")

    limit_i = _clamp(_to_int(limit, 200), 1, 500)

    ob = (order_by or "name").strip().lower()
    if ob not in ("name", "updated_at", "created_at"):
        ob = "name"

    where_parts: List[str] = ["TRUE"]
    params: List[Any] = []

    if ip:
        where_parts.append("device_ip = %s")
        params.append(ip)

    if not include_disabled:
        where_parts.append("disabled = false")

    if action_filter and str(action_filter).strip():
        where_parts.append("LOWER(action) = LOWER(%s)")
        params.append(str(action_filter).strip())

    where_sql = " AND ".join(where_parts)

    sql = f"""
SELECT
  uuid,
  device_ip,
  name,
  action,
  from_zone,
  to_zone,
  source,
  destination,
  application,
  category,
  service,
  log_start,
  log_end,
  disabled,
  rule_type,
  created_at,
  updated_at
FROM public.firewall_security_policies
WHERE {where_sql}
ORDER BY {ob} ASC
LIMIT %s
""".strip()

    params.append(limit_i)
    return _execute_sql_impl(sql, params, limit_i)


@tool_decorator
def list_firewall_policies(
    device_ip: Optional[str] = None,
    limit: int = 200,
    include_disabled: bool = True,
    order_by: str = "name",
    action_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Authoritative policy inventory from public.firewall_security_policies.

    Supports filtering by device_ip and action_filter.
    """
    return _list_firewall_policies_impl(
        device_ip=device_ip,
        limit=limit,
        include_disabled=include_disabled,
        order_by=order_by,
        action_filter=action_filter,
    )


# ---------------------------
# Login activity impl + tool
# ---------------------------

def _login_activity_impl(
    hours: Any = 24,
    limit: int = 100,
    host: Optional[str] = None,
    result: str = "all",
    username: Optional[str] = None,
    srcip: Optional[str] = None,
    aggregate: str = "rows",
) -> Dict[str, Any]:
    seconds = _clamp(int(_to_float(hours, 24.0) * 3600), 1, 30 * 86400)

    match_all = ['%action="login"%', '%type="event"%']
    match_any: List[str] = []

    r = (result or "all").strip().lower()
    if r == "failed":
        match_all.append('%logdesc="Admin login failed"%')
    elif r == "success":
        match_all.append('%logdesc="Admin login successful"%')
    else:
        match_any = ['%logdesc="Admin login failed"%', '%logdesc="Admin login successful"%', '%Admin login%']

    if username:
        match_all.append(f'%user="{username}"%')
    if srcip:
        match_all.append(f"%srcip={srcip}%")

    if (aggregate or "rows").lower() == "count":
        base_where, base_params = _base_where(host or FGT_HOST_DEFAULT)

        clauses = [f"ts >= %s::timestamptz", f"({base_where})"]
        params: List[Any] = [_since_iso_seconds(seconds)] + base_params

        for pat in match_all:
            clauses.append("message ILIKE %s")
            params.append(pat)

        if match_any:
            any_sql = " OR ".join(["message ILIKE %s"] * len(match_any))
            clauses.append(f"({any_sql})")
            params.extend(match_any)

        where_sql = " AND ".join(clauses)
        sql = f"SELECT COUNT(*) FROM syslog_events WHERE {where_sql}"
        return _execute_sql_count_impl(sql, params)

    return _query_syslog_events(match_all=match_all, match_any=match_any, seconds=seconds, limit=limit, host=host)


@tool_decorator
def login_activity(
    hours: Any = 24,
    limit: int = 100,
    host: Optional[str] = None,
    result: str = "all",
    username: Optional[str] = None,
    srcip: Optional[str] = None,
    aggregate: str = "rows",
) -> Dict[str, Any]:
    """
    Query FortiGate admin login activity from the syslog_events table.

    Filters:
      - hours: lookback window (1s to 30 days)
      - result: all|failed|success
      - username: match user="<name>"
      - srcip: match srcip=<ip>
      - host: optionally restrict by FortiGate host/devname
      - aggregate: rows returns matching events; count returns total count
    """
    return _login_activity_impl(
        hours=hours,
        limit=limit,
        host=host,
        result=result,
        username=username,
        srcip=srcip,
        aggregate=aggregate,
    )


# ---------------------------
# Denied traffic impl + tool
# ---------------------------

def _denied_traffic_impl(
    hours: Any = 24,
    limit: int = 100,
    host: Optional[str] = None,
    srcip: Optional[str] = None,
    dstip: Optional[str] = None,
    aggregate: str = "rows",
) -> Dict[str, Any]:
    seconds = _clamp(int(_to_float(hours, 24.0) * 3600), 1, 30 * 86400)

    match_all = ['%type="traffic"%', '%action="deny"%']
    if srcip:
        match_all.append(f"%srcip={srcip}%")
    if dstip:
        match_all.append(f"%dstip={dstip}%")

    if (aggregate or "rows").lower() == "count":
        base_where, base_params = _base_where(host or FGT_HOST_DEFAULT)
        clauses = [f"ts >= %s::timestamptz", f"({base_where})"]
        params: List[Any] = [_since_iso_seconds(seconds)] + base_params

        for pat in match_all:
            clauses.append("message ILIKE %s")
            params.append(pat)

        where_sql = " AND ".join(clauses)
        sql = f"SELECT COUNT(*) FROM syslog_events WHERE {where_sql}"
        return _execute_sql_count_impl(sql, params)

    return _query_syslog_events(
        match_all=match_all,
        match_any=[],
        seconds=seconds,
        limit=limit,
        host=host
    )


@tool_decorator
def denied_traffic(
    hours: Any = 24,
    limit: int = 100,
    host: Optional[str] = None,
    srcip: Optional[str] = None,
    dstip: Optional[str] = None,
    aggregate: str = "rows",
) -> Dict[str, Any]:
    """
    Query denied traffic events from FortiGate traffic logs.

    Filters:
      - hours: lookback window (1s to 30 days)
      - srcip: source IP address
      - dstip: destination IP address
      - host: optionally restrict by FortiGate host/devname
      - aggregate: rows returns matching events; count returns total count
    """
    return _denied_traffic_impl(
        hours=hours,
        limit=limit,
        host=host,
        srcip=srcip,
        dstip=dstip,
        aggregate=aggregate,
    )


# ---------------------------
# Accepted traffic impl + tool
# ---------------------------

def _accepted_traffic_impl(
    hours: Any = 24,
    limit: int = 100,
    host: Optional[str] = None,
    srcip: Optional[str] = None,
    dstip: Optional[str] = None,
    service: Optional[str] = None,
    aggregate: str = "rows",
) -> Dict[str, Any]:
    seconds = _clamp(int(_to_float(hours, 24.0) * 3600), 1, 30 * 86400)

    match_all = ['%type="traffic"%', '%action="accept"%']
    if srcip:
        match_all.append(f"%srcip={srcip}%")
    if dstip:
        match_all.append(f"%dstip={dstip}%")
    if service:
        match_all.append(f'%service="{service}"%')

    if (aggregate or "rows").lower() == "count":
        base_where, base_params = _base_where(host or FGT_HOST_DEFAULT)
        clauses = [f"ts >= %s::timestamptz", f"({base_where})"]
        params: List[Any] = [_since_iso_seconds(seconds)] + base_params

        for pat in match_all:
            clauses.append("message ILIKE %s")
            params.append(pat)

        where_sql = " AND ".join(clauses)
        sql = f"SELECT COUNT(*) FROM syslog_events WHERE {where_sql}"
        return _execute_sql_count_impl(sql, params)

    return _query_syslog_events(
        match_all=match_all,
        match_any=[],
        seconds=seconds,
        limit=limit,
        host=host
    )


@tool_decorator
def accepted_traffic(
    hours: Any = 24,
    limit: int = 100,
    host: Optional[str] = None,
    srcip: Optional[str] = None,
    dstip: Optional[str] = None,
    service: Optional[str] = None,
    aggregate: str = "rows",
) -> Dict[str, Any]:
    """
    Query accepted/allowed traffic events from FortiGate traffic logs.

    Use this to check what traffic IS being permitted through the firewall.
    Helpful for verifying connectivity, confirming policy effectiveness,
    or comparing against denied traffic.

    Filters:
      - hours: lookback window (1s to 30 days)
      - srcip: source IP address
      - dstip: destination IP address
      - service: service name (e.g. "DNS", "HTTP", "NTP", "DHCP")
      - host: optionally restrict by FortiGate host/devname
      - aggregate: rows returns matching events; count returns total count
    """
    return _accepted_traffic_impl(
        hours=hours,
        limit=limit,
        host=host,
        srcip=srcip,
        dstip=dstip,
        service=service,
        aggregate=aggregate,
    )


# ---------------------------
# Config change impl + tool
# ---------------------------

def _config_change_activity_impl(
    question: str = "",
    hours: Any = 24,
    limit: int = 50,
    host: Optional[str] = None,
) -> Dict[str, Any]:
    q = (question or "").strip()
    fallback_seconds = _clamp(int(_to_float(hours, 24.0) * 3600), 1, 30 * 86400)
    seconds = _parse_window_seconds(q, fallback_seconds)

    match_all = ['%type="event"%']
    match_any = [
        '%logdesc="Object attribute configured"%',
        '%logdesc="Attribute configured"%',
        "%cfgpath=%",
        "%cfgattr=%",
    ]

    tokens = [t for t in re.split(r"[^A-Za-z0-9._-]+", q) if len(t) >= 4]
    for t in tokens[:5]:
        match_any.append(f"%{t}%")

    raw = _query_syslog_events(match_all=match_all, match_any=match_any, seconds=seconds, limit=limit, host=host)

    summaries: List[Dict[str, Any]] = []
    for r in raw.get("rows", []) or []:
        msg = r.get("message") or ""
        user = r.get("user") or _extract_kv(msg, "user")
        ui = r.get("ui") or _extract_kv(msg, "ui")
        cfgpath = r.get("cfgpath") or _extract_kv(msg, "cfgpath")
        cfgobj = r.get("cfgobj") or _extract_kv(msg, "cfgobj")
        cfgattr = r.get("cfgattr") or _extract_kv(msg, "cfgattr")

        changes = _parse_cfgattr(cfgattr or "")

        summaries.append({
            "ts": r.get("ts"),
            "user": user,
            "ui": ui,
            "cfgpath": cfgpath,
            "cfgobj": cfgobj,
            "changes": changes,
            "message_snippet": _shorten(msg, 260),
        })

    return {
        "kind": "config_changes",
        "time_window_seconds": seconds,
        "matched_rows": len(summaries),
        "items": summaries,
        "raw": {"sql": raw.get("sql"), "row_count": raw.get("row_count")},
    }


@tool_decorator
def config_change_activity(
    question: str = "",
    hours: Any = 24,
    limit: int = 50,
    host: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Summarize FortiGate configuration change events.

    Searches syslog_events for configuration-change patterns (cfgpath/cfgattr/logdesc)
    and returns a parsed list with user, UI, object path, and changed attributes.
    """
    return _config_change_activity_impl(
        question=question,
        hours=hours,
        limit=limit,
        host=host
    )


# ---------------------------
# Policy change + impact impl + tool
# ---------------------------

def _policy_config_changes_with_traffic_impact_impl(
    question: str = "",
    hours: Any = 24,
    limit: int = 25,
    host: Optional[str] = None,
    impact_window_minutes: int = 30,
) -> Dict[str, Any]:
    q = (question or "").strip()
    fallback_seconds = _clamp(int(_to_float(hours, 24.0) * 3600), 1, 30 * 86400)
    seconds = _parse_window_seconds(q, fallback_seconds)

    match_all = ['%type="event"%', '%cfgpath="firewall.policy"%']
    match_any = ['%logdesc="Object attribute configured"%', '%logdesc="Attribute configured"%', '%cfgattr=%']

    raw = _query_syslog_events(match_all=match_all, match_any=match_any, seconds=seconds, limit=limit, host=host)

    changes_out: List[Dict[str, Any]] = []
    for r in raw.get("rows", []) or []:
        msg = r.get("message") or ""
        ts = r.get("ts")
        user = r.get("user") or _extract_kv(msg, "user")
        ui = r.get("ui") or _extract_kv(msg, "ui")
        cfgobj = r.get("cfgobj") or _extract_kv(msg, "cfgobj")
        cfgattr = r.get("cfgattr") or _extract_kv(msg, "cfgattr")

        parsed_changes = _parse_cfgattr(cfgattr or "")

        policy_id = None
        if cfgobj:
            mm = re.search(r"\b(\d+)\b", str(cfgobj))
            if mm:
                policy_id = mm.group(1)

        impact = None
        if policy_id and ts:
            impact = _traffic_impact_for_policy(
                policy_id=str(policy_id),
                change_ts=ts,
                window_minutes=impact_window_minutes,
                host=host,
            )

        changes_out.append({
            "ts": ts,
            "user": user,
            "ui": ui,
            "policy_id": policy_id,
            "cfgobj": cfgobj,
            "changes": parsed_changes,
            "traffic_impact": impact,
            "message_snippet": _shorten(msg, 260),
        })

    return {
        "kind": "firewall_policy_config_changes_with_impact",
        "time_window_seconds": seconds,
        "matched_rows": len(changes_out),
        "items": changes_out,
        "raw": {"sql": raw.get("sql"), "row_count": raw.get("row_count")},
    }


@tool_decorator
def policy_config_changes_with_traffic_impact(
    question: str = "",
    hours: Any = 24,
    limit: int = 25,
    host: Optional[str] = None,
    impact_window_minutes: int = 30,
) -> Dict[str, Any]:
    """
    Find firewall policy configuration changes and estimate traffic impact around each change.

    Looks for cfgpath="firewall.policy" events and (when possible) correlates with traffic logs
    containing policyid=<n> to compare accept/deny counts before vs after the change.
    """
    return _policy_config_changes_with_traffic_impact_impl(
        question=question,
        hours=hours,
        limit=limit,
        host=host,
        impact_window_minutes=impact_window_minutes,
    )


# ---------------------------
# dynamic_db_search (fixed: calls _impl functions instead of decorated Tool objects)
# ---------------------------

@tool_decorator
def dynamic_db_search(
    question: str,
    hours: Any = 24,
    limit: int = 50,
    host: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Smart router over Postgres-backed FortiGate data.

    Routes the question to:
      - accepted traffic (syslog_events)
      - denied traffic (syslog_events)
      - policy inventory (public.firewall_security_policies)
      - policy config changes with traffic impact (syslog_events)
      - generic config changes (syslog_events)
      - fallback keyword search over syslog_events
    """
    q = (question or "").strip()
    ql = q.lower()

    ip_from_q = None
    m = IP_RE.search(q)
    if m:
        ip_from_q = m.group(1)
    resolved_device_ip = host or ip_from_q or FGT_HOST_DEFAULT

    list_intent = any(k in ql for k in ["list", "show", "display", "give", "print", "all"])
    policy_words = any(k in ql for k in ["policy", "policies", "firewall policy", "security policy", "rules", "rule"])
    change_words = any(k in ql for k in ["config", "configuration", "change", "changed", "rename", "modified", "edit", "updated"])
    accept_words = any(k in ql for k in [
        "accept", "accepted", "allow", "allowed", "permit", "permitted",
        "pass", "passing",
    ])
    deny_words = any(k in ql for k in [
        "deny", "denied", "block", "blocked", "drop", "dropped",
        "reject", "rejected", "can't access", "cannot access",
        "unable to access", "no access",
    ])

    def _extract_traffic_ips(text: str) -> Tuple[Optional[str], Optional[str]]:
        ips = IP_RE.findall(text)
        srcip_q = None
        dstip_q = None
        if len(ips) >= 2:
            srcip_q = ips[0]
            dstip_q = ips[1]
        elif len(ips) == 1:
            srcip_q = ips[0]
        return srcip_q, dstip_q

    # --- Accepted traffic --- (calls _impl, not the decorated tool)
    if accept_words and not deny_words and not change_words and not policy_words:
        srcip_q, dstip_q = _extract_traffic_ips(q)
        return _accepted_traffic_impl(
            hours=hours,
            limit=_clamp(_to_int(limit, 100), 1, 200),
            host=resolved_device_ip if not srcip_q else None,
            srcip=srcip_q,
            dstip=dstip_q,
        )

    # --- Denied traffic --- (calls _impl, not the decorated tool)
    if deny_words and not change_words:
        srcip_q, dstip_q = _extract_traffic_ips(q)
        return _denied_traffic_impl(
            hours=hours,
            limit=_clamp(_to_int(limit, 100), 1, 200),
            host=resolved_device_ip if not srcip_q else None,
            srcip=srcip_q,
            dstip=dstip_q,
        )

    # --- Policy action filter (from policy table) --- (calls _impl, not the decorated tool)
    wants_accept_deny = ("action" in ql) and any(x in ql for x in ["accept", "deny"])
    if wants_accept_deny and not change_words:
        af = "accept" if "accept" in ql else "deny"
        return _list_firewall_policies_impl(
            device_ip=resolved_device_ip,
            limit=_clamp(_to_int(limit, 200), 1, 500),
            include_disabled=True,
            order_by="name",
            action_filter=af,
        )

    # --- Policy inventory ---
    if policy_words and (list_intent or "available" in ql or "inventory" in ql) and not change_words:
        return _list_firewall_policies_impl(
            device_ip=resolved_device_ip,
            limit=_clamp(_to_int(limit, 200), 1, 500),
            include_disabled=True,
            order_by="name",
        )

    # --- Policy config changes ---
    if policy_words and change_words:
        return _policy_config_changes_with_traffic_impact_impl(
            question=q,
            hours=hours,
            limit=min(_to_int(limit, 25), 25),
            host=resolved_device_ip,
            impact_window_minutes=30,
        )

    # --- General config changes ---
    if any(k in ql for k in ["cfgpath", "cfgattr", "configuration", "config change", "config changes", "attribute configured"]):
        return _config_change_activity_impl(
            question=q,
            hours=hours,
            limit=min(_to_int(limit, 50), 50),
            host=resolved_device_ip,
        )

    # --- Fallback keyword search ---
    fallback_seconds = _clamp(int(_to_float(hours, 24.0) * 3600), 1, 30 * 86400)
    seconds = _parse_window_seconds(q, fallback_seconds)

    tokens = [t for t in re.split(r"[^A-Za-z0-9._-]+", q) if len(t) >= 4][:6]
    match_any = [f"%{t}%" for t in tokens] or ["%"]

    data = _query_syslog_events(match_all=[], match_any=match_any, seconds=seconds, limit=limit, host=resolved_device_ip)
    data["kind"] = "syslog_events"
    data["summary"] = {"matched_rows": len(data.get("rows", []) or []), "time_window_seconds": seconds}
    return data