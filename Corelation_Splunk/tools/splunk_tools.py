from ncp import tool
from typing import Dict, Any, Optional
import os

# ============================================================
# SPLUNK METADATA (MATCHES YOUR REAL DATA)
# ============================================================

SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "syslog")
SPLUNK_SOURCETYPE = os.getenv("SPLUNK_SOURCETYPE", "syslog")
SPLUNK_SOURCE = os.getenv("SPLUNK_SOURCE", "udp:5514")
FGT_HOST = os.getenv("FGT_HOST", "10.20.11.29")

DEFAULT_LIMIT = 100


# ============================================================
# HELPERS
# ============================================================

def base_scope(include_source: bool = True) -> str:
    parts = [
        f'index="{SPLUNK_INDEX}"',
        f'sourcetype="{SPLUNK_SOURCETYPE}"',
        f'host="{FGT_HOST}"',
    ]
    if include_source:
        parts.append(f'source="{SPLUNK_SOURCE}"')
    return " ".join(parts)


def time_range_hours(hours: int) -> str:
    return f'earliest=-{int(hours)}h'


def time_range_minutes(minutes: int) -> str:
    return f'earliest=-{int(minutes)}m'


# ============================================================
# DISCOVERY
# ============================================================

@tool
def show_recent_fortigate_logs(limit: int = 20) -> Dict[str, Any]:
    """
    Show recent FortiGate syslog events to understand what data
    is currently being ingested into Splunk.
    """
    scope = base_scope()
    spl_query = (
        f'{scope} earliest=-1h '
        '| table _time type subtype action user srcip dstip dstport service policyid status logid logdesc msg '
        '| sort -_time '
        f'| head {int(limit)}'
    )
    return {"action": "execute_spl", "spl_query": spl_query}


# ============================================================
# AUTHENTICATION EVENTS
# ============================================================

@tool
def search_fortigate_login_failures(
    username: Optional[str] = None,
    hours: int = 24
) -> Dict[str, Any]:
    """
    Find failed FortiGate administrative login attempts.
    """
    scope = base_scope()
    filters = [
        'type="event"',
        'subtype="system"',
        'action="login"',
        'status="failed"',
    ]
    if username:
        filters.append(f'user="{username}"')

    spl_query = (
        f'{scope} ' + " ".join(filters) + f' {time_range_hours(hours)} '
        '| table _time user srcip ui reason method status logid logdesc msg '
        '| sort -_time '
        f'| head {DEFAULT_LIMIT}'
    )
    return {"action": "execute_spl", "spl_query": spl_query}


@tool
def search_fortigate_successful_logins(
    minutes: Optional[int] = None,
    hours: int = 24
) -> Dict[str, Any]:
    """
    Find successful FortiGate administrative login events.

    - If minutes is provided, uses earliest=-{minutes}m
    - Otherwise uses earliest=-{hours}h
    """
    scope = base_scope()
    earliest = (
        time_range_minutes(minutes)
        if minutes is not None
        else time_range_hours(hours)
    )

    spl_query = (
        f'{scope} '
        'type="event" subtype="system" action="login" status="success" '
        f'{earliest} '
        '| table _time user srcip ui status logid logdesc msg '
        '| sort -_time '
        f'| head {DEFAULT_LIMIT}'
    )
    return {"action": "execute_spl", "spl_query": spl_query}


# ============================================================
# USERNAME TO IP RESOLUTION  <-- NEW
# ============================================================

@tool
def resolve_username_to_ip(username: str, hours: int = 24) -> Dict[str, Any]:
    """
    Find the most recent source IP used by a given username
    from FortiGate login events. Use this FIRST when the operator
    provides a username instead of an IP address. Returns one row
    per username with their most recent IP (last_ip) and last seen
    time (last_seen).
    """
    scope = base_scope()
    spl_query = (
        f'{scope} type="event" subtype="system" action="login" '
        f'user="{username}" {time_range_hours(hours)} '
        '| stats latest(_time) as last_seen latest(srcip) as last_ip by user '
        '| table user last_ip last_seen'
    )
    return {"action": "execute_spl", "spl_query": spl_query}


# ============================================================
# CONFIGURATION CHANGES (BEST EFFORT)
# ============================================================

@tool
def search_fortigate_config_changes(hours: int = 24) -> Dict[str, Any]:
    """
    Search for FortiGate configuration change events.
    Returns empty results if config-change logging is not enabled.
    """
    scope = base_scope()
    spl_query = (
        f'{scope} type="event" subtype="system" {time_range_hours(hours)} '
        '(logdesc="*config*" OR logdesc="*change*" OR logdesc="*configured*" '
        'OR msg="*config*" OR msg="*change*" OR msg="*configured*" OR msg="*modified*" OR msg="*edited*") '
        '| table _time user ui logid logdesc cfgpath cfgobj cfgattr msg '
        '| sort -_time '
        f'| head {DEFAULT_LIMIT}'
    )
    return {"action": "execute_spl", "spl_query": spl_query}


# ============================================================
# TRAFFIC / DENY ANALYSIS
# ============================================================

@tool
def search_fortigate_denied_traffic(
    source_ip: Optional[str] = None,
    hours: int = 24
) -> Dict[str, Any]:
    """
    Find traffic denied by FortiGate firewall policies.
    """
    scope = base_scope()
    filters = ['type="traffic"', 'action="deny"']
    if source_ip:
        filters.append(f'srcip="{source_ip}"')

    spl_query = (
        f'{scope} ' + " ".join(filters) + f' {time_range_hours(hours)} '
        '| table _time srcip dstip dstport service proto action policyid logid msg '
        '| sort -_time '
        f'| head {DEFAULT_LIMIT}'
    )
    return {"action": "execute_spl", "spl_query": spl_query}


@tool
def troubleshoot_internet_access(
    source_ip: Optional[str] = None,
    hours: int = 24
) -> Dict[str, Any]:
    """
    Analyze denied internet traffic and determine whether
    the block is due to an implicit or explicit policy.
    """
    scope = base_scope()
    filters = [
        'type="traffic"',
        'action="deny"',
        'NOT (dstip="10.*" OR dstip="192.168.*" OR dstip="172.16.*")',
    ]
    if source_ip:
        filters.append(f'srcip="{source_ip}"')

    spl_query = (
        f'{scope} ' + " ".join(filters) + f' {time_range_hours(hours)} '
        '| eval deny_type=if(policyid=0,"Implicit deny","Explicit policy deny") '
        '| table _time srcip dstip dstport service policyid deny_type msg '
        '| sort -_time '
        f'| head {DEFAULT_LIMIT}'
    )
    return {"action": "execute_spl", "spl_query": spl_query}


# ============================================================
# CURRENT STATE TOOLS (BEST EFFORT)
# ============================================================

@tool
def list_firewall_policies(action_filter: Optional[str] = None) -> Dict[str, Any]:
    """
    Best-effort listing of firewall policies.
    Returns empty results if policy/config data is not indexed in syslog.
    """
    scope = base_scope(include_source=False)
    extra = ""
    if action_filter:
        extra = f' action="{action_filter.lower()}"'

    spl_query = (
        f'{scope}{extra} (path="firewall.policy*" OR "firewall.policy" OR policyid>0) '
        '| table name policyid srcintf dstintf srcaddr dstaddr service action status '
        '| dedup policyid '
        '| sort policyid '
        f'| head {DEFAULT_LIMIT}'
    )
    return {"action": "execute_spl", "spl_query": spl_query}


@tool
def list_address_objects() -> Dict[str, Any]:
    """
    Best-effort listing of address objects.
    Returns empty results if config data is not indexed.
    """
    scope = base_scope(include_source=False)
    spl_query = (
        f'{scope} (path="firewall.address*" OR "firewall.address") '
        '| table name subnet start-ip end-ip comment '
        '| search name!="" '
        '| sort name '
        f'| head {DEFAULT_LIMIT}'
    )
    return {"action": "execute_spl", "spl_query": spl_query}


@tool
def list_service_objects() -> Dict[str, Any]:
    """
    Best-effort listing of service objects.
    Returns empty results if config data is not indexed.
    """
    scope = base_scope(include_source=False)
    spl_query = (
        f'{scope} (path="firewall.service*" OR "firewall.service") '
        '| table name tcp-portrange udp-portrange comment '
        '| search name!="" '
        '| sort name '
        f'| head {DEFAULT_LIMIT}'
    )
    return {"action": "execute_spl", "spl_query": spl_query}


@tool
def search_policy_by_criteria(criteria_type: str, criteria_value: str) -> Dict[str, Any]:
    """
    Best-effort search of policies by criteria.
    criteria_type examples: action, interface, service, address
    """
    scope = base_scope(include_source=False)
    field_map = {
        "action": "action",
        "interface": "srcintf",
        "service": "service",
        "address": "srcaddr",
    }
    field = field_map.get(criteria_type.lower(), criteria_type)

    spl_query = (
        f'{scope} (path="firewall.policy*" OR "firewall.policy" OR policyid>0) '
        f'| search {field}="{criteria_value}" OR {field}="*{criteria_value}*" '
        '| table name policyid srcintf dstintf srcaddr dstaddr service action status '
        '| sort -policyid '
        f'| head {DEFAULT_LIMIT}'
    )
    return {"action": "execute_spl", "spl_query": spl_query}


# ============================================================
# RAW SPL PASSTHROUGH
# ============================================================

@tool
def execute_spl_query(spl_query: str, description: Optional[str] = None) -> Dict[str, Any]:
    """
    Execute a raw SPL query exactly as provided by the agent.
    """
    return {
        "action": "execute_spl",
        "spl_query": spl_query,
        "description": description,
    }