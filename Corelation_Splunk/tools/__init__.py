from .splunk_tools import (
    # Current State Tools
    list_firewall_policies,
    list_address_objects,
    list_service_objects,
    search_policy_by_criteria,

    # Historical Event Tools
    search_fortigate_config_changes,
    search_fortigate_login_failures,
    search_fortigate_successful_logins,
    search_fortigate_denied_traffic,
    troubleshoot_internet_access,

    # Username Resolution  <-- NEW
    resolve_username_to_ip,

    # General
    show_recent_fortigate_logs,
    execute_spl_query,
)

__all__ = [
    "list_firewall_policies",
    "list_address_objects",
    "list_service_objects",
    "search_policy_by_criteria",
    "search_fortigate_config_changes",
    "search_fortigate_login_failures",
    "search_fortigate_successful_logins",
    "search_fortigate_denied_traffic",
    "troubleshoot_internet_access",
    "resolve_username_to_ip",   # <-- NEW
    "show_recent_fortigate_logs",
    "execute_spl_query",
]