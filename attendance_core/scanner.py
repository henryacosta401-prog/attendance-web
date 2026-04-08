def resolve_client_ip(remote_addr=""):
    return (remote_addr or "").strip() or "unknown"
