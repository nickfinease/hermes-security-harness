"""Tool schemas for Hermes security harness plugin."""

SECURITY_VALIDATE_TARGET = {
    "name": "security_validate_target",
    "description": "Validate that a web-target/v1 config is authorized and safe to use before running the security harness.",
    "parameters": {
        "type": "object",
        "properties": {
            "config_path": {"type": "string", "description": "Path to a web-target/v1 YAML or JSON config."},
        },
        "required": ["config_path"],
    },
}

SECURITY_START_SCAN = {
    "name": "security_start_scan",
    "description": "Start an asynchronous security harness job (http-smoke, static-scan, or gated poc-replay).",
    "parameters": {
        "type": "object",
        "properties": {
            "scan_type": {"type": "string", "enum": ["http-smoke", "static-scan", "poc-replay"], "default": "http-smoke"},
            "config_path": {"type": "string", "description": "Path to web-target/v1 YAML or JSON config."},
            "source_root": {"type": "string", "description": "Source root for static-scan jobs."},
            "poc_path": {"type": "string", "description": "HTTP PoC JSON path for poc-replay jobs."},
            "skip_agent": {"type": "boolean", "default": False},
            "request_timeout": {"type": "number", "default": 10},
            "max_turns": {"type": "integer", "default": 16},
            "timeout": {"type": "number", "default": 900},
            "max_files": {"type": "integer", "default": 250},
            "run_lifecycle": {"type": "boolean", "default": False},
            "sandbox_mode": {"type": "string", "enum": ["none", "gvisor", "bwrap", "container", "firejail"], "default": "none"},
            "egress_hosts": {"type": "array", "items": {"type": "string"}},
            "ephemeral_home": {"type": "string"},
            "no_credential_mounts": {"type": "boolean", "default": False},
        },
        "required": ["config_path"],
    },
}

SECURITY_STATUS = {
    "name": "security_status",
    "description": "Check status of a previously started security harness job.",
    "parameters": {
        "type": "object",
        "properties": {
            "job_id": {"type": "string", "description": "Job ID returned by the harness."},
        },
        "required": ["job_id"],
    },
}

SECURITY_REPORT = {
    "name": "security_report",
    "description": "Retrieve the report summary or file path for a completed security harness job.",
    "parameters": {
        "type": "object",
        "properties": {
            "job_id": {"type": "string", "description": "Completed job ID."},
            "format": {"type": "string", "enum": ["summary", "json", "markdown"], "default": "summary"},
        },
        "required": ["job_id"],
    },
}
