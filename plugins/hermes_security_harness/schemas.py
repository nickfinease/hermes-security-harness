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
