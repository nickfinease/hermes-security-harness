"""Hermes plugin registration for the security harness MVP."""
from . import schemas, tools


def register(ctx):
    ctx.register_tool(
        name="security_validate_target",
        toolset="security_harness",
        schema=schemas.SECURITY_VALIDATE_TARGET,
        handler=tools.validate_target,
        description="Validate an authorized web-target/v1 config before running the harness.",
    )
    ctx.register_tool(
        name="security_start_scan",
        toolset="security_harness",
        schema=schemas.SECURITY_START_SCAN,
        handler=tools.start_scan,
        description="Start a security harness scan job and return a job ID for polling.",
    )
    ctx.register_tool(
        name="security_status",
        toolset="security_harness",
        schema=schemas.SECURITY_STATUS,
        handler=tools.status,
        description="Check status of a security harness job.",
    )
    ctx.register_tool(
        name="security_report",
        toolset="security_harness",
        schema=schemas.SECURITY_REPORT,
        handler=tools.report,
        description="Retrieve a completed security harness report summary or file path.",
    )
