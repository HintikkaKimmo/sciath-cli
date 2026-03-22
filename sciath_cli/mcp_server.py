"""
Sciath MCP Server — exposes scan and analysis capabilities as MCP tools.

Runs as `sciath mcp` with stdio transport for editor integration
(Claude Code, Cursor, Windsurf, etc.).

Architecture: API proxy — all tools call the Sciath REST API via the same
httpx client used by the CLI. No local engine dependency.

Tools:
  - scan_sbom: Upload and analyse an SBOM file
  - get_scan_status: Check scan analysis status
  - list_findings: List CVE findings for a scan
  - explain_cve: Get filter reasoning for a specific CVE
  - get_compliance_status: Get CRA readiness summary for a project
"""

import json
import logging

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from sciath_cli.api import SciathAPI, SciathAPIError
from sciath_cli.config import load_config

logger = logging.getLogger(__name__)

server = Server("sciath")


def _get_api() -> SciathAPI:
    """Create an authenticated API client from stored config."""
    config = load_config()
    if not config.api_key:
        raise ValueError("Not authenticated. Run 'sciath login' first.")
    return SciathAPI(config)


@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="scan_sbom",
            description="Upload and analyse a firmware SBOM for CVE vulnerabilities. Returns scan ID and summary.",
            inputSchema={
                "type": "object",
                "properties": {
                    "sbom_path": {"type": "string", "description": "Path to SBOM file (CycloneDX JSON, SPDX, Yocto)"},
                    "project_id": {"type": "string", "description": "Project ID to scan against"},
                    "version_label": {"type": "string", "description": "Version label (optional)"},
                    "kconfig_path": {"type": "string", "description": "Path to kernel .config file (optional)"},
                },
                "required": ["sbom_path", "project_id"],
            },
        ),
        Tool(
            name="get_scan_status",
            description="Check the status and results of a scan analysis.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "Scan ID to check"},
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="list_findings",
            description="List CVE findings for a scan with severity, status, and filter reasoning.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "Scan ID"},
                    "status": {"type": "string", "description": "Filter by status: affected, not_affected, under_investigation"},
                    "limit": {"type": "integer", "description": "Max results (default 50)"},
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="get_compliance_status",
            description="Get CRA compliance readiness summary for a project — assessment completion, critical resolution, report freshness.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "Project ID"},
                },
                "required": ["project_id"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    try:
        if name == "scan_sbom":
            return await _tool_scan_sbom(arguments)
        elif name == "get_scan_status":
            return await _tool_get_scan_status(arguments)
        elif name == "list_findings":
            return await _tool_list_findings(arguments)
        elif name == "get_compliance_status":
            return await _tool_get_compliance_status(arguments)
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
    except ValueError as e:
        return [TextContent(type="text", text=f"Error: {e}")]
    except SciathAPIError as e:
        return [TextContent(type="text", text=f"API error: {e}")]


async def _tool_scan_sbom(args: dict):
    import hashlib
    import time
    from pathlib import Path

    sbom_path = Path(args["sbom_path"])
    if not sbom_path.exists():
        return [TextContent(type="text", text=f"SBOM file not found: {sbom_path}")]

    project_id = args["project_id"]
    version = args.get("version_label") or f"mcp-{int(time.time())}"
    sbom_raw = sbom_path.read_text(errors="replace")
    kconfig_raw = ""
    if args.get("kconfig_path"):
        kp = Path(args["kconfig_path"])
        if kp.exists():
            kconfig_raw = kp.read_text(errors="replace")

    # Detect format
    from sciath_cli.commands.scan import _detect_format
    sbom_format = _detect_format(sbom_path, sbom_raw)

    idem_key = hashlib.sha256(f"{project_id}:{version}:{sbom_raw[:500]}".encode()).hexdigest()[:32]

    api = _get_api()
    try:
        scan = api.create_scan(
            project_id=project_id,
            version_label=version,
            sbom_raw=sbom_raw,
            sbom_format=sbom_format,
            kconfig_raw=kconfig_raw,
            idempotency_key=idem_key,
        )
        api.trigger_analyse(scan["id"])

        # Poll for completion (max 2 minutes)
        import time as _time
        for _ in range(24):
            _time.sleep(5)
            status = api.get_scan_status(scan["id"])
            if status.get("status") in {"triage", "complete", "failed"}:
                result = {
                    "scan_id": scan["id"],
                    "status": status.get("status"),
                    "total_components": status.get("total_components", 0),
                    "total_vulnerabilities": status.get("total_vulnerabilities", 0),
                    "suppressed_count": status.get("suppressed_count", 0),
                    "remaining": (status.get("total_vulnerabilities", 0) or 0)
                               - (status.get("suppressed_count", 0) or 0),
                }
                return [TextContent(type="text", text=json.dumps(result, indent=2))]

        return [TextContent(type="text", text=f"Scan {scan['id']} is still analysing. Check with get_scan_status.")]
    finally:
        api.close()


async def _tool_get_scan_status(args: dict):
    api = _get_api()
    try:
        data = api.get_scan_status(args["scan_id"])
        return [TextContent(type="text", text=json.dumps(data, indent=2))]
    finally:
        api.close()


async def _tool_list_findings(args: dict):
    api = _get_api()
    try:
        params = {"scan_id": args["scan_id"], "limit": args.get("limit", 50)}
        if args.get("status"):
            params["status"] = args["status"]
        data = api.list_assessments(**params)
        items = data.get("items", [])

        findings = []
        for a in items:
            vuln = a.get("vulnerability", {})
            findings.append({
                "cve_id": vuln.get("vuln_id", ""),
                "cvss": vuln.get("cvss_score"),
                "is_kev": vuln.get("is_kev", False),
                "component": vuln.get("component", {}).get("name", ""),
                "status": a.get("status", ""),
                "filter_layer": a.get("filter_layer", ""),
                "justification": a.get("justification_text", ""),
            })

        return [TextContent(type="text", text=json.dumps({
            "total": len(findings),
            "findings": findings,
        }, indent=2))]
    finally:
        api.close()


async def _tool_get_compliance_status(args: dict):
    """Proxy to the project detail — fetch latest scan stats."""
    api = _get_api()
    try:
        # Get project's scans
        scans = api.list_scans(project_id=args["project_id"], limit=1)
        items = scans.get("items", [])
        if not items:
            return [TextContent(type="text", text=json.dumps({"status": "no_scans", "message": "No scans found for this project."}))]

        latest = items[0]
        total = latest.get("total_vulnerabilities", 0)
        suppressed = latest.get("suppressed_count", 0)

        result = {
            "project_id": args["project_id"],
            "latest_version": latest.get("version_label", ""),
            "scan_status": latest.get("status", ""),
            "total_cves": total,
            "suppressed": suppressed,
            "remaining": total - suppressed,
            "noise_reduction_pct": round(suppressed / total * 100) if total else 0,
        }
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    finally:
        api.close()


async def run_server():
    """Start the MCP server with stdio transport."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
