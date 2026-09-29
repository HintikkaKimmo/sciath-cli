"""Check an installed distribution from outside the source checkout."""

import asyncio
import os
import subprocess
import sysconfig
from importlib.metadata import version
from importlib.resources import files
from pathlib import Path

import sciath_cli
from sciath_cli.discovery.packageconfig_maps import load_map
from sciath_cli.mcp_server import list_tools

installed_version = version("sciath-cli")
assert sciath_cli.__version__ == installed_version

executable = Path(sysconfig.get_path("scripts")) / ("sciath.exe" if os.name == "nt" else "sciath")
output = subprocess.check_output([str(executable), "--version"], text=True).strip()
assert output == f"sciath {installed_version}", output
for command in ([], ["scan", "run"], ["init", "yocto"]):
    subprocess.run([str(executable), *command, "--help"], check=True, stdout=subprocess.DEVNULL)

for recipe in ("bluez5", "busybox", "curl", "dbus", "ffmpeg", "gstreamer1.0", "openssl", "systemd", "wpa-supplicant"):
    assert load_map(recipe) is not None, f"Missing or invalid PACKAGECONFIG map: {recipe}"

package = files(sciath_cli)
for resource in ("meta_layer/classes/sciath.bbclass", "meta_layer/conf/layer.conf"):
    assert package.joinpath(resource).is_file(), f"Missing Yocto resource: {resource}"

assert {tool.name for tool in asyncio.run(list_tools())} == {
    "scan_sbom", "get_scan_status", "list_findings", "get_compliance_status",
}
print(f"sciath {installed_version}: CLI, MCP tools, configuration maps, and Yocto resources passed")
