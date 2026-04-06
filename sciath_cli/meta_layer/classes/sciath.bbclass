# sciath.bbclass — Sciath CRA compliance scan integration
#
# Usage:
#   1. Add meta-sciath to your BBLAYERS
#   2. In your image recipe: inherit sciath
#   3. In conf/local.conf:
#        SCIATH_ENABLED = "1"
#        SCIATH_API_KEY = "sk-..."
#        SCIATH_PROJECT = "rpi4-gateway"
#        SCIATH_POLICY = ""              # optional: named filter policy
#        SCIATH_FAIL_ON_ERROR = "0"      # optional: fail build on scan error
#
# The scan runs after do_rootfs. Results are stored in:
#   ${DEPLOY_DIR_IMAGE}/sciath_scan_id   (scan UUID for follow-up)
#   ${DEPLOY_DIR_IMAGE}/sciath_result    (summary: PASS/FAIL + counts)

SCIATH_ENABLED ?= "0"
SCIATH_API_KEY ?= ""
SCIATH_PROJECT ?= ""
SCIATH_POLICY ?= ""
SCIATH_FAIL_ON_ERROR ?= "0"
SCIATH_API_URL ?= "https://api.sciath.io"

python do_sciath_scan() {
    """Run Sciath vulnerability scan after rootfs is assembled."""
    import json
    import subprocess
    import os

    enabled = d.getVar("SCIATH_ENABLED") or "0"
    if enabled != "1":
        bb.note("Sciath: disabled (SCIATH_ENABLED != 1). Skipping scan.")
        return

    api_key = d.getVar("SCIATH_API_KEY") or ""
    project = d.getVar("SCIATH_PROJECT") or ""
    policy = d.getVar("SCIATH_POLICY") or ""
    fail_on_error = (d.getVar("SCIATH_FAIL_ON_ERROR") or "0") == "1"
    api_url = d.getVar("SCIATH_API_URL") or "https://api.sciath.io"

    if not api_key:
        msg = "Sciath: SCIATH_API_KEY not set. Cannot run scan."
        if fail_on_error:
            bb.fatal(msg)
        else:
            bb.warn(msg)
            return

    if not project:
        msg = "Sciath: SCIATH_PROJECT not set. Cannot run scan."
        if fail_on_error:
            bb.fatal(msg)
        else:
            bb.warn(msg)
            return

    # Check sciath CLI is installed
    try:
        subprocess.run(["sciath", "--version"], capture_output=True, check=True, timeout=10)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        msg = f"Sciath: sciath CLI not found. Install with: pip install sciath-cli. Error: {exc}"
        if fail_on_error:
            bb.fatal(msg)
        else:
            bb.error(msg)
            return

    # Build the scan command
    build_dir = d.getVar("BUILDDIR") or os.getcwd()
    deploy_dir = d.getVar("DEPLOY_DIR_IMAGE") or ""
    machine = d.getVar("MACHINE") or ""
    distro = d.getVar("DISTRO") or ""
    version = d.getVar("DISTRO_VERSION") or d.getVar("BUILDNAME") or "yocto-build"

    cmd = [
        "sciath", "scan", "run",
        "--auto-discover",
        "--build-dir", build_dir,
        "--build-system", "yocto",
        "--project", project,
        "--version", f"{machine}-{version}",
        "--format", "json",
    ]

    if policy:
        cmd.extend(["--policy", policy])

    if d.getVar("SCIATH_YOCTO_MACHINE"):
        cmd.extend(["--yocto-machine", machine])
    if d.getVar("SCIATH_YOCTO_DISTRO"):
        cmd.extend(["--yocto-distro", distro])

    # Set environment
    env = os.environ.copy()
    env["SCIATH_API_KEY"] = api_key
    env["SCIATH_API_URL"] = api_url

    bb.note(f"Sciath: running scan for project '{project}' (machine={machine})...")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout
            env=env,
            cwd=build_dir,
        )
    except subprocess.TimeoutExpired:
        msg = "Sciath: scan timed out after 10 minutes."
        if fail_on_error:
            bb.fatal(msg)
        else:
            bb.warn(msg)
            return
    except Exception as exc:
        msg = f"Sciath: unexpected error: {exc}"
        if fail_on_error:
            bb.fatal(msg)
        else:
            bb.warn(msg)
            return

    # Parse result
    scan_id = ""
    remaining = -1
    try:
        data = json.loads(result.stdout)
        scan_id = data.get("scan_id", "")
        remaining = data.get("remaining_count", -1)
    except (json.JSONDecodeError, KeyError):
        pass

    if result.returncode != 0:
        msg = f"Sciath: scan failed (exit {result.returncode}). {result.stderr[:500]}"
        if fail_on_error:
            bb.fatal(msg)
        else:
            bb.warn(msg)

    # Write scan results to deploy dir
    if deploy_dir and scan_id:
        scan_id_file = os.path.join(deploy_dir, "sciath_scan_id")
        with open(scan_id_file, "w") as f:
            f.write(scan_id)
        bb.note(f"Sciath: scan ID written to {scan_id_file}")

        if remaining >= 0:
            result_file = os.path.join(deploy_dir, "sciath_result")
            status = "PASS" if remaining == 0 else f"REVIEW ({remaining} open findings)"
            with open(result_file, "w") as f:
                f.write(f"{status}\n")
            bb.note(f"Sciath: {status}")

    if scan_id:
        bb.note(f"Sciath: scan complete. ID: {scan_id}, open findings: {remaining}")
    else:
        bb.note("Sciath: scan completed but no scan ID returned.")
}

addtask sciath_scan after do_rootfs before do_build
do_sciath_scan[nostamp] = "1"
do_sciath_scan[network] = "1"
