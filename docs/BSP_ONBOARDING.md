# BSP Onboarding Manual

How to add a new vendor BSP to Sciath's suppression database.

## Quick Start

1. Go to Django admin → BSP Repos → Add
2. Fill in: vendor, SoM name, repo URL, branch
3. Save, select it, run "Ingest selected" action
4. Check status: Ready = good, Failed = check error message

## Identifying the BSP Structure

Before adding a BSP, you need to understand how the vendor handles patches.
There are three common patterns. Run this checklist on the vendor's git repos:

### Step 1: Find the meta layer(s)

Search for the vendor's Yocto meta layer. Common locations:
- GitHub: `github.com/<vendor>/meta-<vendor>`
- GitLab: `git.<vendor>.com` or vendor's self-hosted GitLab
- Yocto layer index: layers.openembedded.org

Check for multiple layers. Many vendors split their BSP:
- `meta-<vendor>-bsp-common` — shared config, machine definitions
- `meta-<vendor>-nxp` or `meta-<vendor>-ti` — silicon-specific layer
- `meta-<vendor>-distro` — distribution customization

**The layer with kernel recipes is usually the one you want.**

### Step 2: Identify the patch pattern

Open `recipes-kernel/linux/` in the meta layer and check:

**Pattern A: file:// patches in SRC_URI**
```
SRC_URI = "git://kernel.org/... \
           file://0001-fix-something.patch \
           file://0002-vendor-dts.patch \
           "
```
→ Sciath captures these automatically. Most patches found in recipe-name/ or files/ subdirectory.
→ **Admin fields:** repo URL = meta layer, branch = scarthgap (or latest)

**Pattern B: Vendor kernel fork (git:// source)**
```
SRC_URI = "git://git.vendor.com/linux-vendor.git;branch=${SRCBRANCH}"
SRCBRANCH = "vendor_6.6-2.x"
SRCREV = "abc123..."
```
→ Patches are commits in the fork, not file:// patches
→ Sciath captures the git source URI. Kernel fork analysis needed for CVE matching.
→ **Admin fields:** repo URL = meta layer (for layer resolver), then add kernel fork URL in notes

**Pattern C: Hybrid (both)**
→ Some file:// patches in the layer + kernel fork for the kernel itself
→ Most common pattern (PHYTEC, Variscite, Digi)
→ **Admin fields:** same as Pattern B. Layer ingestion captures file patches. Kernel fork needs separate analysis.

### Step 3: Find the right branch

Vendors use various branch naming:
- `scarthgap` (standard Yocto release name)
- `scarthgap-7.x.y` (Toradex version-tagged)
- `scarthgap_6.6.52-2.2.2_var01` (Variscite kernel-version-tagged)
- `kirkstone`, `nanbield` (older Yocto releases)

Check available branches: `git ls-remote --heads <repo_url>`

**Always use the latest Scarthgap branch** unless the customer specifies otherwise.

## Django Admin Fields

| Field | Description | Example |
|-------|-------------|---------|
| Vendor | BSP vendor name (lowercase) | `toradex` |
| SoM | System-on-Module identifier | `verdin-imx8mp` |
| Repo URL | Git clone URL for the meta layer | `https://git.toradex.com/meta-toradex-nxp.git` |
| Branch | Git branch to analyze | `scarthgap-7.x.y` |
| Layer subpath | Subdirectory if layer isn't at repo root | (usually empty) |
| Notes | Internal notes: kernel fork URL, customer context | `Kernel fork: git://git.toradex.com/linux-toradex.git` |

## What Ingestion Produces

After running "Ingest selected", the system:

1. Clones the repo (--depth=1)
2. Parses all .bb/.bbappend recipes
3. Extracts patches from SRC_URI file:// references
4. Scans for orphan patches in files/ and recipe-name/ directories
5. Extracts CVE tags from patch headers and filenames
6. Classifies patches: cve-tagged, backport, vendor-only, unknown
7. Records git:// source URIs (kernel forks, u-boot forks)
8. Merges kernel config fragments (.cfg files)
9. Stores everything as a JSON profile

**Check the results:**
- `patch_count` — total patches found. If 0, the layer probably uses Pattern B (fork).
- `suppression_count` — CVEs auto-suppressed. Low is normal for v1.
- `parse_confidence` — 100% means all recipes parsed. <90% means check warnings.
- Profile JSON (expand "Profile Data" section) — full details.

## Troubleshooting

### "Clone failed: Remote branch not found"
→ Check available branches with `git ls-remote --heads <url>`
→ Vendor may use non-standard branch naming

### 0 patches found
→ Check if this is a "bsp-common" layer (config only, no kernel recipes)
→ The kernel patches may be in a different layer (e.g., meta-vendor-nxp)
→ Or the vendor uses a kernel fork (Pattern B) — patches are commits, not files

### Low parse confidence (<90%)
→ Some SRC_URI entries use BitBake variables (${PV}, ${BPN}) that can't be resolved statically
→ Check warnings in the profile JSON for specific unresolvable entries
→ This is expected. The unresolved entries are logged but don't block ingestion.

### Ingestion timeout
→ Large repos may exceed the 120s clone timeout
→ Clone manually: `git clone --depth=1 --branch=<branch> <url> /tmp/bsp-test`
→ Then ingest via Django shell: `ingest_bsp(Path('/tmp/bsp-test'), 'vendor', 'som')`

## Real-World Examples

### Toradex (Pattern B — kernel fork)
- **Meta layer:** `https://git.toradex.com/meta-toradex-nxp.git` (branch: `scarthgap-7.x.y`)
- **Result:** 4 file patches, 3 git source forks (kernel, u-boot, SC firmware)
- **Kernel fork:** `git://git.toradex.com/linux-toradex.git`
- **Note:** Most CVE-relevant patches are in the kernel fork, not the meta layer

### Raspberry Pi (Pattern A — file patches)
- **Meta layer:** `https://github.com/agherzan/meta-raspberrypi.git` (branch: `scarthgap`)
- **Result:** 102 patches, 1 CVE suppression (CVE-2022-41325), 32 kconfig keys
- **Note:** Community layer, well-structured, highest patch count in our corpus

### PHYTEC (Pattern C — hybrid)
- **Meta layer:** `https://github.com/phytec/meta-phytec.git` (branch: `scarthgap`)
- **Result:** 40 patches, 262 kconfig keys, 93% confidence
- **Note:** Uses both file patches and a vendor kernel fork (linux-phytec-ti)

### Variscite (Pattern C — hybrid)
- **Meta layer:** `https://github.com/varigit/meta-variscite-bsp-imx.git` (branch: `scarthgap_6.6.52-2.2.2_var01`)
- **Result:** 17 patches, 4 git sources
- **Note:** Non-standard branch naming. Check `git ls-remote` for available branches.

## Kernel Fork Analysis (Pattern B/C vendors)

For vendors with kernel forks, the meta layer ingestion captures file patches
but misses the real CVE fixes. Run kernel fork analysis separately:

### Step 1: Build the vulns.git index (one-time)

```bash
sciath bsp build-vulns-index
# Or manually:
python -c "
from sciath_cli.discovery.vulns_corpus import clone_vulns_repo, build_index, save_index
from pathlib import Path
import tempfile
with tempfile.TemporaryDirectory() as tmp:
    repo = clone_vulns_repo(Path(tmp) / 'vulns')
    index = build_index(repo)
    save_index(index, Path('sciath_cli/discovery/data/vulns_index.json'))
    print(f'{index.total_cves} CVEs indexed')
"
```

This produces ~5MB JSON with 10,994+ CVEs and their fix commits.

### Step 2: Identify the kernel fork

In Django admin, the kernel fork URL should be in the BSP repo record.
If not, find it in the meta layer's kernel recipe:

```bash
grep -r "SRC_URI.*git://" <meta-layer>/recipes-kernel/linux/
```

### Step 3: Find the correct branch

```bash
git ls-remote --heads <kernel-fork-url> | grep "6.6"
```

Common patterns:
- Toradex: `toradex_6.6-2.2.x-imx` (note the `-imx` suffix)
- PHYTEC: `v6.6/master`
- Variscite: `lf-6.6.y`
- NXP: `lf-6.6.y`

### Step 4: Run the analysis

```python
from sciath_cli.discovery.vulns_corpus import load_index
from sciath_cli.discovery.kernel_fork import analyze_kernel_fork, clone_kernel_fork
from pathlib import Path

index = load_index(Path('sciath_cli/discovery/data/vulns_index.json'))

with tempfile.TemporaryDirectory() as tmp:
    fork = clone_kernel_fork('<kernel-fork-url>', Path(tmp) / 'kernel', branch='<branch>')
    analysis = analyze_kernel_fork(fork, '<branch>', '<vendor>', index)
    print(analysis.summary())
    for m in analysis.cve_matches:
        print(f"  {m['cve_id']}: {m['subject'][:60]}")
```

### Real results (April 2026)

| Vendor | Branch | Commits | CVE Matches | Method |
|--------|--------|---------|-------------|--------|
| Toradex | toradex_6.6-2.2.x-imx | 500 | 7 | commit hash + subject |

Note: 7 matches from 500 commits with hash-only matching. Patch-id fingerprinting
against the full vulns.git branch fix corpus will increase this number.

## Internal: Vendor Patch Format Reference

Each BSP vendor handles patches differently. This reference documents the
specific patterns discovered during ingestion for each supported vendor.

| Vendor | Patch Location | Kernel Source | Branch Naming | Notes |
|--------|---------------|---------------|---------------|-------|
| **Toradex** | 4 file patches in meta-toradex-nxp (u-boot, ATF, ISP) | git://git.toradex.com/linux-toradex.git | `toradex_6.6-X.X.x-imx` | Kernel patches are ALL in the fork. Meta layer has almost none. |
| **RPi** | 102 file patches in meta-raspberrypi | Uses upstream linux-raspberrypi (not a vendor fork in meta layer) | `scarthgap` | Community layer. Well-structured. CVE tags in filenames. |
| **PHYTEC** | 40 file patches in meta-phytec | git://github.com/phytec/linux-phytec-ti.git | `v6.6/master` | Hybrid. DTS and config patches in meta layer, kernel security in fork. 262 kconfig keys. |
| **Variscite** | 17 file patches in meta-variscite-bsp-imx | git://github.com/varigit/linux-imx.git | `lf-6.6.y` | Non-standard branch naming with version+variant suffix. |

### What to document for each new BSP

When onboarding a new vendor, record:
1. Which meta layer(s) contain kernel recipes
2. Whether the kernel is a file:// patch layer or a git:// fork (or both)
3. The exact kernel fork URL and branch name
4. Any non-standard branch naming conventions
5. Where kconfig fragments live (in the meta layer or only in the kernel fork)
6. Whether patches have CVE tags or Upstream-Status headers
