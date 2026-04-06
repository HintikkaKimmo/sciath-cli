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
