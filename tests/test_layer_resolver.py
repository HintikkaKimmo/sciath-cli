"""Tests for static Yocto layer resolver."""

from pathlib import Path

import pytest

from sciath_cli.discovery.layer_resolver import resolve_layer


@pytest.fixture
def minimal_bsp_layer(tmp_path: Path) -> Path:
    """Minimal BSP layer with a kernel recipe and patches."""
    layer = tmp_path / "meta-test"
    layer.mkdir()

    # layer.conf
    conf = layer / "conf"
    conf.mkdir()
    (conf / "layer.conf").write_text(
        'BBFILE_COLLECTIONS += "meta-test"\n'
        'BBFILE_PRIORITY_meta-test = "8"\n'
    )

    # Kernel recipe with patches
    kernel_dir = layer / "recipes-kernel" / "linux"
    kernel_dir.mkdir(parents=True)
    (kernel_dir / "linux-test_5.15.bb").write_text(
        'SRC_URI = "git://kernel.org;branch=main \\\n'
        '           file://0001-fix-usb-gadget.patch \\\n'
        '           file://0002-backport-net-fix.patch \\\n'
        '           "\n'
    )

    # Patch files in recipe-name subdirectory
    patches_dir = kernel_dir / "linux-test"
    patches_dir.mkdir()
    (patches_dir / "0001-fix-usb-gadget.patch").write_text(
        "From abc123\n"
        "Subject: fix usb gadget null deref\n"
        "Upstream-Status: Backport\n"
        "CVE: CVE-2024-1234\n"
        "\n"
        "---\n"
        " drivers/usb/gadget/rndis.c | 2 +-\n"
    )
    (patches_dir / "0002-backport-net-fix.patch").write_text(
        "From def456\n"
        "Subject: net: fix skb use after free\n"
        "Upstream-Status: Backport\n"
        "\n"
        "---\n"
        " net/core/skbuff.c | 3 ++-\n"
    )

    # Kernel config fragment
    cfg_dir = kernel_dir / "linux-test"
    (cfg_dir / "usb.cfg").write_text("CONFIG_USB_GADGET=y\n")

    return layer


@pytest.fixture
def bbappend_layer(tmp_path: Path) -> Path:
    """Layer with a bbappend that adds patches via FILESEXTRAPATHS."""
    layer = tmp_path / "meta-vendor"
    layer.mkdir()

    conf = layer / "conf"
    conf.mkdir()
    (conf / "layer.conf").write_text(
        'BBFILE_COLLECTIONS += "meta-vendor"\n'
        'BBFILE_PRIORITY_meta-vendor = "10"\n'
    )

    # bbappend with FILESEXTRAPATHS
    recipe_dir = layer / "recipes-kernel" / "linux"
    recipe_dir.mkdir(parents=True)
    (recipe_dir / "linux-test_%.bbappend").write_text(
        'FILESEXTRAPATHS:prepend := "${THISDIR}/files:"\n'
        'SRC_URI += "file://vendor-hack.patch"\n'
    )

    # Patch in files/ directory
    files_dir = recipe_dir / "files"
    files_dir.mkdir()
    (files_dir / "vendor-hack.patch").write_text(
        "Subject: vendor specific workaround\n"
        "Upstream-Status: Inappropriate [vendor specific]\n"
        "\n"
        "---\n"
        " arch/arm64/boot/dts/vendor.dts | 1 +\n"
    )

    return layer


class TestResolveLayer:
    def test_parses_layer_name(self, minimal_bsp_layer: Path):
        info = resolve_layer(minimal_bsp_layer)
        assert info.layer_name == "meta-test"

    def test_parses_priority(self, minimal_bsp_layer: Path):
        info = resolve_layer(minimal_bsp_layer)
        assert info.priority == 8

    def test_finds_recipes(self, minimal_bsp_layer: Path):
        info = resolve_layer(minimal_bsp_layer)
        assert len(info.recipes) == 1
        assert info.recipes[0].name == "linux-test"

    def test_finds_patches(self, minimal_bsp_layer: Path):
        info = resolve_layer(minimal_bsp_layer)
        recipe = info.recipes[0]
        assert len(recipe.patches) == 2
        patch_names = [p.file_path.name for p in recipe.patches]
        assert "0001-fix-usb-gadget.patch" in patch_names
        assert "0002-backport-net-fix.patch" in patch_names

    def test_extracts_cve_from_patch(self, minimal_bsp_layer: Path):
        info = resolve_layer(minimal_bsp_layer)
        cve_patch = [p for p in info.recipes[0].patches if p.cve_ids][0]
        assert "CVE-2024-1234" in cve_patch.cve_ids
        assert cve_patch.classification == "cve-tagged"

    def test_extracts_upstream_status(self, minimal_bsp_layer: Path):
        info = resolve_layer(minimal_bsp_layer)
        for patch in info.recipes[0].patches:
            assert patch.upstream_status == "Backport"

    def test_classifies_backport(self, minimal_bsp_layer: Path):
        info = resolve_layer(minimal_bsp_layer)
        backport = [p for p in info.recipes[0].patches if not p.cve_ids][0]
        assert backport.classification == "backport"

    def test_finds_kconfig_fragments(self, minimal_bsp_layer: Path):
        info = resolve_layer(minimal_bsp_layer)
        assert len(info.kernel_config_fragments) == 1
        assert info.kernel_config_fragments[0].name == "usb.cfg"

    def test_parse_confidence_full(self, minimal_bsp_layer: Path):
        info = resolve_layer(minimal_bsp_layer)
        assert info.parse_confidence == 1.0

    def test_total_patches_property(self, minimal_bsp_layer: Path):
        info = resolve_layer(minimal_bsp_layer)
        assert info.total_patches == 2


class TestBbappend:
    def test_finds_bbappend_recipe(self, bbappend_layer: Path):
        info = resolve_layer(bbappend_layer)
        assert len(info.recipes) == 1
        assert info.recipes[0].file_path.suffix == ".bbappend"

    def test_resolves_patch_from_files_dir(self, bbappend_layer: Path):
        info = resolve_layer(bbappend_layer)
        recipe = info.recipes[0]
        assert len(recipe.patches) == 1
        assert recipe.patches[0].file_path.name == "vendor-hack.patch"

    def test_classifies_vendor_patch(self, bbappend_layer: Path):
        info = resolve_layer(bbappend_layer)
        patch = info.recipes[0].patches[0]
        assert patch.classification == "vendor-only"
        assert patch.upstream_status == "Inappropriate"

    def test_higher_priority(self, bbappend_layer: Path):
        info = resolve_layer(bbappend_layer)
        assert info.priority == 10


class TestEdgeCases:
    def test_empty_layer(self, tmp_path: Path):
        layer = tmp_path / "meta-empty"
        layer.mkdir()
        (layer / "conf").mkdir()
        (layer / "conf" / "layer.conf").write_text('BBFILE_COLLECTIONS += "meta-empty"\n')

        info = resolve_layer(layer)
        assert len(info.recipes) == 0
        assert info.parse_confidence == 1.0

    def test_no_layer_conf(self, tmp_path: Path):
        layer = tmp_path / "meta-noconf"
        layer.mkdir()

        info = resolve_layer(layer)
        assert "No conf/layer.conf found" in info.warnings

    def test_unresolvable_patch_logged(self, tmp_path: Path):
        """A patch referenced in SRC_URI but missing on disk → parse error."""
        layer = tmp_path / "meta-broken"
        layer.mkdir()
        (layer / "conf").mkdir()
        (layer / "conf" / "layer.conf").write_text('BBFILE_COLLECTIONS += "meta-broken"\n')

        recipe_dir = layer / "recipes-test" / "myrecipe"
        recipe_dir.mkdir(parents=True)
        (recipe_dir / "myrecipe_1.0.bb").write_text(
            'SRC_URI = "file://nonexistent.patch"\n'
        )

        info = resolve_layer(layer)
        assert info.recipes[0].parse_errors
        assert "nonexistent.patch" in info.recipes[0].parse_errors[0]
        assert info.parse_confidence < 1.0

    def test_cve_in_filename(self, tmp_path: Path):
        """CVE IDs in patch filenames are extracted."""
        layer = tmp_path / "meta-cve"
        layer.mkdir()
        (layer / "conf").mkdir()
        (layer / "conf" / "layer.conf").write_text('BBFILE_COLLECTIONS += "meta-cve"\n')

        recipe_dir = layer / "recipes-kernel" / "linux"
        recipe_dir.mkdir(parents=True)
        (recipe_dir / "linux_5.15.bb").write_text(
            'SRC_URI = "file://CVE-2024-5678.patch"\n'
        )
        patches_dir = recipe_dir / "linux"
        patches_dir.mkdir()
        (patches_dir / "CVE-2024-5678.patch").write_text("fix something\n")

        info = resolve_layer(layer)
        patch = info.recipes[0].patches[0]
        assert "CVE-2024-5678" in patch.cve_ids

    def test_summary(self, minimal_bsp_layer: Path):
        info = resolve_layer(minimal_bsp_layer)
        s = info.summary()
        assert "meta-test" in s
        assert "priority 8" in s
        assert "2 patches" in s
        assert "100%" in s
