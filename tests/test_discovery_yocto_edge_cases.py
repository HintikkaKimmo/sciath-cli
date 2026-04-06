"""Edge-case tests for Yocto artifact collection — safety net before refactoring."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from sciath_cli.discovery.base import ArtifactBundle
from sciath_cli.discovery.yocto import YoctoDiscovery


class TestDTBCap:
    def test_dtb_cap_at_20(self, tmp_path: Path):
        """_find_dtbs() caps at 20 even when more DTB files exist."""
        # Minimal Yocto structure
        conf = tmp_path / "conf"
        conf.mkdir()
        (conf / "local.conf").write_text('MACHINE = "testmachine"\n')
        (tmp_path / "tmp").mkdir()

        images_dir = tmp_path / "tmp" / "deploy" / "images" / "testmachine"
        images_dir.mkdir(parents=True)

        # Create 25 DTB files
        for i in range(25):
            (images_dir / f"device-{i:02d}.dtb").write_bytes(b"\x00")

        bundle = YoctoDiscovery().collect(tmp_path)
        assert len(bundle.dtb) == 20


class TestCycloneDXDetection:
    def test_cyclonedx_sbom_detection(self, tmp_path: Path):
        """CycloneDX SBOM (*.cdx.json) detected when no SPDX present."""
        conf = tmp_path / "conf"
        conf.mkdir()
        (conf / "local.conf").write_text('MACHINE = "testmachine"\n')
        (tmp_path / "tmp").mkdir()

        deploy_dir = tmp_path / "tmp" / "deploy"
        deploy_dir.mkdir(parents=True)

        # Place a CycloneDX SBOM (no spdx/ directory)
        cdx_file = deploy_dir / "firmware.cdx.json"
        cdx_file.write_text('{"bomFormat": "CycloneDX"}')

        bundle = YoctoDiscovery().collect(tmp_path)
        assert bundle.sbom_format == "cyclonedx"
        assert bundle.sbom is not None
        assert bundle.sbom.name == "firmware.cdx.json"


class TestBitbakeTimeout:
    @patch("sciath_cli.discovery.yocto.subprocess.run")
    def test_bitbake_timeout_handling(self, mock_run: MagicMock):
        """TimeoutExpired from bitbake -e returns empty dict."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="bitbake", timeout=30)

        discovery = YoctoDiscovery()
        result = discovery._extract_packageconfigs(Path("/fake/build"))
        assert result == {}

    @patch("sciath_cli.discovery.yocto.subprocess.run")
    def test_packageconfig_empty_output(self, mock_run: MagicMock):
        """bitbake -e output with no PACKAGECONFIG line returns None per recipe."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "SOME_OTHER_VAR=foo\nANOTHER_VAR=bar\n"
        mock_run.return_value = mock_result

        discovery = YoctoDiscovery()
        result = discovery._extract_packageconfigs(Path("/fake/build"))
        assert result == {}

    @patch("sciath_cli.discovery.yocto.subprocess.run")
    def test_packageconfig_malformed_output(self, mock_run: MagicMock):
        """Garbled PACKAGECONFIG value is handled gracefully (returns empty list)."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        # Malformed: value is just garbage with no quotes
        mock_result.stdout = 'PACKAGECONFIG=\x00\x01\x02\n'
        mock_run.return_value = mock_result

        discovery = YoctoDiscovery()
        result = discovery._extract_packageconfigs(Path("/fake/build"))

        # Should not raise; every recipe gets the same garbled output.
        # The split logic strips quotes then splits — garbage in, list out,
        # but no exception.
        assert isinstance(result, dict)
        # All 9 target recipes should appear since returncode=0 and
        # the PACKAGECONFIG line is present (even if garbled)
        for flags in result.values():
            assert isinstance(flags, list)


class TestConfigurablePackageconfig:
    @patch("sciath_cli.discovery.yocto.subprocess.run", side_effect=FileNotFoundError)
    def test_env_var_overrides_recipe_list(self, mock_run: MagicMock, monkeypatch):
        """SCIATH_PACKAGECONFIG_RECIPES env var overrides default recipes."""
        monkeypatch.setenv("SCIATH_PACKAGECONFIG_RECIPES", "openssl,curl")

        discovery = YoctoDiscovery()
        discovery._extract_packageconfigs(Path("/fake/build"))

        # Should only query openssl and curl, not the full default list of 9
        assert mock_run.call_count == 2
        queried_recipes = [call.args[0][-1] for call in mock_run.call_args_list]
        assert queried_recipes == ["openssl", "curl"]

    @patch("sciath_cli.discovery.yocto.subprocess.run", side_effect=FileNotFoundError)
    def test_env_var_strips_whitespace(self, mock_run: MagicMock, monkeypatch):
        """Whitespace around recipe names in env var is stripped."""
        monkeypatch.setenv("SCIATH_PACKAGECONFIG_RECIPES", " openssl , curl , ")

        discovery = YoctoDiscovery()
        discovery._extract_packageconfigs(Path("/fake/build"))

        assert mock_run.call_count == 2
        queried_recipes = [call.args[0][-1] for call in mock_run.call_args_list]
        assert queried_recipes == ["openssl", "curl"]

    @patch("sciath_cli.discovery.yocto.subprocess.run", side_effect=FileNotFoundError)
    def test_default_recipe_list_without_env_var(self, mock_run: MagicMock, monkeypatch):
        """Without env var, uses the default 9-recipe list."""
        monkeypatch.delenv("SCIATH_PACKAGECONFIG_RECIPES", raising=False)

        discovery = YoctoDiscovery()
        discovery._extract_packageconfigs(Path("/fake/build"))

        assert mock_run.call_count == 9


class TestConfigurableDtbCap:
    def test_env_var_overrides_dtb_cap(self, tmp_path: Path, monkeypatch):
        """SCIATH_MAX_DTBS env var overrides the default cap of 20."""
        monkeypatch.setenv("SCIATH_MAX_DTBS", "5")

        (tmp_path / "conf").mkdir()
        (tmp_path / "conf" / "local.conf").write_text(
            'MACHINE = "test"\nDISTRO = "poky"\n'
        )
        (tmp_path / "tmp").mkdir()
        deploy = tmp_path / "tmp" / "deploy" / "images" / "test"
        deploy.mkdir(parents=True)
        for i in range(10):
            (deploy / f"board-{i}.dtb").write_bytes(b"\xd0\x0d")

        d = YoctoDiscovery()
        bundle = d.collect(tmp_path)
        assert len(bundle.dtb) == 5

    def test_default_dtb_cap_still_20(self, tmp_path: Path, monkeypatch):
        """Without env var, the default cap of 20 still applies."""
        monkeypatch.delenv("SCIATH_MAX_DTBS", raising=False)

        (tmp_path / "conf").mkdir()
        (tmp_path / "conf" / "local.conf").write_text(
            'MACHINE = "test"\nDISTRO = "poky"\n'
        )
        (tmp_path / "tmp").mkdir()
        deploy = tmp_path / "tmp" / "deploy" / "images" / "test"
        deploy.mkdir(parents=True)
        for i in range(25):
            (deploy / f"board-{i}.dtb").write_bytes(b"\xd0\x0d")

        d = YoctoDiscovery()
        bundle = d.collect(tmp_path)
        assert len(bundle.dtb) == 20


class TestRecipeNameSanitization:
    @patch("sciath_cli.discovery.yocto.subprocess.run")
    def test_rejects_malicious_recipe_name(self, mock_run, yocto_build_dir: Path):
        """Recipe names with shell metacharacters must be skipped."""
        import os

        os.environ["SCIATH_PACKAGECONFIG_RECIPES"] = "openssl,; rm -rf /,curl"
        try:
            d = YoctoDiscovery()
            d.collect(yocto_build_dir)
            # Only openssl and curl should be attempted (the malicious one skipped)
            called_recipes = [
                call.args[0][2] if call.args else call.kwargs.get("args", [])[2]
                for call in mock_run.call_args_list
            ]
            assert "; rm -rf /" not in called_recipes
            assert "openssl" in called_recipes
            assert "curl" in called_recipes
        finally:
            del os.environ["SCIATH_PACKAGECONFIG_RECIPES"]

    @patch("sciath_cli.discovery.yocto.subprocess.run")
    def test_allows_valid_recipe_names(self, mock_run, yocto_build_dir: Path):
        """Valid Yocto recipe names (with dots, hyphens, plus) must be accepted."""
        import os

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'PACKAGECONFIG="ssl"\n'
        os.environ["SCIATH_PACKAGECONFIG_RECIPES"] = "gstreamer1.0,wpa-supplicant,libstdc++"
        try:
            d = YoctoDiscovery()
            d.collect(yocto_build_dir)
            assert mock_run.call_count == 3
        finally:
            del os.environ["SCIATH_PACKAGECONFIG_RECIPES"]


class TestSchemaVersion:
    def test_default_schema_version(self):
        bundle = ArtifactBundle()
        assert bundle.schema_version == "1.1"

    def test_custom_schema_version(self):
        bundle = ArtifactBundle(schema_version="2.0")
        assert bundle.schema_version == "2.0"
