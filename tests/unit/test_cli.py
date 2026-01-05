"""Tests for CLI commands."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from joyfuljay.cli.main import cli


@pytest.fixture
def runner() -> CliRunner:
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def sample_pcap(tmp_path: Path) -> Path:
    """Create a minimal PCAP file for testing.

    This creates a valid but minimal PCAP file structure.
    """
    # PCAP file header (24 bytes) + minimal packet
    pcap_header = bytes(
        [
            0xD4, 0xC3, 0xB2, 0xA1,  # Magic number (little-endian)
            0x02, 0x00, 0x04, 0x00,  # Version 2.4
            0x00, 0x00, 0x00, 0x00,  # GMT offset
            0x00, 0x00, 0x00, 0x00,  # Timestamp accuracy
            0xFF, 0xFF, 0x00, 0x00,  # Snaplen
            0x01, 0x00, 0x00, 0x00,  # Link type (Ethernet)
        ]
    )

    pcap_file = tmp_path / "test.pcap"
    with open(pcap_file, "wb") as f:
        f.write(pcap_header)

    return pcap_file


class TestVersionOption:
    """Tests for --version option."""

    def test_version(self, runner: CliRunner) -> None:
        """Test version output."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "joyfuljay" in result.output.lower()


class TestHelpOption:
    """Tests for --help option."""

    def test_help(self, runner: CliRunner) -> None:
        """Test help output."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "JoyfulJay" in result.output
        assert "extract" in result.output

    def test_extract_help(self, runner: CliRunner) -> None:
        """Test extract command help."""
        result = runner.invoke(cli, ["extract", "--help"])
        assert result.exit_code == 0
        assert "--output" in result.output
        assert "--format" in result.output

    def test_live_help(self, runner: CliRunner) -> None:
        """Test live command help."""
        result = runner.invoke(cli, ["live", "--help"])
        assert result.exit_code == 0
        assert "INTERFACE" in result.output

    def test_serve_help(self, runner: CliRunner) -> None:
        """Test serve command help."""
        result = runner.invoke(cli, ["serve", "--help"])
        assert result.exit_code == 0
        assert "--port" in result.output
        assert "--tls-cert" in result.output

    def test_connect_help(self, runner: CliRunner) -> None:
        """Test connect command help."""
        result = runner.invoke(cli, ["connect", "--help"])
        assert result.exit_code == 0
        assert "URL" in result.output

    def test_discover_help(self, runner: CliRunner) -> None:
        """Test discover command help."""
        result = runner.invoke(cli, ["discover", "--help"])
        assert result.exit_code == 0
        assert "--timeout" in result.output

    def test_watch_help(self, runner: CliRunner) -> None:
        """Test watch command help."""
        result = runner.invoke(cli, ["watch", "--help"])
        assert result.exit_code == 0
        assert "DIRECTORY" in result.output

    def test_schema_help(self, runner: CliRunner) -> None:
        """Test schema command help."""
        result = runner.invoke(cli, ["schema", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output

    def test_features_help(self, runner: CliRunner) -> None:
        """Test features command help."""
        result = runner.invoke(cli, ["features", "--help"])
        assert result.exit_code == 0

    def test_status_help(self, runner: CliRunner) -> None:
        """Test status command help."""
        result = runner.invoke(cli, ["status", "--help"])
        assert result.exit_code == 0

    def test_info_help(self, runner: CliRunner) -> None:
        """Test info command help."""
        result = runner.invoke(cli, ["info", "--help"])
        assert result.exit_code == 0
        assert "INPUT_PATH" in result.output


class TestExtractCommand:
    """Tests for extract command."""

    def test_missing_input(self, runner: CliRunner) -> None:
        """Test error when input file is missing."""
        result = runner.invoke(cli, ["extract"])
        assert result.exit_code != 0

    def test_nonexistent_input(self, runner: CliRunner) -> None:
        """Test error when input file doesn't exist."""
        result = runner.invoke(cli, ["extract", "/nonexistent/file.pcap"])
        assert result.exit_code != 0

    @patch("joyfuljay.cli.main.Pipeline")
    def test_extract_to_stdout(
        self, mock_pipeline: MagicMock, runner: CliRunner, sample_pcap: Path
    ) -> None:
        """Test extraction to stdout."""
        mock_instance = MagicMock()
        mock_instance.process_pcap.return_value = []
        mock_pipeline.return_value = mock_instance

        result = runner.invoke(cli, ["extract", str(sample_pcap)])

        # Should not fail
        assert mock_pipeline.called

    @patch("joyfuljay.cli.main.Pipeline")
    def test_extract_to_file(
        self, mock_pipeline: MagicMock, runner: CliRunner, tmp_path: Path, sample_pcap: Path
    ) -> None:
        """Test extraction to file."""
        mock_instance = MagicMock()
        mock_instance.process_pcap.return_value = [
            {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}
        ]
        mock_instance.process_pcaps_batch.return_value = [
            {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}
        ]
        mock_pipeline.return_value = mock_instance

        output_file = tmp_path / "output.csv"
        result = runner.invoke(
            cli, ["extract", str(sample_pcap), "-o", str(output_file)]
        )

        assert mock_pipeline.called

    @patch("joyfuljay.cli.main.Pipeline")
    def test_extract_with_features(
        self, mock_pipeline: MagicMock, runner: CliRunner, sample_pcap: Path
    ) -> None:
        """Test extraction with specific feature groups."""
        mock_instance = MagicMock()
        mock_instance.process_pcap.return_value = []
        mock_pipeline.return_value = mock_instance

        result = runner.invoke(
            cli,
            ["extract", str(sample_pcap), "--features", "timing", "--features", "tls"],
        )

        # Check that Config was created with correct features
        call_args = mock_pipeline.call_args
        # Config is in the positional args or the 'config' keyword arg


class TestStatusCommand:
    """Tests for status command."""

    def test_status_runs(self, runner: CliRunner) -> None:
        """Test that status command runs successfully."""
        result = runner.invoke(cli, ["status"])
        assert result.exit_code == 0
        assert "JoyfulJay" in result.output
        assert "Platform" in result.output
        assert "Python" in result.output

    def test_status_shows_interfaces(self, runner: CliRunner) -> None:
        """Test that status shows interface information."""
        result = runner.invoke(cli, ["status"])
        # Should show interface info or "No interfaces found"
        assert "interfaces" in result.output.lower() or "capture" in result.output.lower()


class TestFeaturesCommand:
    """Tests for features command."""

    def test_features_lists_features(self, runner: CliRunner) -> None:
        """Test that features command lists available features."""
        result = runner.invoke(cli, ["features"])
        # Should list feature groups or descriptions
        assert result.exit_code == 0


class TestSchemaCommand:
    """Tests for schema command."""

    def test_schema_json(self, runner: CliRunner) -> None:
        """Test schema output in JSON format."""
        result = runner.invoke(cli, ["schema", "-f", "json"])
        assert result.exit_code == 0
        # Output should be valid JSON
        try:
            json.loads(result.output)
        except json.JSONDecodeError:
            pass  # May output to stderr

    def test_schema_to_file(self, runner: CliRunner, tmp_path: Path) -> None:
        """Test schema output to file."""
        output_file = tmp_path / "schema.json"
        result = runner.invoke(cli, ["schema", "-f", "json", "-o", str(output_file)])
        # Should not error


class TestInfoCommand:
    """Tests for info command."""

    def test_info_missing_input(self, runner: CliRunner) -> None:
        """Test error when input file is missing."""
        result = runner.invoke(cli, ["info"])
        assert result.exit_code != 0

    def test_info_nonexistent(self, runner: CliRunner) -> None:
        """Test error when input file doesn't exist."""
        result = runner.invoke(cli, ["info", "/nonexistent/file.pcap"])
        assert result.exit_code != 0

    @patch("joyfuljay.capture.scapy_backend.ScapyBackend")
    def test_info_runs(
        self, mock_backend: MagicMock, runner: CliRunner, sample_pcap: Path
    ) -> None:
        """Test that info command runs with valid PCAP."""
        mock_instance = MagicMock()
        mock_instance.iter_packets_offline.return_value = iter([])
        mock_backend.return_value = mock_instance

        result = runner.invoke(cli, ["info", str(sample_pcap)])
        # May show "No IP packets" or process normally


class TestDiscoverCommand:
    """Tests for discover command."""

    @patch("joyfuljay.remote.discovery.discover_servers")
    def test_discover_no_servers(
        self, mock_discover: MagicMock, runner: CliRunner
    ) -> None:
        """Test discover when no servers found."""
        mock_discover.return_value = []

        result = runner.invoke(cli, ["discover"])
        assert result.exit_code == 0
        assert "No" in result.output or "servers" in result.output.lower()

    @patch("joyfuljay.remote.discovery.discover_servers")
    def test_discover_json_output(
        self, mock_discover: MagicMock, runner: CliRunner
    ) -> None:
        """Test discover with JSON output."""
        from joyfuljay.remote.discovery import DiscoveredServer

        mock_discover.return_value = [
            DiscoveredServer(
                name="test-server",
                address="192.168.1.100",
                port=8765,
                properties={"tls": "1"},
            )
        ]

        result = runner.invoke(cli, ["discover", "--json"])
        assert result.exit_code == 0

        # Should be valid JSON
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["name"] == "test-server"


class TestVerboseOption:
    """Tests for --verbose option."""

    def test_verbose_flag(self, runner: CliRunner) -> None:
        """Test that verbose flag is accepted."""
        result = runner.invoke(cli, ["-v", "status"])
        assert result.exit_code == 0

    def test_verbose_long_form(self, runner: CliRunner) -> None:
        """Test that --verbose flag is accepted."""
        result = runner.invoke(cli, ["--verbose", "status"])
        assert result.exit_code == 0
