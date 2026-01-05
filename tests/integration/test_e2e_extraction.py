"""End-to-end feature extraction tests."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from joyfuljay import Config, Pipeline, extract


class TestEndToEndExtraction:
    """End-to-end tests for feature extraction pipeline."""

    @pytest.fixture
    def config(self) -> Config:
        """Create a test configuration."""
        return Config(
            flow_timeout=60.0,
            features=["all"],
        )

    @pytest.fixture
    def minimal_config(self) -> Config:
        """Create a minimal configuration for fast testing."""
        return Config(
            flow_timeout=10.0,
            features=["flow_meta", "timing", "size"],
        )

    def test_pipeline_creation(self, config: Config) -> None:
        """Test Pipeline can be created with config."""
        pipeline = Pipeline(config)
        assert pipeline is not None
        assert pipeline.config == config

    def test_pipeline_default_config(self) -> None:
        """Test Pipeline can be created without config."""
        pipeline = Pipeline()
        assert pipeline is not None
        assert pipeline.config is not None

    def test_pipeline_extractors_initialized(self, config: Config) -> None:
        """Test that extractors are properly initialized."""
        pipeline = Pipeline(config)
        # Pipeline should have extractors registered
        assert hasattr(pipeline, "extractors")
        assert len(pipeline.extractors) > 0

    def test_extract_function_exists(self) -> None:
        """Test that extract convenience function exists."""
        assert callable(extract)

    def test_pipeline_context_manager(self, config: Config) -> None:
        """Test Pipeline can be used as context manager."""
        with Pipeline(config) as pipeline:
            assert pipeline is not None
            # Pipeline should work normally in context

    def test_config_serialization(self, config: Config) -> None:
        """Test config can be serialized and deserialized."""
        config_dict = config.to_dict()
        assert isinstance(config_dict, dict)
        assert "flow_timeout" in config_dict

        restored = Config.from_dict(config_dict)
        assert restored.flow_timeout == config.flow_timeout

    def test_config_json_roundtrip(self, config: Config) -> None:
        """Test config JSON serialization roundtrip."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            config.to_json(f.name)

            restored = Config.from_file(f.name)
            assert restored.flow_timeout == config.flow_timeout

            Path(f.name).unlink()

    def test_pipeline_feature_names(self, config: Config) -> None:
        """Test that pipeline can report feature names."""
        pipeline = Pipeline(config)

        # Collect feature names from all extractors
        all_features = set()
        for extractor in pipeline.extractors:
            all_features.update(extractor.feature_names)

        assert len(all_features) > 0


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_invalid_flow_timeout(self) -> None:
        """Test that negative flow timeout raises error."""
        with pytest.raises(ValueError):
            Config(flow_timeout=-1.0)

    def test_invalid_sequence_length(self) -> None:
        """Test that invalid sequence length raises error."""
        with pytest.raises(ValueError):
            Config(max_sequence_length=0)

    def test_invalid_burst_threshold(self) -> None:
        """Test that negative burst threshold raises error."""
        with pytest.raises(ValueError):
            Config(burst_threshold_ms=-50.0)

    def test_valid_feature_groups(self) -> None:
        """Test that valid feature groups are accepted."""
        config = Config(features=["timing", "size", "tls"])
        assert "timing" in config.features


class TestOutputFormats:
    """Tests for output format handling."""

    def test_output_format_dataframe(self) -> None:
        """Test DataFrame output format."""
        from joyfuljay.output.formats import to_dataframe

        features = [
            {"feature1": 1.0, "feature2": "test"},
            {"feature1": 2.0, "feature2": "test2"},
        ]

        df = to_dataframe(features)
        assert len(df) == 2
        assert "feature1" in df.columns
        assert "feature2" in df.columns

    def test_output_format_numpy(self) -> None:
        """Test NumPy output format."""
        from joyfuljay.output.formats import to_numpy

        features = [
            {"feature1": 1.0, "feature2": 2.0},
            {"feature1": 3.0, "feature2": 4.0},
        ]

        arr, names = to_numpy(features)
        assert arr.shape[0] == 2
        assert len(names) == 2

    def test_csv_output(self) -> None:
        """Test CSV output."""
        from joyfuljay.output.formats import to_csv
        import tempfile

        features = [
            {"feature1": 1.0, "feature2": "test"},
            {"feature1": 2.0, "feature2": "test2"},
        ]

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            to_csv(features, f.name)

            # Verify file was created
            assert Path(f.name).exists()
            assert Path(f.name).stat().st_size > 0

            Path(f.name).unlink()

    def test_json_output(self) -> None:
        """Test JSON output."""
        from joyfuljay.output.formats import to_json
        import tempfile
        import json

        features = [
            {"feature1": 1.0, "feature2": "test"},
            {"feature1": 2.0, "feature2": "test2"},
        ]

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            to_json(features, f.name)

            # Verify file contents
            with open(f.name) as rf:
                content = rf.read()
                # Should be valid JSON lines
                lines = content.strip().split("\n")
                for line in lines:
                    json.loads(line)  # Should not raise

            Path(f.name).unlink()


class TestStreamingWriter:
    """Tests for streaming output."""

    def test_streaming_csv_writer(self) -> None:
        """Test streaming CSV writer."""
        from joyfuljay.output.formats import StreamingWriter
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            with StreamingWriter(f.name, format="csv") as writer:
                writer.write({"a": 1, "b": 2})
                writer.write({"a": 3, "b": 4})

            # Verify output
            content = Path(f.name).read_text()
            assert "a" in content
            assert "1" in content

            Path(f.name).unlink()

    def test_streaming_jsonl_writer(self) -> None:
        """Test streaming JSON Lines writer."""
        from joyfuljay.output.formats import StreamingWriter
        import tempfile
        import json

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            with StreamingWriter(f.name, format="jsonl") as writer:
                writer.write({"a": 1, "b": 2})
                writer.write({"a": 3, "b": 4})

            # Verify output
            lines = Path(f.name).read_text().strip().split("\n")
            assert len(lines) == 2
            assert json.loads(lines[0]) == {"a": 1, "b": 2}

            Path(f.name).unlink()
