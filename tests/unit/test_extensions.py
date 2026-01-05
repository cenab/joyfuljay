"""Tests for Cython extensions and pure Python fallbacks."""

import pytest
import numpy as np

from joyfuljay.extensions import (
    compute_statistics_fast,
    compute_interarrival_times_fast,
    compute_percentiles_fast,
    shannon_entropy_fast,
    byte_distribution_fast,
    character_class_counts_fast,
    is_cython_available,
    get_available_extensions,
)


class TestStatisticsExtension:
    """Tests for compute_statistics_fast."""

    def test_empty_list(self):
        """Empty input returns zero stats."""
        result = compute_statistics_fast([])
        assert result["count"] == 0
        assert result["mean"] == 0.0
        assert result["std"] == 0.0

    def test_single_value(self):
        """Single value returns that value for all stats."""
        result = compute_statistics_fast([5.0])
        assert result["count"] == 1
        assert result["min"] == 5.0
        assert result["max"] == 5.0
        assert result["mean"] == 5.0
        assert result["std"] == 0.0
        assert result["median"] == 5.0

    def test_known_values(self):
        """Test with known statistical values."""
        data = [1.0, 2.0, 3.0, 4.0, 5.0]
        result = compute_statistics_fast(data)

        assert result["count"] == 5
        assert result["min"] == 1.0
        assert result["max"] == 5.0
        assert result["mean"] == 3.0
        assert result["sum"] == 15.0
        assert result["median"] == 3.0

        # Standard deviation of [1,2,3,4,5] is sqrt(2) = 1.414...
        assert np.isclose(result["std"], np.sqrt(2), rtol=1e-5)

    def test_percentiles(self):
        """Test percentile calculations."""
        data = list(range(1, 101))  # 1 to 100
        result = compute_statistics_fast(data)

        assert np.isclose(result["p25"], 25.75, rtol=0.01)
        assert np.isclose(result["p75"], 75.25, rtol=0.01)
        assert np.isclose(result["p90"], 90.1, rtol=0.01)

    def test_large_dataset(self):
        """Test with a larger dataset."""
        data = list(np.random.uniform(0, 1000, 10000))
        result = compute_statistics_fast(data)

        assert result["count"] == 10000
        assert result["min"] >= 0
        assert result["max"] <= 1000
        # Mean should be close to 500 for uniform distribution
        assert 400 < result["mean"] < 600


class TestInterarrivalTimesExtension:
    """Tests for compute_interarrival_times_fast."""

    def test_empty_list(self):
        """Empty input returns empty list."""
        result = compute_interarrival_times_fast([])
        assert result == []

    def test_single_timestamp(self):
        """Single timestamp returns empty list."""
        result = compute_interarrival_times_fast([1.0])
        assert result == []

    def test_known_values(self):
        """Test with known timestamps."""
        timestamps = [0.0, 0.1, 0.3, 0.6, 1.0]
        result = compute_interarrival_times_fast(timestamps)

        assert len(result) == 4
        assert np.isclose(result[0], 0.1, rtol=1e-5)
        assert np.isclose(result[1], 0.2, rtol=1e-5)
        assert np.isclose(result[2], 0.3, rtol=1e-5)
        assert np.isclose(result[3], 0.4, rtol=1e-5)

    def test_uniform_spacing(self):
        """Uniformly spaced timestamps."""
        timestamps = [i * 0.5 for i in range(10)]
        result = compute_interarrival_times_fast(timestamps)

        assert len(result) == 9
        for iat in result:
            assert np.isclose(iat, 0.5, rtol=1e-5)


class TestPercentilesExtension:
    """Tests for compute_percentiles_fast."""

    def test_empty_list(self):
        """Empty input returns zero percentiles."""
        result = compute_percentiles_fast([], [25, 50, 75])
        assert result["p25"] == 0.0
        assert result["p50"] == 0.0
        assert result["p75"] == 0.0

    def test_known_percentiles(self):
        """Test with known data."""
        data = list(range(1, 101))
        result = compute_percentiles_fast(data, [25, 50, 75, 90])

        assert np.isclose(result["p50"], 50.5, rtol=0.01)
        assert result["p25"] < result["p50"] < result["p75"]


class TestEntropyExtension:
    """Tests for shannon_entropy_fast."""

    def test_empty_data(self):
        """Empty data returns zero entropy."""
        result = shannon_entropy_fast(b"")
        assert result == 0.0

    def test_single_byte(self):
        """Single byte returns zero entropy."""
        result = shannon_entropy_fast(b"A")
        assert result == 0.0

    def test_uniform_distribution(self):
        """All bytes appear once - maximum entropy."""
        data = bytes(range(256))
        result = shannon_entropy_fast(data)
        # Maximum entropy for 256 unique bytes is 8.0
        assert np.isclose(result, 8.0, rtol=1e-5)

    def test_all_same_bytes(self):
        """All same bytes - zero entropy."""
        result = shannon_entropy_fast(b"AAAAAAAAAA")
        assert result == 0.0

    def test_two_bytes_equal(self):
        """Two bytes with equal frequency."""
        result = shannon_entropy_fast(b"ABABABABAB")
        # Two symbols with equal probability: entropy = 1.0 bit
        assert np.isclose(result, 1.0, rtol=1e-5)

    def test_random_data_high_entropy(self):
        """Random data should have high entropy."""
        import random
        data = bytes(random.randint(0, 255) for _ in range(10000))
        result = shannon_entropy_fast(data)
        # Random data should have entropy close to 8
        assert result > 7.5


class TestByteDistributionExtension:
    """Tests for byte_distribution_fast."""

    def test_empty_data(self):
        """Empty data returns zero values."""
        result = byte_distribution_fast(b"")
        assert result["entropy"] == 0.0
        assert result["unique_bytes"] == 0
        assert result["uniformity"] == 0.0

    def test_single_byte(self):
        """Single byte type."""
        result = byte_distribution_fast(b"AAAAA")
        assert result["entropy"] == 0.0
        assert result["unique_bytes"] == 1
        assert result["most_common_byte"] == ord("A")
        assert result["most_common_count"] == 5

    def test_multiple_unique_bytes(self):
        """Multiple unique bytes."""
        result = byte_distribution_fast(b"AABBCC")
        assert result["unique_bytes"] == 3
        # Entropy of 3 symbols with equal probability
        assert np.isclose(result["entropy"], np.log2(3), rtol=1e-5)


class TestCharacterClassExtension:
    """Tests for character_class_counts_fast."""

    def test_empty_data(self):
        """Empty data returns zero counts."""
        result = character_class_counts_fast(b"")
        assert result["total"] == 0
        assert result["printable_count"] == 0
        assert result["null_count"] == 0
        assert result["high_byte_count"] == 0
        assert result["control_count"] == 0

    def test_printable_ascii(self):
        """Printable ASCII characters."""
        result = character_class_counts_fast(b"Hello World!")
        assert result["printable_count"] == 12
        assert result["null_count"] == 0
        assert result["high_byte_count"] == 0
        assert result["control_count"] == 0
        assert result["total"] == 12

    def test_null_bytes(self):
        """Null bytes."""
        result = character_class_counts_fast(b"\x00\x00\x00")
        assert result["null_count"] == 3
        assert result["printable_count"] == 0

    def test_high_bytes(self):
        """High bytes (>= 0x80)."""
        result = character_class_counts_fast(b"\x80\x90\xa0\xff")
        assert result["high_byte_count"] == 4
        assert result["printable_count"] == 0

    def test_control_characters(self):
        """Control characters (< 0x20, not whitespace)."""
        result = character_class_counts_fast(b"\x01\x02\x03")
        assert result["control_count"] == 3
        assert result["printable_count"] == 0

    def test_whitespace(self):
        """Whitespace characters (tab, newline, carriage return)."""
        result = character_class_counts_fast(b"\t\n\r")
        # Tab, newline, CR are counted as printable
        assert result["printable_count"] == 3
        assert result["control_count"] == 0

    def test_mixed_content(self):
        """Mixed content with all character classes."""
        data = b"Hello\x00\x01\xff\t"
        result = character_class_counts_fast(data)
        assert result["printable_count"] == 6  # 'Hello' + '\t'
        assert result["null_count"] == 1       # '\x00'
        assert result["control_count"] == 1    # '\x01'
        assert result["high_byte_count"] == 1  # '\xff'
        assert result["total"] == 9


class TestExtensionAvailability:
    """Tests for extension availability checking."""

    def test_is_cython_available(self):
        """Check that availability function works."""
        result = is_cython_available()
        assert isinstance(result, bool)

    def test_get_available_extensions(self):
        """Check that extension status dict works."""
        result = get_available_extensions()
        assert isinstance(result, dict)
        assert "fast_stats" in result
        assert "fast_entropy" in result
        assert isinstance(result["fast_stats"], bool)
        assert isinstance(result["fast_entropy"], bool)


class TestPythonFallbackConsistency:
    """Tests ensuring Cython and pure Python produce identical results."""

    def test_statistics_consistency(self):
        """Cython and Python statistics should match."""
        from joyfuljay.utils.stats import compute_statistics_dict

        data = [1.5, 2.5, 3.5, 4.5, 5.5, 10.0, 20.0]
        cy_result = compute_statistics_fast(data)
        py_result = compute_statistics_dict(data)

        for key in py_result:
            assert np.isclose(cy_result[key], py_result[key], rtol=1e-5), f"Mismatch in {key}"

    def test_entropy_consistency(self):
        """Cython and Python entropy should match."""
        from joyfuljay.utils.entropy import shannon_entropy_fallback

        data = b"Hello World! This is a test of entropy calculation."
        cy_result = shannon_entropy_fast(data)
        py_result = shannon_entropy_fallback(data)

        assert np.isclose(cy_result, py_result, rtol=1e-5)

    def test_byte_distribution_consistency(self):
        """Cython and Python byte distribution should match."""
        from joyfuljay.utils.entropy import byte_distribution_fallback

        import random
        data = bytes(random.randint(0, 255) for _ in range(1000))

        cy_result = byte_distribution_fast(data)
        py_result = byte_distribution_fallback(data)

        for key in py_result:
            if isinstance(py_result[key], float):
                assert np.isclose(cy_result[key], py_result[key], rtol=1e-5), f"Mismatch in {key}"
            else:
                assert cy_result[key] == py_result[key], f"Mismatch in {key}"

    def test_character_class_consistency(self):
        """Cython and Python character class counts should match."""
        from joyfuljay.utils.entropy import character_class_counts_fallback

        data = b"Hello\x00\x01\x02\x80\x90\xff\t\n\r World!"
        cy_result = character_class_counts_fast(data)
        py_result = character_class_counts_fallback(data)

        assert cy_result == py_result
