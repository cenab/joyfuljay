# Changelog

All notable changes to JoyfulJay will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-01-01

### Added

- Initial release of JoyfulJay
- Core feature extraction pipeline with streaming architecture
- Scapy-based capture backend for PCAP files and live capture
- Flow segmentation with bidirectional 5-tuple identification
- Feature extractors:
  - **Flow Metadata**: 5-tuple, duration, packet/byte counts, ratios
  - **Timing**: Inter-arrival times, burst metrics, burstiness index
  - **Size**: Packet length statistics, payload analysis, dominant size detection
  - **TLS**: Handshake parsing, JA3/JA3S fingerprints, SNI extraction
  - **QUIC**: Version detection, connection ID analysis
  - **Padding**: Constant size/rate detection, Tor cell detection
  - **Fingerprint**: Tor, VPN, and DoH traffic classification
- Multiple output formats: Pandas DataFrame, NumPy arrays, CSV, JSON
- Command-line interface (`jj`) with commands:
  - `extract`: Process PCAP files
  - `live`: Capture from network interfaces
  - `info`: Display PCAP file information
  - `features`: List available features
- Python API with high-level convenience functions
- Comprehensive type hints with mypy strict mode support
- GitHub Actions CI/CD pipeline

### Technical Details

- Python 3.10+ required
- Streaming PCAP processing (no full file loading)
- Configurable flow timeout and feature selection
- Modular extractor architecture for easy extension
