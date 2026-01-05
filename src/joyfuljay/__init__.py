"""JoyfulJay - Encrypted Traffic Feature Extraction Library.

JoyfulJay extracts standardized, ML-ready features from encrypted network traffic.
It operates on PCAP files and live network interfaces, producing feature vectors
that capture timing, size, and protocol metadata patterns.

Example:
    >>> import joyfuljay as jj
    >>> features = jj.extract("capture.pcap")
    >>> print(features.shape)

TensorFlow-style usage:
    >>> import joyfuljay as jj
    >>> config = jj.Config(flow_timeout=30)
    >>> pipeline = jj.Pipeline(config)
    >>> features = pipeline.process_pcap("capture.pcap")

Submodule access:
    >>> import joyfuljay as jj
    >>> backend = jj.capture.ScapyBackend()
    >>> server = jj.remote.Server("eth0", port=8765)
"""

from __future__ import annotations

__version__ = "0.1.0"

# Core classes at top level (TensorFlow style)
from .core.config import Config, FeatureGroup
from .core.flow import Flow, FlowKey
from .core.packet import Packet
from .core.pipeline import Pipeline, extract, extract_live

# Submodules available as jj.capture, jj.extractors, etc.
from . import capture
from . import core
from . import extractors
from . import monitoring
from . import output
from . import remote
from . import utils

__all__ = [
    "__version__",
    "Config",
    "FeatureGroup",
    "Flow",
    "FlowKey",
    "Packet",
    "Pipeline",
    "extract",
    "extract_live",
    "capture",
    "core",
    "extractors",
    "monitoring",
    "output",
    "remote",
    "utils",
]
