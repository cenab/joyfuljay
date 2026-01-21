"""Abstract base class for feature extractors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..core.flow import Flow
    from ..schema.registry import FeatureMeta


class FeatureExtractor(ABC):
    """Abstract base class for feature extraction modules.

    Each extractor is responsible for computing a specific group
    of features from a completed flow. Extractors should be stateless
    and thread-safe.

    Subclasses must implement:
        - extract(): Extract features from a flow
        - feature_names: List of raw feature names
        - extractor_id: Stable extractor identifier (e.g., "tls", "timing")
        - feature_meta(): Metadata for each feature
    """

    @abstractmethod
    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract features from a completed flow.

        Args:
            flow: The completed flow to extract features from.

        Returns:
            Dictionary mapping feature names to values.
        """

    @property
    @abstractmethod
    def feature_names(self) -> list[str]:
        """Get the list of feature names this extractor produces.

        Returns:
            List of feature name strings (without extractor prefix).
        """

    @property
    @abstractmethod
    def extractor_id(self) -> str:
        """Get the stable identifier for this extractor.

        This ID is used as a prefix for feature IDs (e.g., "tls" -> "tls.ja3_hash").

        Returns:
            Stable extractor identifier string.
        """

    @abstractmethod
    def feature_meta(self) -> dict[str, FeatureMeta]:
        """Get metadata for all features produced by this extractor.

        Returns:
            Dictionary mapping feature ID (with prefix) to FeatureMeta.
        """

    @property
    def name(self) -> str:
        """Get the name of this extractor.

        Returns:
            Extractor name, defaults to class name.
        """
        return self.__class__.__name__

    def feature_ids(self) -> list[str]:
        """Get stable feature IDs with extractor prefix.

        Returns:
            List of feature IDs in format "{extractor_id}.{feature_name}".
        """
        prefix = self.extractor_id
        return [f"{prefix}.{name}" for name in self.feature_names]

    def validate_features(self, features: dict[str, Any]) -> bool:
        """Validate that extracted features match expected names.

        Args:
            features: Dictionary of extracted features.

        Returns:
            True if all expected feature names are present.
        """
        expected = set(self.feature_names)
        actual = set(features.keys())
        return expected == actual
