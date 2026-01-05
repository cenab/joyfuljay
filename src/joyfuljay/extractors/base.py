"""Abstract base class for feature extractors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..core.flow import Flow


class FeatureExtractor(ABC):
    """Abstract base class for feature extraction modules.

    Each extractor is responsible for computing a specific group
    of features from a completed flow. Extractors should be stateless
    and thread-safe.
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
            List of feature name strings.
        """

    @property
    def name(self) -> str:
        """Get the name of this extractor.

        Returns:
            Extractor name, defaults to class name.
        """
        return self.__class__.__name__

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
