"""Main processing pipeline for feature extraction."""

from __future__ import annotations

import logging
import multiprocessing
import os
import random
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any, Iterator, Literal, cast, overload

import pandas as pd

from ..analysis.connection_graph import ConnectionGraph
from ..capture.scapy_backend import ScapyBackend
from ..extractors.connection import ConnectionExtractor
from ..extractors.dns import DNSExtractor
from ..extractors.entropy import EntropyExtractor
from ..extractors.fingerprint import FingerprintExtractor
from ..extractors.flow_meta import FlowMetaExtractor
from ..extractors.icmp import ICMPExtractor
from ..extractors.ip_extended import IPExtendedExtractor
from ..extractors.ipv6_options import IPv6OptionsExtractor
from ..extractors.mac import MACExtractor
from ..extractors.padding import PaddingExtractor
from ..extractors.quic import QUICExtractor
from ..extractors.size import SizeExtractor
from ..extractors.ssh import SSHExtractor
from ..extractors.tcp import TCPExtractor
from ..extractors.tcp_fingerprint import TCPFingerprintExtractor
from ..extractors.tcp_mptcp import MPTCPExtractor
from ..extractors.tcp_options import TCPOptionsExtractor
from ..extractors.tcp_rtt import TCPRTTExtractor
from ..extractors.tcp_sequence import TCPSequenceExtractor
from ..extractors.tcp_window import TCPWindowExtractor
from ..extractors.timing import TimingExtractor
from ..extractors.tls import TLSExtractor
from ..output.formats import to_dataframe, to_numpy
from .config import Config, FeatureGroup
from .flow import FlowTable

if TYPE_CHECKING:
    import numpy as np

    from ..capture.base import CaptureBackend
    from ..extractors.base import FeatureExtractor
    from ..monitoring.base import MetricsSink
    from .flow import Flow
    from .packet import Packet

logger = logging.getLogger(__name__)


class Pipeline:
    """Main pipeline for extracting features from network traffic.

    The pipeline coordinates:
    - Packet capture (via backends)
    - Flow assembly (via FlowTable)
    - Feature extraction (via extractors)
    - Output formatting

    Example:
        >>> import joyfuljay as jj
        >>> config = jj.Config(flow_timeout=30.0)
        >>> pipeline = jj.Pipeline(config)
        >>> features = pipeline.process_pcap("capture.pcap")
    """

    def __init__(
        self,
        config: Config | None = None,
        backend: CaptureBackend | None = None,
        metrics: MetricsSink | None = None,
    ) -> None:
        """Initialize the feature pipeline.

        Args:
            config: Configuration options. Uses defaults if None.
            backend: Capture backend. Uses ScapyBackend if None.
            metrics: Optional metrics sink for monitoring.
        """
        self.config = config or Config()
        self.backend = backend or ScapyBackend(
            store_raw_payload=self._needs_raw_payload(),
        )
        self.metrics = metrics
        self.flow_table = FlowTable(
            timeout=self.config.flow_timeout,
            max_flows=self.config.max_concurrent_flows,
            eviction_strategy=self.config.flow_eviction_strategy,
            terminate_on_fin_rst=self.config.terminate_on_fin_rst,
        )
        self.extractors = self._init_extractors()
        self._connection_extractor = self._init_connection_extractor()

    def __enter__(self) -> Pipeline:
        """Enter context manager.

        Returns:
            Self for use in with statements.
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Exit context manager, cleanup resources.

        Stops any active capture and clears flow state.

        Args:
            exc_type: Exception type if an exception was raised.
            exc_val: Exception value if an exception was raised.
            exc_tb: Exception traceback if an exception was raised.
        """
        self.close()

    def close(self) -> None:
        """Clean up pipeline resources.

        Stops the backend and clears the flow table.
        """
        if self.backend:
            self.backend.stop()
        self.flow_table.flush_all()

    def _record_packet(self, packet: Packet) -> None:
        """Record packet-level metrics if enabled."""
        if self.metrics:
            self.metrics.observe_packet(packet)
            self.metrics.set_active_flows(self.flow_table.active_flow_count)

    def _record_flow(self, flow: Flow, reason: str) -> None:
        """Record flow-level metrics if enabled."""
        if self.metrics:
            self.metrics.observe_flow(flow, reason)
            self.metrics.set_active_flows(self.flow_table.active_flow_count)

    def _record_error(self, stage: str, error: Exception | None = None) -> None:
        """Record error metrics if enabled."""
        if self.metrics:
            self.metrics.observe_error(stage, error)

    def _record_processing_time(self, mode: str, seconds: float) -> None:
        """Record processing duration metrics if enabled."""
        if self.metrics:
            self.metrics.observe_processing_time(mode, seconds)

    def _should_sample_packet(self) -> bool:
        """Check if a packet should be sampled based on sampling_rate.

        Returns:
            True if the packet should be processed, False if it should be skipped.
        """
        if self.config.sampling_rate is None:
            return True
        return random.random() < self.config.sampling_rate

    def _needs_raw_payload(self) -> bool:
        """Check if any enabled feature requires raw payload access."""
        # TLS, QUIC, SSH, DNS, and entropy features need raw payload
        return any(
            self.config.should_extract(group)
            for group in [
                FeatureGroup.TLS,
                FeatureGroup.QUIC,
                FeatureGroup.SSH,
                FeatureGroup.DNS,
                FeatureGroup.ENTROPY,
            ]
        )

    def _init_extractors(self) -> list[FeatureExtractor]:
        """Initialize feature extractors based on configuration."""
        extractors: list[FeatureExtractor] = []

        if self.config.should_extract(FeatureGroup.FLOW_META):
            extractors.append(
                FlowMetaExtractor(
                    include_ips=self.config.include_ip_addresses,
                    include_ports=self.config.include_ports,
                    anonymize_ips=self.config.anonymize_ips,
                    anonymization_salt=self.config.anonymization_salt,
                    include_flow_id=self.config.include_flow_id,
                )
            )

        if self.config.should_extract(FeatureGroup.TIMING):
            extractors.append(
                TimingExtractor(
                    include_sequences=self.config.include_raw_sequences,
                    max_sequence_length=self.config.max_sequence_length,
                    burst_threshold_ms=self.config.burst_threshold_ms,
                    include_splt=self.config.include_splt,
                )
            )

        if self.config.should_extract(FeatureGroup.SIZE):
            extractors.append(
                SizeExtractor(
                    include_sequences=self.config.include_raw_sequences,
                    max_sequence_length=self.config.max_sequence_length,
                )
            )

        if self.config.should_extract(FeatureGroup.TCP):
            extractors.append(TCPExtractor())

        if self.config.should_extract(FeatureGroup.TLS):
            extractors.append(TLSExtractor())

        if self.config.should_extract(FeatureGroup.QUIC):
            extractors.append(QUICExtractor())

        if self.config.should_extract(FeatureGroup.SSH):
            extractors.append(SSHExtractor())

        if self.config.should_extract(FeatureGroup.DNS):
            extractors.append(DNSExtractor())

        if self.config.should_extract(FeatureGroup.PADDING):
            extractors.append(PaddingExtractor())

        if self.config.should_extract(FeatureGroup.FINGERPRINT):
            extractors.append(FingerprintExtractor())

        if self.config.should_extract(FeatureGroup.ENTROPY):
            extractors.append(
                EntropyExtractor(sample_size=self.config.entropy_sample_bytes)
            )

        # Tranalyzer-compatible extractors (#44-#58)
        if self.config.should_extract(FeatureGroup.MAC):
            extractors.append(MACExtractor())

        if self.config.should_extract(FeatureGroup.IP_EXTENDED):
            extractors.append(IPExtendedExtractor())

        if self.config.should_extract(FeatureGroup.IPV6_OPTIONS):
            extractors.append(IPv6OptionsExtractor())

        if self.config.should_extract(FeatureGroup.TCP_SEQUENCE):
            extractors.append(TCPSequenceExtractor())

        if self.config.should_extract(FeatureGroup.TCP_WINDOW):
            extractors.append(TCPWindowExtractor())

        if self.config.should_extract(FeatureGroup.TCP_OPTIONS):
            extractors.append(TCPOptionsExtractor())

        if self.config.should_extract(FeatureGroup.TCP_MPTCP):
            extractors.append(MPTCPExtractor())

        if self.config.should_extract(FeatureGroup.TCP_RTT):
            extractors.append(TCPRTTExtractor())

        if self.config.should_extract(FeatureGroup.TCP_FINGERPRINT):
            extractors.append(TCPFingerprintExtractor())

        if self.config.should_extract(FeatureGroup.ICMP):
            extractors.append(ICMPExtractor())

        return extractors

    def _init_connection_extractor(self) -> ConnectionExtractor | None:
        """Initialize connection extractor if CONNECTION features are enabled.

        The connection extractor is handled separately because it requires
        a pre-built graph from all flows before extraction can occur.

        Returns:
            ConnectionExtractor instance or None if not enabled.
        """
        if not self.config.should_extract(FeatureGroup.CONNECTION):
            return None

        return ConnectionExtractor(
            include_graph_metrics=self.config.connection_include_graph_metrics,
            include_temporal=self.config.connection_include_temporal,
            use_ports=self.config.connection_use_ports,
            community_algorithm=self.config.connection_community_algorithm,
        )

    def process_pcap(
        self,
        path: str,
        output_format: str = "dataframe",
    ) -> pd.DataFrame | np.ndarray | list[dict[str, Any]]:
        """Process a PCAP file and extract features.

        Args:
            path: Path to the PCAP file.
            output_format: Output format ("dataframe", "numpy", "dict").

        Returns:
            Features in the requested format.
        """
        # If connection features are enabled, use two-phase processing
        if self._connection_extractor is not None:
            return self._process_pcap_with_connection(path, output_format)

        # Standard single-phase processing
        features_list: list[dict[str, Any]] = []
        packet_count = 0
        flow_count = 0

        logger.info(f"Processing PCAP: {path}")
        start_time = time.time()

        # Process packets
        for packet in self.backend.iter_packets_offline(path):
            packet_count += 1

            # Apply sampling if configured
            if not self._should_sample_packet():
                continue
            self._record_packet(packet)
            self._record_packet(packet)

            # Add to flow table
            result = self.flow_table.add_packet(packet)
            if result is not None:
                # Handle both single flow and list of flows (eviction case)
                flows = result if isinstance(result, list) else [result]
                for flow in flows:
                    features = self._extract_features(flow)
                    features_list.append(features)
                    flow_count += 1
                    reason = "evicted" if isinstance(result, list) else "completed"
                    self._record_flow(flow, reason)

            # Periodic expiration check
            if packet_count % 10000 == 0:
                expired = self.flow_table.expire_flows(packet.timestamp)
                for flow in expired:
                    features = self._extract_features(flow)
                    features_list.append(features)
                    flow_count += 1
                    self._record_flow(flow, "expired")

        # Flush remaining flows
        remaining = self.flow_table.flush_all()
        for flow in remaining:
            features = self._extract_features(flow)
            features_list.append(features)
            flow_count += 1
            self._record_flow(flow, "flushed")

        elapsed = time.time() - start_time
        self._record_processing_time("pcap", elapsed)
        logger.info(
            f"Processed {packet_count} packets, {flow_count} flows in {elapsed:.2f}s"
        )

        return self._format_output(features_list, output_format)

    def _process_pcap_with_connection(
        self,
        path: str,
        output_format: str,
    ) -> pd.DataFrame | np.ndarray | list[dict[str, Any]]:
        """Process a PCAP file with connection graph analysis (two-phase).

        Phase 1: Collect all flows and build connection graph
        Phase 2: Extract features including connection metrics

        Args:
            path: Path to the PCAP file.
            output_format: Output format ("dataframe", "numpy", "dict").

        Returns:
            Features in the requested format.
        """
        from .flow import Flow

        collected_flows: list[Flow] = []
        packet_count = 0

        logger.info(f"Processing PCAP (with connection analysis): {path}")
        start_time = time.time()

        # Phase 1: Collect all flows
        for packet in self.backend.iter_packets_offline(path):
            packet_count += 1

            # Apply sampling if configured
            if not self._should_sample_packet():
                continue

            # Add to flow table
            result = self.flow_table.add_packet(packet)
            if result is not None:
                flows = result if isinstance(result, list) else [result]
                collected_flows.extend(flows)
                reason = "evicted" if isinstance(result, list) else "completed"
                for flow in flows:
                    self._record_flow(flow, reason)

            # Periodic expiration check
            if packet_count % 10000 == 0:
                expired = self.flow_table.expire_flows(packet.timestamp)
                collected_flows.extend(expired)
                for flow in expired:
                    self._record_flow(flow, "expired")

        # Flush remaining flows
        remaining = self.flow_table.flush_all()
        collected_flows.extend(remaining)
        for flow in remaining:
            self._record_flow(flow, "flushed")

        flow_count = len(collected_flows)
        phase1_time = time.time() - start_time
        logger.info(f"Phase 1: Collected {flow_count} flows in {phase1_time:.2f}s")

        # Phase 2: Build connection graph and extract features
        graph_start = time.time()

        # Build connection graph from all flows
        graph = ConnectionGraph(
            use_ports=self.config.connection_use_ports,
            include_graph_metrics=self.config.connection_include_graph_metrics,
            include_temporal=self.config.connection_include_temporal,
            community_algorithm=self.config.connection_community_algorithm,
        )
        for flow in collected_flows:
            graph.add_flow(flow)

        # Build NetworkX graph if graph metrics are needed
        if self.config.connection_include_graph_metrics:
            graph.build_graph()

        # Inject graph into connection extractor
        assert self._connection_extractor is not None
        self._connection_extractor.set_graph(graph)

        graph_time = time.time() - graph_start
        logger.info(f"Phase 2a: Built connection graph in {graph_time:.2f}s")

        # Extract features for all flows
        extract_start = time.time()
        features_list: list[dict[str, Any]] = []

        for flow in collected_flows:
            # Extract standard features
            features = self._extract_features(flow)

            # Add connection features
            try:
                conn_features = self._connection_extractor.extract(flow)
                features.update(conn_features)
            except Exception as e:
                logger.warning(f"Connection extractor failed: {e}")
                self._record_error("connection_extractor", e)
                for name in self._connection_extractor.feature_names:
                    if name not in features:
                        features[name] = None

            features_list.append(features)

        extract_time = time.time() - extract_start
        total_time = time.time() - start_time
        self._record_processing_time("pcap_connection", total_time)
        logger.info(
            f"Phase 2b: Extracted features in {extract_time:.2f}s"
        )
        logger.info(
            f"Processed {packet_count} packets, {flow_count} flows in {total_time:.2f}s"
        )

        return self._format_output(features_list, output_format)

    @overload
    def process_live(
        self,
        interface: str,
        duration: float | None = None,
        output_format: Literal["stream"] = "stream",
        save_pcap: str | None = None,
        pid: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        ...

    @overload
    def process_live(
        self,
        interface: str,
        duration: float | None = None,
        output_format: Literal["dataframe"] = "dataframe",
        save_pcap: str | None = None,
        pid: int | None = None,
    ) -> pd.DataFrame:
        ...

    def process_live(
        self,
        interface: str,
        duration: float | None = None,
        output_format: str = "dataframe",
        save_pcap: str | None = None,
        pid: int | None = None,
    ) -> pd.DataFrame | Iterator[dict[str, Any]]:
        """Process live network traffic.

        Args:
            interface: Network interface name.
            duration: Capture duration in seconds. None for continuous.
            output_format: Output format ("dataframe" or "stream").
            save_pcap: Optional path to save captured packets to a PCAP file.
            pid: Optional process ID to filter traffic by.

        Returns:
            Features as DataFrame or iterator of feature dicts.
        """
        if output_format == "stream":
            return self._process_live_stream(interface, duration, save_pcap, pid)
        else:
            return self._process_live_batch(interface, duration, save_pcap, pid)

    def _process_live_stream(
        self,
        interface: str,
        duration: float | None = None,
        save_pcap: str | None = None,
        pid: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Process live traffic in streaming mode.

        Yields feature dicts as flows complete.

        Note: Connection features are not available in streaming mode
        because they require all flows to be collected before graph
        analysis can be performed.
        """
        if self._connection_extractor is not None:
            logger.warning(
                "Connection features are not available in streaming mode. "
                "Use batch mode (process_live with output_format='dataframe') "
                "to get connection features."
            )

        start_time = time.time()
        last_expire = start_time

        for packet in self.backend.iter_packets_live(
            interface,
            bpf_filter=self.config.bpf_filter,
            save_pcap=save_pcap,
            pid=pid,
        ):
            # Check duration limit
            if duration and (time.time() - start_time) >= duration:
                break

            # Apply sampling if configured
            if not self._should_sample_packet():
                continue
            self._record_packet(packet)

            # Add to flow table
            result = self.flow_table.add_packet(packet)
            if result is not None:
                flows = result if isinstance(result, list) else [result]
                for flow in flows:
                    yield self._extract_features(flow)
                    reason = "evicted" if isinstance(result, list) else "completed"
                    self._record_flow(flow, reason)

            # Periodic expiration
            current_time = time.time()
            if current_time - last_expire > 5.0:
                expired = self.flow_table.expire_flows(current_time)
                for flow in expired:
                    yield self._extract_features(flow)
                    self._record_flow(flow, "expired")
                last_expire = current_time

        # Flush remaining
        self.backend.stop()
        for flow in self.flow_table.flush_all():
            yield self._extract_features(flow)
            self._record_flow(flow, "flushed")
        elapsed = time.time() - start_time
        self._record_processing_time("live", elapsed)

    def _process_live_batch(
        self,
        interface: str,
        duration: float | None = None,
        save_pcap: str | None = None,
        pid: int | None = None,
    ) -> pd.DataFrame:
        """Process live traffic and return DataFrame."""
        features_list = list(self._process_live_stream(interface, duration, save_pcap, pid))
        return to_dataframe(features_list)

    def _extract_features(self, flow: Flow) -> dict[str, Any]:
        """Run all extractors on a completed flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of all extracted features (filtered if specific_features is set).
        """
        features: dict[str, Any] = {}

        for extractor in self.extractors:
            try:
                extractor_features = extractor.extract(flow)
                features.update(extractor_features)
            except Exception as e:
                logger.warning(f"Extractor {extractor.name} failed: {e}")
                self._record_error("extractor", e)
                # Add placeholder values for failed extractor
                for name in extractor.feature_names:
                    if name not in features:
                        features[name] = None

        # Apply bidirectional splitting if configured
        if self.config.bidirectional_split:
            from ..utils.bidir_split import split_features_bidirectional
            features = split_features_bidirectional(features)

        # Apply specific feature filtering if configured
        return self.config.filter_features(features)

    def _format_output(
        self,
        features_list: list[dict[str, Any]],
        output_format: str,
    ) -> pd.DataFrame | np.ndarray | list[dict[str, Any]]:
        """Format features according to requested output format.

        Args:
            features_list: List of feature dictionaries.
            output_format: Desired output format.

        Returns:
            Features in the requested format.
        """
        if output_format == "dict":
            return features_list
        elif output_format == "numpy":
            array, _ = to_numpy(features_list)
            return array
        else:
            return to_dataframe(features_list)

    def get_feature_names(self) -> list[str]:
        """Get all feature names that will be extracted.

        Returns:
            List of feature name strings.
        """
        names: list[str] = []
        for extractor in self.extractors:
            names.extend(extractor.feature_names)
        # Add connection features if enabled
        if self._connection_extractor is not None:
            names.extend(self._connection_extractor.feature_names)
        return names

    def process_pcap_streaming(
        self,
        path: str,
        output_path: str,
        output_format: str = "csv",
    ) -> int:
        """Process a PCAP file with streaming output to avoid memory issues.

        This method writes features to disk incrementally as flows complete,
        avoiding the need to hold all features in memory. Ideal for large
        captures with millions of flows.

        Note: Connection features are not available in streaming mode
        because they require all flows to be collected before graph
        analysis can be performed.

        Args:
            path: Path to the PCAP file.
            output_path: Path to the output file.
            output_format: Output format ("csv", "jsonl", "parquet").

        Returns:
            Number of flows processed.
        """
        from ..output.formats import StreamingWriter

        if self._connection_extractor is not None:
            logger.warning(
                "Connection features are not available in streaming mode. "
                "Use process_pcap() for batch processing with connection features."
            )

        packet_count = 0
        flow_count = 0

        logger.info(f"Processing PCAP (streaming): {path}")
        start_time = time.time()

        with StreamingWriter(output_path, format=output_format) as writer:
            # Process packets
            for packet in self.backend.iter_packets_offline(path):
                packet_count += 1

                # Apply sampling if configured
                if not self._should_sample_packet():
                    continue
                self._record_packet(packet)

                # Add to flow table
                result = self.flow_table.add_packet(packet)
                if result is not None:
                    flows = result if isinstance(result, list) else [result]
                    for flow in flows:
                        features = self._extract_features(flow)
                        writer.write(features)
                        flow_count += 1
                        reason = "evicted" if isinstance(result, list) else "completed"
                        self._record_flow(flow, reason)

                # Periodic expiration check
                if packet_count % 10000 == 0:
                    expired = self.flow_table.expire_flows(packet.timestamp)
                    for flow in expired:
                        features = self._extract_features(flow)
                        writer.write(features)
                        flow_count += 1
                        self._record_flow(flow, "expired")

            # Flush remaining flows
            remaining = self.flow_table.flush_all()
            for flow in remaining:
                features = self._extract_features(flow)
                writer.write(features)
                flow_count += 1
                self._record_flow(flow, "flushed")

        elapsed = time.time() - start_time
        self._record_processing_time("pcap_stream", elapsed)
        logger.info(
            f"Processed {packet_count} packets, {flow_count} flows in {elapsed:.2f}s (streaming)"
        )

        return flow_count

    def iter_features(self, path: str) -> Iterator[dict[str, Any]]:
        """Iterate over features from a PCAP file without loading all into memory.

        This is a generator that yields feature dictionaries one at a time,
        useful for custom streaming or incremental processing.

        Note: Connection features are not available in streaming mode
        because they require all flows to be collected before graph
        analysis can be performed.

        Args:
            path: Path to the PCAP file.

        Yields:
            Feature dictionaries for each completed flow.
        """
        if self._connection_extractor is not None:
            logger.warning(
                "Connection features are not available in streaming mode. "
                "Use process_pcap() for batch processing with connection features."
            )

        packet_count = 0
        start_time = time.time()

        try:
            for packet in self.backend.iter_packets_offline(path):
                packet_count += 1

                # Apply sampling if configured
                if not self._should_sample_packet():
                    continue
                self._record_packet(packet)

                # Add to flow table
                result = self.flow_table.add_packet(packet)
                if result is not None:
                    flows = result if isinstance(result, list) else [result]
                    for flow in flows:
                        yield self._extract_features(flow)
                        reason = "evicted" if isinstance(result, list) else "completed"
                        self._record_flow(flow, reason)

                # Periodic expiration check
                if packet_count % 10000 == 0:
                    expired = self.flow_table.expire_flows(packet.timestamp)
                    for flow in expired:
                        yield self._extract_features(flow)
                        self._record_flow(flow, "expired")

            # Flush remaining flows
            for flow in self.flow_table.flush_all():
                yield self._extract_features(flow)
                self._record_flow(flow, "flushed")
        finally:
            elapsed = time.time() - start_time
            self._record_processing_time("pcap_iter", elapsed)

    def process_pcaps_batch(
        self,
        paths: list[str],
        output_format: str = "dataframe",
    ) -> pd.DataFrame | np.ndarray | list[dict[str, Any]]:
        """Process multiple PCAP files, optionally in parallel.

        Args:
            paths: List of paths to PCAP files.
            output_format: Output format ("dataframe", "numpy", "dict").

        Returns:
            Features in the requested format.
        """
        if not paths:
            return self._format_output([], output_format)

        num_workers = self.config.num_workers

        # Use multiprocessing if workers > 1 and multiple files
        if num_workers > 1 and len(paths) > 1:
            return self._process_batch_parallel(paths, output_format, num_workers)
        else:
            return self._process_batch_sequential(paths, output_format)

    def _process_batch_sequential(
        self,
        paths: list[str],
        output_format: str,
    ) -> pd.DataFrame | np.ndarray | list[dict[str, Any]]:
        """Process PCAP files sequentially."""
        all_features: list[dict[str, Any]] = []

        for path in paths:
            logger.info(f"Processing: {path}")
            features_list = self.process_pcap(path, output_format="dict")
            if isinstance(features_list, list):
                all_features.extend(features_list)

        return self._format_output(all_features, output_format)

    def _process_batch_parallel(
        self,
        paths: list[str],
        output_format: str,
        num_workers: int,
    ) -> pd.DataFrame | np.ndarray | list[dict[str, Any]]:
        """Process PCAP files in parallel using multiprocessing.

        Args:
            paths: List of PCAP file paths.
            output_format: Output format.
            num_workers: Number of worker processes.

        Returns:
            Combined features from all files.
        """
        # Limit workers to CPU count
        max_workers = min(num_workers, multiprocessing.cpu_count(), len(paths))
        logger.info(f"Processing {len(paths)} files with {max_workers} workers")

        all_features: list[dict[str, Any]] = []

        # Use ProcessPoolExecutor for parallel processing
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_path = {
                executor.submit(_process_single_pcap, path, self.config): path
                for path in paths
            }

            # Collect results as they complete
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    features_list = future.result()
                    all_features.extend(features_list)
                    logger.info(f"Completed: {path} ({len(features_list)} flows)")
                except Exception as e:
                    logger.error(f"Error processing {path}: {e}")

        return self._format_output(all_features, output_format)


def _process_single_pcap(path: str, config: Config) -> list[dict[str, Any]]:
    """Process a single PCAP file (for use in multiprocessing).

    This function is defined at module level to be picklable for multiprocessing.

    Args:
        path: Path to the PCAP file.
        config: Configuration to use.

    Returns:
        List of feature dictionaries.
    """
    # Create a new pipeline for this process
    pipeline = Pipeline(config)
    result = pipeline.process_pcap(path, output_format="dict")

    if isinstance(result, list):
        return result
    return []


# Convenience functions for TensorFlow-style API
def extract(
    path: str,
    output_format: Literal["dataframe", "dict"] = "dataframe",
    **config_kwargs: Any,
) -> pd.DataFrame | list[dict[str, Any]]:
    """Extract features from a PCAP file.

    This is a convenience function for quick feature extraction.

    Args:
        path: Path to the PCAP file.
        output_format: Output format ("dataframe" or "dict").
        **config_kwargs: Additional configuration options passed to Config.

    Returns:
        Feature data in the requested format.

    Example:
        >>> import joyfuljay as jj
        >>> features = jj.extract("capture.pcap")
        >>> features = jj.extract("capture.pcap", flow_timeout=30)
    """
    config = Config(**config_kwargs)
    pipeline = Pipeline(config)
    return cast(
        pd.DataFrame | list[dict[str, Any]],
        pipeline.process_pcap(path, output_format=output_format),
    )


def extract_live(
    interface: str,
    duration: float | None = None,
    output_format: Literal["dataframe", "stream"] = "dataframe",
    **config_kwargs: Any,
) -> pd.DataFrame | Iterator[dict[str, Any]]:
    """Extract features from live network traffic.

    This is a convenience function for quick live capture.

    Args:
        interface: Network interface name (e.g., "eth0", "en0").
        duration: Capture duration in seconds. None for continuous capture.
        output_format: Output format ("dataframe" or "dict").
        **config_kwargs: Additional configuration options passed to Config.

    Returns:
        Feature data in the requested format.

    Example:
        >>> import joyfuljay as jj
        >>> features = jj.extract_live("eth0", duration=60)
    """
    config = Config(**config_kwargs)
    pipeline = Pipeline(config)
    return pipeline.process_live(interface, duration=duration, output_format=output_format)
