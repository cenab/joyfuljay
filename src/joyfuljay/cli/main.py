"""Command-line interface for JoyfulJay."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import TextIO

import click

from .. import __version__
from ..core.config import Config
from ..core.pipeline import Pipeline
from ..output.formats import to_csv_stream, to_json_stream
from ..utils.progress import create_progress, is_rich_available

# ASCII art splash screen
SPLASH = r"""
   ▗▖ ▗▄▖▗▖  ▗▖▗▄▄▄▖▗▖ ▗▖▗▖      ▗▖ ▗▄▖▗▖  ▗▖
   ▐▌▐▌ ▐▌▝▚▞▘ ▐▌   ▐▌ ▐▌▐▌      ▐▌▐▌ ▐▌▝▚▞▘
   ▐▌▐▌ ▐▌ ▐▌  ▐▛▀▀▘▐▌ ▐▌▐▌      ▐▌▐▛▀▜▌ ▐▌
▗▄▄▞▘▝▚▄▞▘ ▐▌  ▐▌   ▝▚▄▞▘▐▙▄▄▖▗▄▄▞▘▐▌ ▐▌ ▐▌
"""


def setup_logging(verbose: bool) -> None:
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stderr,
    )


def _start_prometheus_metrics(port: int | None, addr: str) -> "PrometheusMetrics | None":
    if port is None:
        return None
    try:
        from ..monitoring.prometheus import PrometheusMetrics, start_prometheus_server
    except ImportError as exc:
        raise click.ClickException(str(exc))

    metrics = PrometheusMetrics()
    start_prometheus_server(port, addr=addr, registry=metrics.registry)
    click.echo(f"Prometheus metrics available at http://{addr}:{port}", err=True)
    return metrics


class SplashGroup(click.Group):
    """Custom Click group that shows splash on help."""

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """Show splash banner before help text."""
        formatter.write(SPLASH)
        formatter.write(f"  Encrypted Traffic Feature Extraction v{__version__}\n")
        formatter.write("  https://github.com/cenab/joyfuljay\n\n")
        super().format_help(ctx, formatter)


@click.group(cls=SplashGroup)
@click.version_option(version=__version__, prog_name="joyfuljay")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """JoyfulJay: Encrypted Traffic Feature Extraction.

    Extract ML-ready features from encrypted network traffic.
    Use 'joyfuljay' or 'jj' to run commands.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    setup_logging(verbose)


@cli.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    help="Output file path. Defaults to stdout.",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["csv", "json", "parquet", "sqlite", "postgres", "kafka"]),
    default="csv",
    help="Output format (parquet requires pyarrow).",
)
@click.option(
    "-c",
    "--config",
    "config_file",
    type=click.Path(exists=True),
    help="Configuration file (JSON or YAML).",
)
@click.option(
    "--features",
    multiple=True,
    help="Feature groups to extract (can specify multiple).",
)
@click.option(
    "--feature",
    "specific_features",
    multiple=True,
    help="Specific feature names to include (can specify multiple, e.g., --feature ja3_hash --feature duration).",
)
@click.option(
    "--profile",
    type=click.Choice(["JJ-CORE", "JJ-EXTENDED", "JJ-EXPERIMENTAL"]),
    help="Feature profile to use. Filters output to only include features in the specified profile.",
)
@click.option(
    "--timeout",
    type=float,
    default=None,
    help="Flow inactivity timeout in seconds.",
)
@click.option(
    "--no-ips",
    is_flag=True,
    help="Exclude IP addresses from output.",
)
@click.option(
    "--no-ports",
    is_flag=True,
    help="Exclude port numbers from output.",
)
@click.option(
    "--include-sequences",
    is_flag=True,
    help="Include raw packet sequences (IAT, sizes).",
)
@click.option(
    "--bidir-split",
    is_flag=True,
    help="Split features into forward (fwd_) and backward (bwd_) directions.",
)
@click.option(
    "-w",
    "--workers",
    type=int,
    default=1,
    help="Number of parallel workers for batch processing.",
)
@click.option(
    "--progress/--no-progress",
    default=True,
    help="Show progress bar during processing.",
)
@click.option(
    "--streaming",
    is_flag=True,
    help="Use streaming mode to write output incrementally (for large captures).",
)
@click.option(
    "--prometheus-port",
    type=int,
    default=None,
    help="Expose Prometheus metrics on this port.",
)
@click.option(
    "--prometheus-addr",
    type=str,
    default="0.0.0.0",
    help="Prometheus bind address.",
)
@click.option(
    "--db-table",
    default="joyfuljay_features",
    help="Database table name for sqlite/postgres output.",
)
@click.option(
    "--db-if-exists",
    type=click.Choice(["append", "replace", "fail"]),
    default="append",
    help="Database table handling when it already exists.",
)
@click.option(
    "--db-batch-size",
    type=int,
    default=1000,
    help="Rows per batch for database output.",
)
@click.option(
    "--kafka-brokers",
    type=str,
    default=None,
    help="Kafka bootstrap servers (comma-separated).",
)
@click.option(
    "--kafka-topic",
    type=str,
    default=None,
    help="Kafka topic for streaming output.",
)
@click.option(
    "--kafka-key",
    type=str,
    default=None,
    help="Feature field to use as Kafka message key.",
)
@click.option(
    "--kafka-batch-size",
    type=int,
    default=1000,
    help="Flush every N messages for Kafka output.",
)
@click.pass_context
def extract(
    ctx: click.Context,
    input_path: str,
    output: str | None,
    output_format: str,
    config_file: str | None,
    features: tuple[str, ...],
    specific_features: tuple[str, ...],
    profile: str | None,
    timeout: float | None,
    no_ips: bool,
    no_ports: bool,
    include_sequences: bool,
    bidir_split: bool,
    workers: int,
    progress: bool,
    streaming: bool,
    prometheus_port: int | None,
    prometheus_addr: str,
    db_table: str,
    db_if_exists: str,
    db_batch_size: int,
    kafka_brokers: str | None,
    kafka_topic: str | None,
    kafka_key: str | None,
    kafka_batch_size: int,
) -> None:
    """Extract features from PCAP file(s).

    INPUT_PATH can be a single PCAP file or a directory containing PCAPs.

    Examples:

        jj extract capture.pcap -o features.csv

        jj extract traces/ -o features.json -f json

        jj extract capture.pcap --features timing --features size

        jj extract capture.pcap -c config.yaml
    """
    input_path_obj = Path(input_path)

    # Collect PCAP files
    if input_path_obj.is_dir():
        pcap_files = list(input_path_obj.glob("*.pcap")) + list(
            input_path_obj.glob("*.pcapng")
        )
        if not pcap_files:
            raise click.ClickException(f"No PCAP files found in {input_path}")
    else:
        pcap_files = [input_path_obj]

    # Build configuration
    if config_file:
        # Load from config file
        try:
            config = Config.from_file(config_file)
            click.echo(f"Loaded config from: {config_file}", err=True)
        except Exception as e:
            raise click.ClickException(f"Failed to load config file: {e}")

        # CLI options override config file
        if timeout is not None:
            config.flow_timeout = timeout
        if features:
            config.features = list(features)
        if specific_features:
            config.specific_features = list(specific_features)
        if profile:
            config.profile = profile  # type: ignore[assignment]
        if bidir_split:
            config.bidirectional_split = True
        if no_ips:
            config.include_ip_addresses = False
        if no_ports:
            config.include_ports = False
        if include_sequences:
            config.include_raw_sequences = True
        if workers > 1:
            config.num_workers = workers
    else:
        config = Config(
            flow_timeout=timeout if timeout is not None else 60.0,
            features=list(features) if features else ["all"],
            specific_features=list(specific_features) if specific_features else None,
            profile=profile,  # type: ignore[arg-type]
            bidirectional_split=bidir_split,
            include_ip_addresses=not no_ips,
            include_ports=not no_ports,
            include_raw_sequences=include_sequences,
            num_workers=workers,
        )

    metrics = _start_prometheus_metrics(prometheus_port, prometheus_addr)

    # Create pipeline
    pipeline = Pipeline(config, metrics=metrics)

    if output_format in {"sqlite", "postgres", "kafka"}:
        if output_format in {"sqlite", "postgres"}:
            if not output:
                raise click.ClickException(
                    "Database output requires --output with a SQLite path or PostgreSQL DSN."
                )
            from ..output.database import DatabaseWriter, detect_database_backend

            db_info = detect_database_backend(output)
            if output_format == "sqlite" and db_info.backend != "sqlite":
                raise click.ClickException(
                    "Output format sqlite requires a SQLite path or sqlite:// DSN."
                )
            if output_format == "postgres" and db_info.backend != "postgres":
                raise click.ClickException(
                    "Output format postgres requires a postgresql:// DSN."
                )

            sink = DatabaseWriter(
                dsn=output,
                table=db_table,
                if_exists=db_if_exists,
                batch_size=db_batch_size,
            )
        else:
            if not kafka_brokers or not kafka_topic:
                raise click.ClickException(
                    "Kafka output requires --kafka-brokers and --kafka-topic."
                )
            from ..output.kafka import KafkaWriter

            sink = KafkaWriter(
                brokers=kafka_brokers,
                topic=kafka_topic,
                key_field=kafka_key,
                batch_size=kafka_batch_size,
            )

        use_streaming = streaming or output_format == "kafka"
        flow_count = 0
        show_progress = progress and output is not None

        try:
            if use_streaming:
                if show_progress and len(pcap_files) > 1:
                    with create_progress(
                        description="Processing PCAPs",
                        total=len(pcap_files),
                        use_rich=is_rich_available(),
                    ) as prog:
                        for pcap_file in pcap_files:
                            for features in pipeline.iter_features(str(pcap_file)):
                                sink.write(features)
                                flow_count += 1
                            prog.update(1)
                else:
                    for pcap_file in pcap_files:
                        click.echo(f"Processing: {pcap_file}", err=True)
                        for features in pipeline.iter_features(str(pcap_file)):
                            sink.write(features)
                            flow_count += 1
            else:
                if len(pcap_files) > 1 and workers > 1:
                    click.echo(
                        "Database/Kafka output uses sequential processing for safety.",
                        err=True,
                    )
                for pcap_file in pcap_files:
                    click.echo(f"Processing: {pcap_file}", err=True)
                    features_list = pipeline.process_pcap(str(pcap_file), output_format="dict")
                    if isinstance(features_list, list):
                        sink.write_many(features_list)
                        flow_count += len(features_list)
        finally:
            sink.close()

        click.echo(f"Extracted {flow_count} flows", err=True)
        if output_format in {"sqlite", "postgres"}:
            click.echo(f"Written to table: {db_table}", err=True)
        else:
            click.echo(f"Published to Kafka topic: {kafka_topic}", err=True)
        return

    # Handle streaming mode
    if streaming:
        if not output:
            raise click.ClickException(
                "Streaming mode requires an output file. Use -o to specify output path."
            )
        if len(pcap_files) > 1:
            raise click.ClickException(
                "Streaming mode currently only supports a single PCAP file."
            )

        # Map output format for streaming
        stream_format = output_format
        if output_format == "json":
            stream_format = "jsonl"

        click.echo(f"Processing (streaming mode): {pcap_files[0]}", err=True)
        flow_count = pipeline.process_pcap_streaming(
            str(pcap_files[0]),
            output_path=output,
            output_format=stream_format,
        )
        click.echo(f"Extracted {flow_count} flows (streaming)", err=True)
        click.echo(f"Written to: {output}", err=True)
        return

    # Process files with optional progress bar
    all_features: list = []

    # Disable progress if outputting to stdout (would interfere with output)
    show_progress = progress and output is not None

    if show_progress and len(pcap_files) > 1:
        # Multiple files with progress bar
        with create_progress(
            description="Processing PCAPs",
            total=len(pcap_files),
            use_rich=is_rich_available(),
        ) as prog:
            for pcap_file in pcap_files:
                features_list = pipeline.process_pcap(str(pcap_file), output_format="dict")
                if isinstance(features_list, list):
                    all_features.extend(features_list)
                prog.update(1)
    elif show_progress:
        # Single file with progress
        click.echo(f"Processing: {pcap_files[0]}", err=True)
        features_list = pipeline.process_pcap(str(pcap_files[0]), output_format="dict")
        if isinstance(features_list, list):
            all_features = features_list
    else:
        # No progress bar (parallel processing or stdout output)
        if len(pcap_files) > 1 and workers > 1:
            click.echo(f"Processing {len(pcap_files)} files with {workers} workers", err=True)
        else:
            for pcap_file in pcap_files:
                click.echo(f"Processing: {pcap_file}", err=True)

        features_result = pipeline.process_pcaps_batch(
            [str(f) for f in pcap_files],
            output_format="dict",
        )
        if isinstance(features_result, list):
            all_features = features_result

    click.echo(f"Extracted {len(all_features)} flows", err=True)

    # Output results
    if output:
        output_path = Path(output)
        if output_format == "json":
            from ..output.formats import to_json

            to_json(all_features, output_path)
        elif output_format == "parquet":
            from ..output.formats import is_parquet_available, to_parquet

            if not is_parquet_available():
                raise click.ClickException(
                    "Parquet output requires pyarrow. Install with: pip install pyarrow"
                )
            to_parquet(all_features, output_path)
        else:
            from ..output.formats import to_csv

            to_csv(all_features, output_path)
        click.echo(f"Written to: {output}", err=True)
    else:
        # Write to stdout (parquet not supported for stdout)
        if output_format == "parquet":
            raise click.ClickException(
                "Parquet format requires an output file. Use -o to specify output path."
            )
        if output_format == "json":
            to_json_stream(all_features, sys.stdout)
        else:
            to_csv_stream(all_features, sys.stdout)


@cli.command()
@click.argument("interface")
@click.option(
    "-d",
    "--duration",
    type=float,
    help="Capture duration in seconds.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    help="Output file path. Defaults to stdout.",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["csv", "json", "sqlite", "postgres", "kafka"]),
    default="csv",
    help="Output format.",
)
@click.option(
    "--filter",
    "bpf_filter",
    type=str,
    help="BPF filter expression.",
)
@click.option(
    "--timeout",
    type=float,
    default=60.0,
    help="Flow inactivity timeout in seconds.",
)
@click.option(
    "--save-pcap",
    "save_pcap",
    type=click.Path(),
    help="Save captured packets to a PCAP file.",
)
@click.option(
    "--pid",
    type=int,
    help="Filter traffic by process ID.",
)
@click.option(
    "--process",
    type=str,
    help="Filter traffic by process name (e.g., 'chrome', 'firefox').",
)
@click.option(
    "--prometheus-port",
    type=int,
    default=None,
    help="Expose Prometheus metrics on this port.",
)
@click.option(
    "--prometheus-addr",
    type=str,
    default="0.0.0.0",
    help="Prometheus bind address.",
)
@click.option(
    "--db-table",
    default="joyfuljay_features",
    help="Database table name for sqlite/postgres output.",
)
@click.option(
    "--db-if-exists",
    type=click.Choice(["append", "replace", "fail"]),
    default="append",
    help="Database table handling when it already exists.",
)
@click.option(
    "--db-batch-size",
    type=int,
    default=1000,
    help="Rows per batch for database output.",
)
@click.option(
    "--kafka-brokers",
    type=str,
    default=None,
    help="Kafka bootstrap servers (comma-separated).",
)
@click.option(
    "--kafka-topic",
    type=str,
    default=None,
    help="Kafka topic for streaming output.",
)
@click.option(
    "--kafka-key",
    type=str,
    default=None,
    help="Feature field to use as Kafka message key.",
)
@click.option(
    "--kafka-batch-size",
    type=int,
    default=1000,
    help="Flush every N messages for Kafka output.",
)
@click.pass_context
def live(
    ctx: click.Context,
    interface: str,
    duration: float | None,
    output: str | None,
    output_format: str,
    bpf_filter: str | None,
    timeout: float,
    save_pcap: str | None,
    pid: int | None,
    process: str | None,
    prometheus_port: int | None,
    prometheus_addr: str,
    db_table: str,
    db_if_exists: str,
    db_batch_size: int,
    kafka_brokers: str | None,
    kafka_topic: str | None,
    kafka_key: str | None,
    kafka_batch_size: int,
) -> None:
    """Capture and extract features from live traffic.

    INTERFACE is the network interface to capture from (e.g., eth0, en0).

    Examples:

        jj live eth0 -d 60 -o features.csv

        jj live en0 --filter "port 443" -f json

        jj live en0 --pid 12345 -o app_traffic.csv

        jj live en0 --process chrome -o chrome_traffic.csv

    Note: Live capture may require root/admin privileges.
    """
    # Resolve process name to PIDs if specified
    target_pid = pid
    if process:
        from ..utils.pid_filter import find_pids_by_name

        pids = find_pids_by_name(process)
        if not pids:
            raise click.ClickException(f"No processes found matching '{process}'")

        # Use the first matching PID (main process)
        target_pid = pids[0]
        click.echo(f"Found {len(pids)} processes matching '{process}'", err=True)
        click.echo(f"Using PID {target_pid} as primary process", err=True)

    if pid and process:
        click.echo("Warning: Both --pid and --process specified, using --pid", err=True)
        target_pid = pid

    # Build configuration
    config = Config(
        flow_timeout=timeout,
        bpf_filter=bpf_filter,
    )

    metrics = _start_prometheus_metrics(prometheus_port, prometheus_addr)

    # Create pipeline
    pipeline = Pipeline(config, metrics=metrics)

    click.echo(f"Capturing on interface: {interface}", err=True)
    if duration:
        click.echo(f"Duration: {duration} seconds", err=True)
    if bpf_filter:
        click.echo(f"Filter: {bpf_filter}", err=True)
    if save_pcap:
        click.echo(f"Saving packets to: {save_pcap}", err=True)
    if target_pid:
        click.echo(f"Filtering by PID: {target_pid}", err=True)

    try:
        if output_format in {"sqlite", "postgres", "kafka"}:
            if output_format in {"sqlite", "postgres"}:
                if not output:
                    raise click.ClickException(
                        "Database output requires --output with a SQLite path or PostgreSQL DSN."
                    )
                from ..output.database import DatabaseWriter, detect_database_backend

                db_info = detect_database_backend(output)
                if output_format == "sqlite" and db_info.backend != "sqlite":
                    raise click.ClickException(
                        "Output format sqlite requires a SQLite path or sqlite:// DSN."
                    )
                if output_format == "postgres" and db_info.backend != "postgres":
                    raise click.ClickException(
                        "Output format postgres requires a postgresql:// DSN."
                    )

                sink = DatabaseWriter(
                    dsn=output,
                    table=db_table,
                    if_exists=db_if_exists,
                    batch_size=db_batch_size,
                )
            else:
                if not kafka_brokers or not kafka_topic:
                    raise click.ClickException(
                        "Kafka output requires --kafka-brokers and --kafka-topic."
                    )
                from ..output.kafka import KafkaWriter

                sink = KafkaWriter(
                    brokers=kafka_brokers,
                    topic=kafka_topic,
                    key_field=kafka_key,
                    batch_size=kafka_batch_size,
                )

            flow_count = 0
            try:
                for features in pipeline.process_live(
                    interface,
                    duration=duration,
                    output_format="stream",
                    save_pcap=save_pcap,
                    pid=target_pid,
                ):
                    sink.write(features)
                    flow_count += 1
            finally:
                sink.close()

            click.echo(f"Captured {flow_count} flows", err=True)
            if output_format in {"sqlite", "postgres"}:
                click.echo(f"Written to table: {db_table}", err=True)
            else:
                click.echo(f"Published to Kafka topic: {kafka_topic}", err=True)
            return

        # Process live traffic
        features_list = pipeline.process_live(
            interface,
            duration=duration,
            output_format="dataframe",
            save_pcap=save_pcap,
            pid=target_pid,
        )

        # Convert to list of dicts for output
        if hasattr(features_list, "to_dict"):
            all_features = features_list.to_dict("records")
        else:
            all_features = list(features_list)

        click.echo(f"Captured {len(all_features)} flows", err=True)

        # Output results
        if output:
            output_path = Path(output)
            if output_format == "json":
                from ..output.formats import to_json

                to_json(all_features, output_path)
            else:
                from ..output.formats import to_csv

                to_csv(all_features, output_path)
            click.echo(f"Written to: {output}", err=True)
        else:
            if output_format == "json":
                to_json_stream(all_features, sys.stdout)
            else:
                to_csv_stream(all_features, sys.stdout)

    except PermissionError:
        raise click.ClickException(
            "Permission denied. Live capture may require root/admin privileges."
        )
    except KeyboardInterrupt:
        click.echo("\nCapture interrupted by user.", err=True)


@cli.command()
@click.pass_context
def features(ctx: click.Context) -> None:
    """List all available features and their descriptions."""
    from ..output.schema import get_feature_documentation

    click.echo(get_feature_documentation())


@cli.command()
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    help="Output file path (defaults to stdout).",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "csv", "markdown"]),
    default="json",
    help="Schema output format.",
)
@click.option(
    "--group",
    type=str,
    help="Filter by feature group (e.g., 'tls', 'timing').",
)
@click.pass_context
def schema(
    ctx: click.Context,
    output: str | None,
    output_format: str,
    group: str | None,
) -> None:
    """Export feature schema in various formats.

    The schema includes feature names, types, descriptions, units, and groups.
    Useful for understanding the output format or integrating with other tools.

    Examples:

        jj schema -f json -o schema.json

        jj schema -f csv -o schema.csv

        jj schema --group tls
    """
    from ..output.schema import (
        export_schema_csv,
        export_schema_json,
        get_available_groups,
        get_feature_documentation,
        get_features_by_group,
    )

    if group:
        # Check if group exists
        available = get_available_groups()
        if group not in available:
            raise click.ClickException(
                f"Unknown group '{group}'. Available: {', '.join(available)}"
            )

    if output_format == "json":
        content = export_schema_json()
    elif output_format == "csv":
        content = export_schema_csv()
    else:  # markdown
        content = get_feature_documentation()

    if output:
        Path(output).write_text(content)
        click.echo(f"Schema written to: {output}", err=True)
    else:
        click.echo(content)


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Check system status and available interfaces.

    Useful for diagnosing live capture issues on Windows/macOS/Linux.
    """
    import platform

    from ..capture.scapy_backend import (
        check_live_capture_available,
        get_available_interfaces,
    )

    click.echo(f"JoyfulJay v{__version__}")
    click.echo(f"Platform: {platform.system()} {platform.release()}")
    click.echo(f"Python: {platform.python_version()}")
    click.echo()

    # Check live capture
    available, message = check_live_capture_available()
    if available:
        click.echo(f"Live capture: [OK] {message}")
    else:
        click.echo(f"Live capture: [WARNING] {message}")

    click.echo()

    # List interfaces
    interfaces = get_available_interfaces()
    if interfaces:
        click.echo("Available interfaces:")
        for iface in interfaces:
            name = iface["name"]
            desc = iface.get("description", "")
            if desc:
                click.echo(f"  - {name} ({desc})")
            else:
                click.echo(f"  - {name}")
    else:
        click.echo("No interfaces found (may require elevated privileges)")

    click.echo()
    click.echo("PCAP file processing: [OK] Always available")


@cli.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.pass_context
def info(ctx: click.Context, input_path: str) -> None:
    """Show information about a PCAP file.

    Displays basic statistics about the PCAP without full processing.
    """
    from ..capture.scapy_backend import ScapyBackend

    backend = ScapyBackend()

    packet_count = 0
    first_ts: float | None = None
    last_ts: float | None = None
    protocols: dict[int, int] = {}

    click.echo(f"Analyzing: {input_path}")

    for packet in backend.iter_packets_offline(input_path):
        packet_count += 1
        if first_ts is None:
            first_ts = packet.timestamp
        last_ts = packet.timestamp
        protocols[packet.protocol] = protocols.get(packet.protocol, 0) + 1

    if packet_count == 0:
        click.echo("No IP packets found in file.")
        return

    duration = (last_ts - first_ts) if first_ts and last_ts else 0.0

    click.echo(f"\nPackets: {packet_count}")
    click.echo(f"Duration: {duration:.2f} seconds")
    click.echo(f"Packets/sec: {packet_count / duration:.2f}" if duration > 0 else "N/A")
    click.echo("\nProtocols:")
    for proto, count in sorted(protocols.items(), key=lambda x: -x[1]):
        proto_name = {6: "TCP", 17: "UDP"}.get(proto, str(proto))
        click.echo(f"  {proto_name}: {count} ({100 * count / packet_count:.1f}%)")


@cli.command()
@click.argument("interface")
@click.option(
    "-p",
    "--port",
    type=int,
    default=8765,
    help="Port to listen on.",
)
@click.option(
    "--host",
    default="0.0.0.0",
    help="Host address to bind to.",
)
@click.option(
    "--filter",
    "bpf_filter",
    type=str,
    help="BPF filter expression.",
)
@click.option(
    "--token",
    type=str,
    help="Authentication token (generated if not provided).",
)
@click.option(
    "--pid",
    type=int,
    help="Filter traffic by process ID.",
)
@click.option(
    "--process",
    type=str,
    help="Filter traffic by process name (e.g., 'chrome', 'firefox').",
)
@click.option(
    "--max-clients",
    type=int,
    default=5,
    help="Maximum concurrent client connections (0 for unlimited).",
)
@click.option(
    "--max-bandwidth",
    type=str,
    default=None,
    help="Maximum bandwidth per client (e.g., '1M', '500K', '10M').",
)
@click.option(
    "--tls-cert",
    type=click.Path(exists=True),
    default=None,
    help="Path to TLS certificate for WSS.",
)
@click.option(
    "--tls-key",
    type=click.Path(exists=True),
    default=None,
    help="Path to TLS private key for WSS.",
)
@click.option(
    "--announce/--no-announce",
    default=False,
    help="Advertise the server via mDNS/Bonjour.",
)
@click.option(
    "--announce-name",
    type=str,
    default=None,
    help="Override the mDNS service name.",
)
@click.option(
    "--compress/--no-compress",
    default=True,
    help="Enable stream compression.",
)
@click.pass_context
def serve(
    ctx: click.Context,
    interface: str,
    port: int,
    host: str,
    bpf_filter: str | None,
    token: str | None,
    pid: int | None,
    process: str | None,
    max_clients: int,
    max_bandwidth: str | None,
    tls_cert: str | None,
    tls_key: str | None,
    announce: bool,
    announce_name: str | None,
    compress: bool,
) -> None:
    """Start JoyfulJay server for remote capture.

    Run this on the device you want to capture traffic from.
    Clients can connect using the displayed URL and token.

    INTERFACE is the network interface to capture from (e.g., wlan0, eth0).

    Examples:

        jj serve wlan0

        jj serve eth0 -p 9000 --filter "port 443"

        jj serve wlan0 --pid 5678

        jj serve wlan0 --process firefox

    Note: Requires root/admin privileges for packet capture.
    """
    import asyncio

    from ..remote.server import Server

    # Parse bandwidth string (e.g., "1M", "500K", "10M")
    bandwidth_bytes: float | None = None
    if max_bandwidth:
        try:
            value = max_bandwidth.upper()
            if value.endswith("K"):
                bandwidth_bytes = float(value[:-1]) * 1024
            elif value.endswith("M"):
                bandwidth_bytes = float(value[:-1]) * 1024 * 1024
            elif value.endswith("G"):
                bandwidth_bytes = float(value[:-1]) * 1024 * 1024 * 1024
            else:
                bandwidth_bytes = float(value)
        except ValueError:
            raise click.ClickException(
                f"Invalid bandwidth format: {max_bandwidth}. Use e.g., '1M', '500K', '10M'"
            )

    # Resolve process name to PID if specified
    target_pid = pid
    if process:
        from ..utils.pid_filter import find_pids_by_name

        pids = find_pids_by_name(process)
        if not pids:
            raise click.ClickException(f"No processes found matching '{process}'")

        target_pid = pids[0]
        click.echo(f"Found {len(pids)} processes matching '{process}'", err=True)
        click.echo(f"Using PID {target_pid} as primary process", err=True)

    if pid and process:
        click.echo("Warning: Both --pid and --process specified, using --pid", err=True)
        target_pid = pid

    if (tls_cert and not tls_key) or (tls_key and not tls_cert):
        raise click.ClickException("Both --tls-cert and --tls-key are required for TLS.")

    server = Server(
        interface=interface,
        host=host,
        port=port,
        bpf_filter=bpf_filter,
        token=token,
        pid=target_pid,
        max_clients=max_clients,
        max_bandwidth=bandwidth_bytes,
        compress=compress,
        tls_cert=tls_cert,
        tls_key=tls_key,
        announce=announce,
        announce_name=announce_name,
    )

    click.echo("Starting JoyfulJay remote capture server...", err=True)
    click.echo(f"Interface: {interface}", err=True)
    click.echo(f"Listening on: {host}:{port}", err=True)
    click.echo(f"Max clients: {max_clients if max_clients > 0 else 'unlimited'}", err=True)
    if bandwidth_bytes:
        click.echo(f"Max bandwidth per client: {max_bandwidth}", err=True)
    if bpf_filter:
        click.echo(f"Filter: {bpf_filter}", err=True)
    if target_pid:
        click.echo(f"Filtering by PID: {target_pid}", err=True)
    if tls_cert:
        click.echo("TLS: enabled (WSS)", err=True)
    if announce:
        click.echo("mDNS: enabled", err=True)
    if compress:
        click.echo("Compression: enabled", err=True)
    click.echo(err=True)
    click.echo("=" * 60, err=True)
    click.echo(f"Connection URL: {server.get_connection_url()}", err=True)
    click.echo(f"Token: {server.token}", err=True)
    click.echo("=" * 60, err=True)
    click.echo(err=True)
    click.echo("Waiting for connections... (Ctrl+C to stop)", err=True)

    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        click.echo("\nServer stopped.", err=True)
    except PermissionError:
        raise click.ClickException(
            "Permission denied. Capture may require root/admin privileges."
        )


@cli.command()
@click.option(
    "--timeout",
    type=float,
    default=2.0,
    help="Discovery time window in seconds.",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Output discovered servers as JSON.",
)
@click.pass_context
def discover(ctx: click.Context, timeout: float, json_output: bool) -> None:
    """Discover JoyfulJay servers on the local network via mDNS."""
    from ..remote.discovery import discover_servers

    servers = discover_servers(timeout=timeout)

    if json_output:
        payload = [
            {
                "name": server.name,
                "address": server.address,
                "port": server.port,
                "properties": server.properties,
            }
            for server in servers
        ]
        click.echo(json.dumps(payload, indent=2))
        return

    if not servers:
        click.echo("No JoyfulJay servers discovered.", err=True)
        return

    click.echo("Discovered JoyfulJay servers:", err=True)
    for server in servers:
        tls_flag = server.properties.get("tls") == "1"
        suffix = "?tls=1" if tls_flag else ""
        click.echo(f"- {server.name}: jj://{server.address}:{server.port}{suffix}")


@cli.command()
@click.argument("url")
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    help="Output file path. Defaults to stdout.",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["csv", "json", "sqlite", "postgres", "kafka"]),
    default="csv",
    help="Output format.",
)
@click.option(
    "-d",
    "--duration",
    type=float,
    help="Capture duration in seconds.",
)
@click.option(
    "--timeout",
    type=float,
    default=60.0,
    help="Flow inactivity timeout in seconds.",
)
@click.option(
    "--save-pcap",
    "save_pcap",
    type=click.Path(),
    help="Save received packets to a PCAP file.",
)
@click.option(
    "--tls-ca",
    type=click.Path(exists=True),
    default=None,
    help="CA bundle for WSS verification.",
)
@click.option(
    "--tls-insecure",
    is_flag=True,
    help="Disable TLS certificate verification (unsafe).",
)
@click.option(
    "--prometheus-port",
    type=int,
    default=None,
    help="Expose Prometheus metrics on this port.",
)
@click.option(
    "--prometheus-addr",
    type=str,
    default="0.0.0.0",
    help="Prometheus bind address.",
)
@click.option(
    "--db-table",
    default="joyfuljay_features",
    help="Database table name for sqlite/postgres output.",
)
@click.option(
    "--db-if-exists",
    type=click.Choice(["append", "replace", "fail"]),
    default="append",
    help="Database table handling when it already exists.",
)
@click.option(
    "--db-batch-size",
    type=int,
    default=1000,
    help="Rows per batch for database output.",
)
@click.option(
    "--kafka-brokers",
    type=str,
    default=None,
    help="Kafka bootstrap servers (comma-separated).",
)
@click.option(
    "--kafka-topic",
    type=str,
    default=None,
    help="Kafka topic for streaming output.",
)
@click.option(
    "--kafka-key",
    type=str,
    default=None,
    help="Feature field to use as Kafka message key.",
)
@click.option(
    "--kafka-batch-size",
    type=int,
    default=1000,
    help="Flush every N messages for Kafka output.",
)
@click.pass_context
def connect(
    ctx: click.Context,
    url: str,
    output: str | None,
    output_format: str,
    duration: float | None,
    timeout: float,
    save_pcap: str | None,
    tls_ca: str | None,
    tls_insecure: bool,
    prometheus_port: int | None,
    prometheus_addr: str,
    db_table: str,
    db_if_exists: str,
    db_batch_size: int,
    kafka_brokers: str | None,
    kafka_topic: str | None,
    kafka_key: str | None,
    kafka_batch_size: int,
) -> None:
    """Connect to a remote JoyfulJay server and extract features.

    URL format: jj://host:port?token=xxx

    Examples:

        jj connect "jj://192.168.1.100:8765?token=abc123" -o features.csv

        jj connect "jj://192.168.1.100:8765?token=abc123" -d 60 -f json

        jj connect "jj://192.168.1.100:8765?token=abc123" --save-pcap capture.pcap
    """
    from ..capture.remote_backend import RemoteCaptureBackend

    click.echo(f"Connecting to: {url}", err=True)

    try:
        backend = RemoteCaptureBackend.from_jj_url(
            url,
            tls_ca=tls_ca,
            tls_verify=not tls_insecure,
        )
    except ValueError as e:
        raise click.ClickException(str(e))

    config = Config(flow_timeout=timeout)
    metrics = _start_prometheus_metrics(prometheus_port, prometheus_addr)
    pipeline = Pipeline(config, backend=backend, metrics=metrics)

    if save_pcap:
        click.echo(f"Saving packets to: {save_pcap}", err=True)

    try:
        if output_format in {"sqlite", "postgres", "kafka"}:
            if output_format in {"sqlite", "postgres"}:
                if not output:
                    raise click.ClickException(
                        "Database output requires --output with a SQLite path or PostgreSQL DSN."
                    )
                from ..output.database import DatabaseWriter, detect_database_backend

                db_info = detect_database_backend(output)
                if output_format == "sqlite" and db_info.backend != "sqlite":
                    raise click.ClickException(
                        "Output format sqlite requires a SQLite path or sqlite:// DSN."
                    )
                if output_format == "postgres" and db_info.backend != "postgres":
                    raise click.ClickException(
                        "Output format postgres requires a postgresql:// DSN."
                    )

                sink = DatabaseWriter(
                    dsn=output,
                    table=db_table,
                    if_exists=db_if_exists,
                    batch_size=db_batch_size,
                )
            else:
                if not kafka_brokers or not kafka_topic:
                    raise click.ClickException(
                        "Kafka output requires --kafka-brokers and --kafka-topic."
                    )
                from ..output.kafka import KafkaWriter

                sink = KafkaWriter(
                    brokers=kafka_brokers,
                    topic=kafka_topic,
                    key_field=kafka_key,
                    batch_size=kafka_batch_size,
                )

            flow_count = 0
            try:
                for features in pipeline.process_live(
                    interface="",  # Not used for remote
                    duration=duration,
                    output_format="stream",
                    save_pcap=save_pcap,
                ):
                    sink.write(features)
                    flow_count += 1
            finally:
                sink.close()

            click.echo(f"Received {flow_count} flows", err=True)
            if output_format in {"sqlite", "postgres"}:
                click.echo(f"Written to table: {db_table}", err=True)
            else:
                click.echo(f"Published to Kafka topic: {kafka_topic}", err=True)
            return

        features_list = pipeline.process_live(
            interface="",  # Not used for remote
            duration=duration,
            output_format="dataframe",
            save_pcap=save_pcap,
        )

        # Convert to list of dicts for output
        if hasattr(features_list, "to_dict"):
            all_features = features_list.to_dict("records")
        else:
            all_features = list(features_list)

        click.echo(f"Received {len(all_features)} flows", err=True)

        # Output results
        if output:
            output_path = Path(output)
            if output_format == "json":
                from ..output.formats import to_json

                to_json(all_features, output_path)
            else:
                from ..output.formats import to_csv

                to_csv(all_features, output_path)
            click.echo(f"Written to: {output}", err=True)
        else:
            if output_format == "json":
                to_json_stream(all_features, sys.stdout)
            else:
                to_csv_stream(all_features, sys.stdout)

    except PermissionError as e:
        raise click.ClickException(f"Authentication failed: {e}")
    except ConnectionError as e:
        raise click.ClickException(f"Connection failed: {e}")
    except KeyboardInterrupt:
        click.echo("\nCapture interrupted by user.", err=True)


@cli.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output-dir",
    type=click.Path(),
    help="Output directory for processed files.",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["csv", "json", "parquet"]),
    default="csv",
    help="Output format.",
)
@click.option(
    "--recursive/--no-recursive",
    default=True,
    help="Watch subdirectories recursively.",
)
@click.option(
    "-c",
    "--config",
    "config_file",
    type=click.Path(exists=True),
    help="Configuration file (JSON or YAML).",
)
@click.pass_context
def watch(
    ctx: click.Context,
    directory: str,
    output_dir: str | None,
    output_format: str,
    recursive: bool,
    config_file: str | None,
) -> None:
    """Watch a directory and process new PCAP files automatically.

    DIRECTORY is the path to watch for new PCAP files.

    Examples:

        jj watch /var/pcap -o /var/features

        jj watch ./captures --format json

        jj watch /data/pcaps -c config.yaml
    """
    from ..utils.file_watcher import FileWatcher

    # Build configuration
    if config_file:
        try:
            config = Config.from_file(config_file)
            click.echo(f"Loaded config from: {config_file}", err=True)
        except Exception as e:
            raise click.ClickException(f"Failed to load config file: {e}")
    else:
        config = Config()

    pipeline = Pipeline(config)

    # Determine output directory
    out_dir = Path(output_dir) if output_dir else Path(directory) / "features"
    out_dir.mkdir(parents=True, exist_ok=True)

    def process_pcap(pcap_path: Path) -> None:
        """Process a single PCAP file."""
        try:
            click.echo(f"Processing: {pcap_path.name}", err=True)

            # Generate output filename
            output_file = out_dir / f"{pcap_path.stem}.{output_format}"

            # Process
            features = pipeline.process_pcap(str(pcap_path), output_format="dict")

            if not features:
                click.echo(f"  No flows found in {pcap_path.name}", err=True)
                return

            # Write output
            if output_format == "json":
                from ..output.formats import to_json
                to_json(features, output_file)
            elif output_format == "parquet":
                from ..output.formats import to_parquet
                to_parquet(features, output_file)
            else:
                from ..output.formats import to_csv
                to_csv(features, output_file)

            click.echo(f"  -> {output_file} ({len(features)} flows)", err=True)

        except Exception as e:
            click.echo(f"  Error: {e}", err=True)

    click.echo(f"Watching directory: {directory}", err=True)
    click.echo(f"Output directory: {out_dir}", err=True)
    click.echo(f"Recursive: {recursive}", err=True)
    click.echo("Press Ctrl+C to stop...", err=True)
    click.echo("", err=True)

    watcher = FileWatcher(
        paths=[directory],
        callback=process_pcap,
        recursive=recursive,
    )

    try:
        watcher.start()
        # Keep running until interrupted
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        click.echo("\nStopping watcher...", err=True)
        watcher.stop()


@cli.command()
@click.pass_context
def repl(ctx: click.Context) -> None:
    """Start interactive REPL for exploring PCAP files.

    The REPL provides commands for loading, exploring, and extracting
    features from PCAP files interactively.

    Commands in REPL:
        load <file>     - Load a PCAP file
        info            - Show info about loaded PCAP
        flows           - List flows
        features        - Extract features
        export <file>   - Export features to file
        help            - Show all commands
        quit            - Exit
    """
    try:
        from ..repl import start_repl
        start_repl()
    except ImportError as e:
        raise click.ClickException(
            f"REPL dependencies not available: {e}. "
            "The REPL requires standard Python libraries."
        )


@cli.group()
@click.pass_context
def profiles(ctx: click.Context) -> None:
    """Manage feature profiles.

    Profiles define subsets of features for different use cases:
    - JJ-CORE: Stable, commonly-used features (151 features)
    - JJ-EXTENDED: Additional analysis features (148 features)
    - JJ-EXPERIMENTAL: Experimental/specialized features (102 features)

    Use --profile with extract/live commands to filter output.
    """
    pass


@profiles.command(name="list")
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Output as JSON.",
)
@click.pass_context
def profiles_list(ctx: click.Context, json_output: bool) -> None:
    """List all available feature profiles."""
    from ..schema.profiles import list_profiles, load_profile

    profile_names = list_profiles()

    if json_output:
        data = {}
        for name in profile_names:
            features = load_profile(name)
            data[name] = {
                "feature_count": len(features),
                "features": features,
            }
        click.echo(json.dumps(data, indent=2))
        return

    click.echo("Available feature profiles:\n")
    for name in profile_names:
        features = load_profile(name)
        click.echo(f"  {name}: {len(features)} features")

    click.echo("\nUse 'jj profiles show <profile>' to see features in a profile.")
    click.echo("Use 'jj extract --profile <profile>' to filter extraction output.")


@profiles.command(name="show")
@click.argument("profile_name")
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Output as JSON.",
)
@click.option(
    "--group",
    type=str,
    help="Filter by extractor group (e.g., 'tls', 'timing').",
)
@click.pass_context
def profiles_show(
    ctx: click.Context,
    profile_name: str,
    json_output: bool,
    group: str | None,
) -> None:
    """Show features in a specific profile.

    Examples:

        jj profiles show JJ-CORE

        jj profiles show JJ-EXTENDED --group tls

        jj profiles show JJ-CORE --json
    """
    from ..schema.profiles import list_profiles, load_profile

    # Validate profile name
    valid_profiles = list_profiles()
    if profile_name not in valid_profiles:
        raise click.ClickException(
            f"Unknown profile: {profile_name}. "
            f"Valid profiles: {', '.join(valid_profiles)}"
        )

    features = load_profile(profile_name)

    # Filter by group if specified
    if group:
        features = [f for f in features if f.startswith(f"{group}.")]
        if not features:
            raise click.ClickException(
                f"No features found for group '{group}' in profile {profile_name}"
            )

    if json_output:
        click.echo(json.dumps(features, indent=2))
        return

    click.echo(f"{profile_name} ({len(features)} features):\n")

    # Group by extractor
    grouped: dict[str, list[str]] = {}
    for feature in features:
        if "." in feature:
            extractor, name = feature.split(".", 1)
        else:
            extractor, name = "other", feature
        grouped.setdefault(extractor, []).append(name)

    for extractor, names in sorted(grouped.items()):
        click.echo(f"  {extractor}:")
        for name in names:
            click.echo(f"    - {name}")


@profiles.command(name="validate")
@click.pass_context
def profiles_validate(ctx: click.Context) -> None:
    """Validate that all features are assigned to exactly one profile."""
    from ..schema.tiering import validate_tiering_complete

    try:
        validate_tiering_complete()
        click.echo("Validation passed: All features are assigned to exactly one profile.")
    except ValueError as e:
        raise click.ClickException(f"Validation failed: {e}")


@cli.command()
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["bibtex", "apa", "cff"]),
    default="bibtex",
    help="Citation format.",
)
@click.pass_context
def cite(ctx: click.Context, output_format: str) -> None:
    """Print citation information for JoyfulJay.

    Examples:

        jj cite

        jj cite -f apa

        jj cite -f cff
    """
    if output_format == "bibtex":
        citation = f'''@software{{joyfuljay,
  title = {{JoyfulJay: Encrypted Traffic Feature Extraction Library}},
  author = {{JoyfulJay Contributors}},
  year = {{2025}},
  url = {{https://github.com/cenab/joyfuljay}},
  version = {{{__version__}}},
  license = {{MIT}},
}}'''
    elif output_format == "apa":
        citation = f'''JoyfulJay Contributors. (2025). JoyfulJay: Encrypted Traffic Feature Extraction Library (Version {__version__}) [Computer software]. https://github.com/cenab/joyfuljay'''
    else:  # cff
        from pathlib import Path
        cff_path = Path(__file__).parents[2] / "CITATION.cff"
        if cff_path.exists():
            citation = cff_path.read_text()
        else:
            citation = "CITATION.cff not found. See https://github.com/cenab/joyfuljay"

    click.echo(citation)


@cli.command(name="validate")
@click.argument("pcap_path", type=click.Path(exists=True))
@click.option(
    "--expected",
    type=click.Path(exists=True),
    required=True,
    help="Path to expected output JSON file.",
)
@click.option(
    "--profile",
    type=click.Choice(["JJ-CORE", "JJ-EXTENDED", "JJ-EXPERIMENTAL"]),
    default="JJ-CORE",
    help="Feature profile to use for extraction.",
)
@click.option(
    "--tolerance",
    type=float,
    default=1e-9,
    help="Tolerance for floating-point comparisons.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show detailed comparison output.",
)
@click.pass_context
def validate_golden(
    ctx: click.Context,
    pcap_path: str,
    expected: str,
    profile: str,
    tolerance: float,
    verbose: bool,
) -> None:
    """Validate PCAP extraction against expected golden output.

    This command compares extracted features against a known-good output
    to verify determinism and reproducibility.

    Examples:

        jj validate tests/golden/sample.pcap --expected tests/golden/sample.json

        jj validate capture.pcap --expected expected.json --profile JJ-CORE

        jj validate test.pcap --expected golden.json --tolerance 1e-6 -v
    """
    import json as json_module
    from pathlib import Path

    # Load expected output
    expected_path = Path(expected)
    try:
        with open(expected_path) as f:
            expected_data = json_module.load(f)
    except Exception as e:
        raise click.ClickException(f"Failed to load expected output: {e}")

    # Extract features
    config = Config(profile=profile)  # type: ignore[arg-type]
    pipeline = Pipeline(config)

    click.echo(f"Extracting features from: {pcap_path}", err=True)
    click.echo(f"Profile: {profile}", err=True)

    try:
        features_result = pipeline.process_pcap(pcap_path, output_format="dict")
        if hasattr(features_result, "to_dict"):
            actual_flows = features_result.to_dict(orient="records")
        else:
            actual_flows = list(features_result)
    except Exception as e:
        raise click.ClickException(f"Failed to extract features: {e}")

    # Get expected flows
    expected_flows = expected_data.get("flows", [])

    click.echo(f"Extracted: {len(actual_flows)} flows", err=True)
    click.echo(f"Expected: {len(expected_flows)} flows", err=True)

    # Compare
    if len(actual_flows) != len(expected_flows):
        raise click.ClickException(
            f"Flow count mismatch: expected {len(expected_flows)}, got {len(actual_flows)}"
        )

    differences: list[str] = []

    for i, (actual, expected_flow) in enumerate(zip(actual_flows, expected_flows)):
        flow_diffs: list[str] = []

        # Check for missing or extra keys
        actual_keys = set(actual.keys())
        expected_keys = set(expected_flow.keys())

        missing = expected_keys - actual_keys
        extra = actual_keys - expected_keys

        if missing:
            flow_diffs.append(f"  Missing features: {sorted(missing)}")
        if extra and verbose:
            flow_diffs.append(f"  Extra features: {sorted(extra)}")

        # Compare common keys
        for key in actual_keys & expected_keys:
            actual_val = actual[key]
            expected_val = expected_flow[key]

            # Handle float comparison with tolerance
            if isinstance(expected_val, float) and isinstance(actual_val, (int, float)):
                if abs(float(actual_val) - expected_val) > tolerance:
                    flow_diffs.append(
                        f"  {key}: expected {expected_val}, got {actual_val} "
                        f"(diff: {abs(float(actual_val) - expected_val):.2e})"
                    )
            elif actual_val != expected_val:
                if verbose:
                    flow_diffs.append(f"  {key}: expected {expected_val!r}, got {actual_val!r}")
                else:
                    flow_diffs.append(f"  {key}: mismatch")

        if flow_diffs:
            differences.append(f"Flow {i}:")
            differences.extend(flow_diffs)

    if differences:
        click.echo("\nValidation FAILED:", err=True)
        for diff in differences[:50]:  # Limit output
            click.echo(diff, err=True)
        if len(differences) > 50:
            click.echo(f"  ... and {len(differences) - 50} more differences", err=True)
        raise click.ClickException("Output does not match expected golden output")

    click.echo("\nValidation PASSED: Output matches expected golden output.", err=True)


if __name__ == "__main__":
    cli()
