"""Smart connection cache for efficient PID filtering."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...core.packet import Packet
    from .base import ConnectionInfo

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """A cached connection entry with metadata."""

    connection: ConnectionInfo
    first_seen: float
    last_seen: float
    hit_count: int = 0
    packet_count: int = 0


@dataclass
class CacheStats:
    """Statistics for the connection cache."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0
    hit_rate: float = 0.0


class ConnectionCache:
    """Smart connection cache with TTL and LRU eviction.

    Features:
    - TTL-based expiration for stale connections
    - LRU eviction when max size reached
    - Fast O(1) lookups using hash tables
    - Thread-safe operations
    - Statistics tracking
    """

    def __init__(
        self,
        max_size: int = 10000,
        ttl_seconds: float = 300.0,
        cleanup_interval: float = 30.0,
    ) -> None:
        """Initialize the connection cache.

        Args:
            max_size: Maximum number of connections to cache.
            ttl_seconds: Time-to-live for cache entries.
            cleanup_interval: How often to run cleanup.
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cleanup_interval = cleanup_interval

        self._cache: dict[tuple[str, int, str, int, int], CacheEntry] = {}
        self._lock = threading.RLock()
        self._stats = CacheStats()
        self._last_cleanup = time.time()

    def add(self, connection: ConnectionInfo) -> bool:
        """Add a connection to the cache.

        Args:
            connection: Connection to cache.

        Returns:
            True if added (was not already cached).
        """
        now = time.time()
        key = connection.key

        with self._lock:
            if key in self._cache:
                # Update existing entry
                entry = self._cache[key]
                entry.last_seen = now
                return False

            # Evict if at capacity
            if len(self._cache) >= self.max_size:
                self._evict_oldest()

            # Add new entry
            self._cache[key] = CacheEntry(
                connection=connection,
                first_seen=now,
                last_seen=now,
            )
            self._stats.size = len(self._cache)
            return True

    def remove(self, connection: ConnectionInfo) -> bool:
        """Remove a connection from the cache.

        Args:
            connection: Connection to remove.

        Returns:
            True if removed (was cached).
        """
        key = connection.key

        with self._lock:
            if key in self._cache:
                del self._cache[key]
                self._stats.size = len(self._cache)
                return True
            return False

    def get(self, key: tuple[str, int, str, int, int]) -> ConnectionInfo | None:
        """Get a connection by key.

        Args:
            key: Connection key tuple.

        Returns:
            ConnectionInfo if found, None otherwise.
        """
        with self._lock:
            entry = self._cache.get(key)
            if entry:
                entry.last_seen = time.time()
                entry.hit_count += 1
                self._stats.hits += 1
                return entry.connection
            self._stats.misses += 1
            return None

    def matches_packet(self, packet: Packet) -> ConnectionInfo | None:
        """Check if a packet matches any cached connection.

        Args:
            packet: Packet to check.

        Returns:
            Matching ConnectionInfo if found, None otherwise.
        """
        # Try to build potential keys for this packet
        forward_key = (
            packet.src_ip,
            packet.src_port,
            packet.dst_ip,
            packet.dst_port,
            packet.protocol,
        )
        reverse_key = (
            packet.dst_ip,
            packet.dst_port,
            packet.src_ip,
            packet.src_port,
            packet.protocol,
        )

        with self._lock:
            # Check forward direction
            entry = self._cache.get(forward_key)
            if entry:
                entry.last_seen = time.time()
                entry.hit_count += 1
                entry.packet_count += 1
                self._stats.hits += 1
                return entry.connection

            # Check reverse direction
            entry = self._cache.get(reverse_key)
            if entry:
                entry.last_seen = time.time()
                entry.hit_count += 1
                entry.packet_count += 1
                self._stats.hits += 1
                return entry.connection

            # Check listening sockets (match by port)
            for key, entry in self._cache.items():
                conn = entry.connection
                if conn.remote_ip in ("0.0.0.0", "::", "*") and conn.remote_port == 0:
                    if packet.dst_port == conn.local_port or packet.src_port == conn.local_port:
                        if packet.protocol == conn.protocol:
                            entry.last_seen = time.time()
                            entry.hit_count += 1
                            entry.packet_count += 1
                            self._stats.hits += 1
                            return entry.connection

            self._stats.misses += 1
            return None

    def cleanup(self, force: bool = False) -> int:
        """Remove expired entries from the cache.

        Args:
            force: If True, run cleanup regardless of interval.

        Returns:
            Number of entries removed.
        """
        now = time.time()

        if not force and (now - self._last_cleanup) < self.cleanup_interval:
            return 0

        removed = 0
        cutoff = now - self.ttl_seconds

        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.last_seen < cutoff
            ]

            for key in expired_keys:
                del self._cache[key]
                removed += 1

            self._stats.evictions += removed
            self._stats.size = len(self._cache)
            self._last_cleanup = now

        if removed > 0:
            logger.debug(f"Cache cleanup: removed {removed} expired entries")

        return removed

    def clear(self) -> None:
        """Clear all entries from the cache."""
        with self._lock:
            self._cache.clear()
            self._stats.size = 0

    def _evict_oldest(self) -> None:
        """Evict the oldest entry from the cache."""
        if not self._cache:
            return

        # Find the entry with oldest last_seen
        oldest_key = min(
            self._cache.keys(),
            key=lambda k: self._cache[k].last_seen,
        )

        del self._cache[oldest_key]
        self._stats.evictions += 1
        self._stats.size = len(self._cache)

    @property
    def stats(self) -> CacheStats:
        """Get cache statistics."""
        with self._lock:
            total = self._stats.hits + self._stats.misses
            self._stats.hit_rate = (self._stats.hits / total * 100) if total > 0 else 0.0
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions,
                size=self._stats.size,
                hit_rate=self._stats.hit_rate,
            )

    def update_from_connections(self, connections: set[ConnectionInfo]) -> tuple[int, int]:
        """Update cache from a new set of connections.

        Args:
            connections: New set of connections.

        Returns:
            Tuple of (added_count, removed_count).
        """
        now = time.time()
        added = 0
        removed = 0

        with self._lock:
            current_keys = set(self._cache.keys())
            new_keys = {c.key for c in connections}
            new_conn_map = {c.key: c for c in connections}

            # Remove connections no longer present
            for key in current_keys - new_keys:
                del self._cache[key]
                removed += 1

            # Add new connections
            for key in new_keys - current_keys:
                if len(self._cache) >= self.max_size:
                    self._evict_oldest()

                self._cache[key] = CacheEntry(
                    connection=new_conn_map[key],
                    first_seen=now,
                    last_seen=now,
                )
                added += 1

            # Update existing connections
            for key in new_keys & current_keys:
                self._cache[key].last_seen = now

            self._stats.size = len(self._cache)

        return added, removed
