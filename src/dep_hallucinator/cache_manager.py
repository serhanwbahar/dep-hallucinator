"""
Cache manager for package registry results with TTL-based expiration.

Provides efficient caching to reduce redundant API calls while maintaining
data freshness through configurable TTL and automatic cleanup.
"""

import asyncio
import gc
import hashlib
import threading
import time
from dataclasses import asdict, dataclass
from threading import Lock
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from .cli_config import get_config
from .error_handling import ErrorCategory, get_error_handler

if TYPE_CHECKING:
    pass


@dataclass(frozen=True)
class CacheKey:
    """Cache key for package lookups."""

    package_name: str
    registry_type: str

    def __str__(self) -> str:
        """Generate a string representation for use as dict key."""
        return f"{self.registry_type}:{self.package_name}"

    def to_hash(self) -> str:
        """Generate a hash for use as file cache key."""
        key_str = f"{self.registry_type}:{self.package_name}".encode()
        return hashlib.sha256(key_str).hexdigest()[:32]


@dataclass
class CacheEntry:
    """Cache entry with TTL and access tracking."""

    key: CacheKey
    data: Any  # RegistryCheckResult but using Any to avoid circular import
    created_at: float
    last_accessed: float
    ttl_seconds: int
    access_count: int = 0

    def is_expired(self) -> bool:
        """Check if the cache entry has expired."""
        return (time.time() - self.created_at) > self.ttl_seconds

    def is_fresh(self) -> bool:
        """Check if the cache entry is still fresh."""
        return not self.is_expired()

    def touch(self) -> None:
        """Update last access time and increment access count."""
        self.last_accessed = time.time()
        self.access_count += 1

    def age_seconds(self) -> float:
        """Get the age of the entry in seconds."""
        return time.time() - self.created_at

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        # Convert RegistryCheckResult to dict
        data_dict = asdict(self.data)

        return {
            "key": {
                "package_name": self.key.package_name,
                "registry_type": self.key.registry_type,
            },
            "data": data_dict,
            "created_at": self.created_at,
            "last_accessed": self.last_accessed,
            "ttl_seconds": self.ttl_seconds,
            "access_count": self.access_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CacheEntry":
        """Create from dictionary."""
        # Import here to avoid circular imports
        from .registry_clients import PackageInfo, RegistryCheckResult

        key = CacheKey(
            package_name=data["key"]["package_name"],
            registry_type=data["key"]["registry_type"],
        )

        # Reconstruct RegistryCheckResult
        result_data = data["data"]
        package_info = None
        if result_data.get("package_info"):
            package_info = PackageInfo(**result_data["package_info"])

        registry_result = RegistryCheckResult(
            package_name=result_data["package_name"],
            registry_type=result_data["registry_type"],
            package_info=package_info,
            error=result_data.get("error"),
            check_duration_ms=result_data.get("check_duration_ms"),
        )

        return cls(
            key=key,
            data=registry_result,
            created_at=data["created_at"],
            last_accessed=data["last_accessed"],
            ttl_seconds=data["ttl_seconds"],
            access_count=data["access_count"],
        )


class CacheStats:
    """Cache performance statistics."""

    def __init__(self):
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.expired_removals = 0
        self.manual_removals = 0
        self.total_requests = 0
        self._lock = Lock()

    def record_hit(self) -> None:
        """Record a cache hit."""
        with self._lock:
            self.hits += 1
            self.total_requests += 1

    def record_miss(self) -> None:
        """Record a cache miss."""
        with self._lock:
            self.misses += 1
            self.total_requests += 1

    def record_eviction(self) -> None:
        """Record a cache eviction."""
        with self._lock:
            self.evictions += 1

    def record_expired_removal(self) -> None:
        """Record removal of expired entry."""
        with self._lock:
            self.expired_removals += 1

    def record_manual_removal(self) -> None:
        """Record manual cache removal."""
        with self._lock:
            self.manual_removals += 1

    def get_hit_rate(self) -> float:
        """Get cache hit rate as percentage."""
        with self._lock:
            if self.total_requests == 0:
                return 0.0
            return (self.hits / self.total_requests) * 100.0

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        with self._lock:
            # Calculate hit rate directly to avoid nested lock
            hit_rate_percent = 0.0
            if self.total_requests > 0:
                hit_rate_percent = (self.hits / self.total_requests) * 100.0

            return {
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
                "expired_removals": self.expired_removals,
                "manual_removals": self.manual_removals,
                "total_requests": self.total_requests,
                "hit_rate_percent": hit_rate_percent,
            }

    def reset(self) -> None:
        """Reset all statistics."""
        with self._lock:
            self.hits = 0
            self.misses = 0
            self.evictions = 0
            self.expired_removals = 0
            self.manual_removals = 0
            self.total_requests = 0


class PackageCacheManager:
    """
    Thread-safe cache manager for package registry results.

    Features:
    - TTL-based expiration
    - LRU eviction policy
    - Configurable size limits
    - Thread-safe operations
    - Performance statistics
    - Automatic background cleanup
    """

    def __init__(
        self, max_size: Optional[int] = None, default_ttl: Optional[int] = None
    ):
        """
        Initialize the cache manager.

        Args:
            max_size: Maximum number of entries (defaults to config)
            default_ttl: Default TTL in seconds (defaults to config)
        """
        config = get_config()

        self.max_size = max_size or config.performance.max_cache_size
        self.default_ttl = default_ttl or config.performance.cache_ttl_seconds
        self.enabled = config.performance.enable_caching

        self._cache: Dict[str, CacheEntry] = {}
        self._lock = threading.RLock()  # Reentrant lock for nested calls
        self._stats = CacheStats()

        # Background cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._cleanup_interval = min(
            self.default_ttl // 4, 300
        )  # Cleanup every 5 minutes or 1/4 TTL
        self._stop_cleanup = False

        if self.enabled:
            self._start_background_cleanup()

    def _start_background_cleanup(self) -> None:
        """Start background cleanup task."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                self._cleanup_task = loop.create_task(self._cleanup_loop())
        except RuntimeError:
            # No event loop running, cleanup will happen manually
            pass

    async def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        while not self._stop_cleanup:
            try:
                await asyncio.sleep(self._cleanup_interval)
                if not self._stop_cleanup:
                    self._cleanup_expired()
                    self._maybe_trigger_gc()
            except asyncio.CancelledError:
                break
            except Exception as e:
                get_error_handler().warning(
                    ErrorCategory.CONFIGURATION,
                    f"Cache cleanup error: {e}",
                    "cache_manager",
                    "_cleanup_loop",
                )

    def _cleanup_expired(self) -> None:
        """Remove expired entries from cache."""
        with self._lock:
            expired_keys = []
            current_time = time.time()

            for key, entry in self._cache.items():
                if (current_time - entry.created_at) > entry.ttl_seconds:
                    expired_keys.append(key)

            for key in expired_keys:
                del self._cache[key]
                self._stats.record_expired_removal()

    def _maybe_trigger_gc(self) -> None:
        """Trigger garbage collection if configured threshold is reached."""
        config = get_config()
        if len(self._cache) > config.performance.gc_threshold:
            gc.collect()

    def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if not self._cache:
            return

        # Find LRU entry
        lru_key = min(self._cache.keys(), key=lambda k: self._cache[k].last_accessed)

        del self._cache[lru_key]
        self._stats.record_eviction()

    def get(self, package_name: str, registry_type: str) -> Optional[Any]:
        """
        Get cached registry result for a package.

        Args:
            package_name: Package name to look up
            registry_type: Registry type (pypi, npm)

        Returns:
            Cached RegistryCheckResult or None if not found/expired
        """
        if not self.enabled:
            return None

        cache_key = CacheKey(package_name, registry_type)
        key_str = str(cache_key)

        with self._lock:
            entry = self._cache.get(key_str)

            if entry is None:
                self._stats.record_miss()
                return None

            if entry.is_expired():
                # Remove expired entry
                del self._cache[key_str]
                self._stats.record_expired_removal()
                self._stats.record_miss()
                return None

            # Update access statistics
            entry.touch()
            self._stats.record_hit()

            return entry.data

    def put(
        self,
        package_name: str,
        registry_type: str,
        result: Any,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """
        Cache a registry result.

        Args:
            package_name: Package name
            registry_type: Registry type (pypi, npm)
            result: Registry check result to cache
            ttl_seconds: Custom TTL in seconds (defaults to default_ttl)
        """
        if not self.enabled:
            return

        cache_key = CacheKey(package_name, registry_type)
        key_str = str(cache_key)
        ttl = ttl_seconds or self.default_ttl

        current_time = time.time()
        entry = CacheEntry(
            key=cache_key,
            data=result,
            created_at=current_time,
            last_accessed=current_time,
            ttl_seconds=ttl,
        )

        with self._lock:
            # Check if we need to evict entries
            while len(self._cache) >= self.max_size:
                self._evict_lru()

            self._cache[key_str] = entry

    def remove(self, package_name: str, registry_type: str) -> bool:
        """
        Remove a specific entry from cache.

        Args:
            package_name: Package name
            registry_type: Registry type

        Returns:
            True if entry was removed, False if not found
        """
        if not self.enabled:
            return False

        cache_key = CacheKey(package_name, registry_type)
        key_str = str(cache_key)

        with self._lock:
            if key_str in self._cache:
                del self._cache[key_str]
                self._stats.record_manual_removal()
                return True
            return False

    def clear(self) -> int:
        """
        Clear all cache entries.

        Returns:
            Number of entries removed
        """
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            return count

    def size(self) -> int:
        """Get current cache size."""
        with self._lock:
            return len(self._cache)

    def get_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive cache statistics.

        Returns:
            Dictionary with cache performance metrics
        """
        base_stats = self._stats.get_stats()

        with self._lock:
            # Add size and memory info
            base_stats.update(
                {
                    "current_size": len(self._cache),
                    "max_size": self.max_size,
                    "enabled": self.enabled,
                    "default_ttl_seconds": self.default_ttl,
                    "size_utilization_percent": (
                        (len(self._cache) / self.max_size) * 100.0
                        if self.max_size > 0
                        else 0.0
                    ),
                }
            )

        return base_stats

    def get_entries_info(self) -> List[Dict[str, Any]]:
        """
        Get information about current cache entries.

        Returns:
            List of entry information dictionaries
        """
        with self._lock:
            entries_info = []
            current_time = time.time()

            for entry in self._cache.values():
                entries_info.append(
                    {
                        "package_name": entry.key.package_name,
                        "registry_type": entry.key.registry_type,
                        "age_seconds": current_time - entry.created_at,
                        "ttl_seconds": entry.ttl_seconds,
                        "is_expired": entry.is_expired(),
                        "access_count": entry.access_count,
                        "seconds_until_expiry": entry.ttl_seconds
                        - (current_time - entry.created_at),
                    }
                )

            # Sort by most recently accessed
            entries_info.sort(key=lambda x: x["access_count"], reverse=True)

            return entries_info

    def cleanup_now(self) -> Dict[str, int]:
        """
        Immediately cleanup expired entries.

        Returns:
            Dictionary with cleanup statistics
        """
        with self._lock:
            initial_size = len(self._cache)
            self._cleanup_expired()
            final_size = len(self._cache)

            return {
                "initial_size": initial_size,
                "final_size": final_size,
                "removed_count": initial_size - final_size,
            }

    def shutdown(self) -> None:
        """Shutdown the cache manager and cleanup resources."""
        self._stop_cleanup = True

        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()

        with self._lock:
            self._cache.clear()


# Global cache manager instance
_global_cache_manager: Optional[PackageCacheManager] = None


def get_cache_manager() -> PackageCacheManager:
    """
    Get the global cache manager instance.

    Returns:
        Global PackageCacheManager instance
    """
    global _global_cache_manager

    if _global_cache_manager is None:
        _global_cache_manager = PackageCacheManager()

    return _global_cache_manager


def reset_cache_manager() -> None:
    """Reset the global cache manager (useful for testing)."""
    global _global_cache_manager

    if _global_cache_manager:
        _global_cache_manager.shutdown()
        _global_cache_manager = None
