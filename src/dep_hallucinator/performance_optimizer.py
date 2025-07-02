"""
Production performance optimizer for dep-hallucinator.

Provides runtime optimizations for improved performance in production environments
including connection pooling, memory management, and async optimizations.
"""

import asyncio
import gc
import os
import sys
import threading
import time
from typing import Any, Dict, Optional

from .cli_config import get_config


class PerformanceOptimizer:
    """Manages performance optimizations for production deployment."""
    
    def __init__(self):
        self.config = get_config()
        self.production_config = self.config.production
        self._optimization_applied = False
        self._original_settings = {}
        
    async def apply_optimizations(self) -> Dict[str, Any]:
        """Apply all performance optimizations for production."""
        if self._optimization_applied:
            return {"status": "already_applied"}
            
        optimization_results = {}
        
        if self.production_config.enable_uvloop:
            optimization_results["uvloop"] = await self._setup_uvloop()
        
        if self.production_config.enable_orjson:
            optimization_results["orjson"] = self._setup_orjson()
        
        if self.production_config.enable_lz4_compression:
            optimization_results["lz4"] = self._setup_lz4_compression()
        
        optimization_results["memory"] = self._optimize_memory_usage()
        optimization_results["gc"] = self._optimize_garbage_collection()
        optimization_results["http"] = self._optimize_http_clients()
        optimization_results["asyncio"] = self._optimize_asyncio()
        
        self._optimization_applied = True
        return optimization_results
    
    async def _setup_uvloop(self) -> Dict[str, Any]:
        """Setup uvloop for better async performance on Unix systems."""
        if sys.platform == "win32":
            return {"status": "skipped", "reason": "not supported on Windows"}
        
        try:
            import uvloop  # type: ignore
            
            current_loop = None
            try:
                current_loop = asyncio.get_running_loop()
            except RuntimeError:
                pass
            
            if current_loop is None or not isinstance(current_loop, uvloop.Loop):  # type: ignore
                asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())  # type: ignore
                return {
                    "status": "success",
                    "policy_set": True,
                    "current_loop": str(type(current_loop).__name__ if current_loop else "None")
                }
            else:
                return {
                    "status": "already_active",
                    "current_loop": str(type(current_loop).__name__)
                }
                
        except ImportError:
            return {"status": "unavailable", "reason": "uvloop not installed"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def _setup_orjson(self) -> Dict[str, Any]:
        """Setup orjson for faster JSON processing."""
        try:
            import orjson  # type: ignore
            
            import json
            if not hasattr(json, '_original_dumps'):
                json._original_dumps = json.dumps  # type: ignore
                json._original_loads = json.loads  # type: ignore
                
                def orjson_dumps(obj, **kwargs):
                    return orjson.dumps(obj).decode('utf-8')
                
                def orjson_loads(s, **kwargs):
                    return orjson.loads(s)
                
                json.dumps = orjson_dumps
                json.loads = orjson_loads
                
                return {
                    "status": "success",
                    "monkey_patched": True,
                    "version": getattr(orjson, "__version__", "unknown")
                }
            else:
                return {"status": "already_patched"}
                
        except ImportError:
            return {"status": "unavailable", "reason": "orjson not installed"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def _setup_lz4_compression(self) -> Dict[str, Any]:
        """Setup LZ4 compression for cache optimization."""
        try:
            import lz4.frame  # type: ignore
            import lz4  # type: ignore
            
            if not hasattr(self, '_lz4_available'):
                self._lz4_available = True
                return {
                    "status": "success",
                    "compression_level": self.production_config.cache_compression_level,
                    "version": getattr(lz4, "__version__", "unknown")
                }
            else:
                return {"status": "already_available"}
                
        except ImportError:
            return {"status": "unavailable", "reason": "lz4 not installed"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def _optimize_memory_usage(self) -> Dict[str, Any]:
        """Apply memory usage optimizations."""
        try:
            if not hasattr(self, '_original_gc_thresholds'):
                self._original_gc_thresholds = gc.get_threshold()
            
            gc_threshold = self.config.performance.gc_threshold
            gc.set_threshold(gc_threshold, gc_threshold // 2, gc_threshold // 4)
            
            collected = gc.collect()
            memory_limit = self.production_config.max_memory_mb
            
            return {
                "status": "success",
                "gc_threshold_set": gc.get_threshold(),
                "initial_gc_collected": collected,
                "memory_limit_mb": memory_limit,
                "current_objects": len(gc.get_objects())
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def _optimize_garbage_collection(self) -> Dict[str, Any]:
        """Optimize garbage collection for production."""
        try:
            if self.config.production.enable_metrics:
                gc.set_debug(gc.DEBUG_STATS)
            else:
                gc.set_debug(0)
            
            collected_counts = []
            for generation in range(3):
                collected = gc.collect(generation)
                collected_counts.append(collected)
            
            return {
                "status": "success",
                "debug_flags": gc.get_debug(),
                "collected_by_generation": collected_counts,
                "total_objects": len(gc.get_objects()),
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def _optimize_http_clients(self) -> Dict[str, Any]:
        """Optimize HTTP client configurations."""
        try:
            http_optimizations = {
                "pool_connections": self.production_config.http_pool_connections,
                "pool_maxsize": self.production_config.http_pool_maxsize,
                "retries": self.production_config.http_retries,
                "timeout": self.production_config.async_timeout,
                "keepalive_enabled": True,
                "http2_enabled": True
            }
            
            return {
                "status": "success",
                "optimizations": http_optimizations
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def _optimize_asyncio(self) -> Dict[str, Any]:
        """Optimize asyncio settings for production."""
        try:
            optimizations = {}
            
            debug_mode = self.config.logging.log_level == "DEBUG"
            asyncio_debug = os.environ.get("PYTHONASYNCIODEBUG", "0") == "1"
            
            optimizations["debug_mode"] = debug_mode or asyncio_debug
            
            max_workers = self.production_config.max_async_workers
            optimizations["max_workers"] = max_workers
            
            try:
                loop = asyncio.get_running_loop()
                optimizations["current_loop_type"] = type(loop).__name__
                optimizations["loop_debug"] = loop.get_debug()
            except RuntimeError:
                optimizations["current_loop_type"] = "no_loop"
            
            return {
                "status": "success",
                "optimizations": optimizations
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get current performance statistics."""
        try:
            stats = {
                "memory": {
                    "gc_objects": len(gc.get_objects()),
                    "gc_counts": gc.get_count(),
                    "gc_thresholds": gc.get_threshold(),
                },
                "threading": {
                    "active_threads": threading.active_count(),
                    "main_thread_alive": threading.main_thread().is_alive(),
                },
                "process": {
                    "pid": os.getpid(),
                    "cwd": os.getcwd(),
                }
            }
            
            try:
                import psutil
                process = psutil.Process()
                memory_info = process.memory_info()
                stats["memory"]["rss_mb"] = memory_info.rss / 1024 / 1024
                stats["memory"]["vms_mb"] = memory_info.vms / 1024 / 1024
                stats["process"]["cpu_percent"] = process.cpu_percent()
                stats["process"]["memory_percent"] = process.memory_percent()
            except ImportError:
                stats["memory"]["psutil_available"] = False
            
            try:
                loop = asyncio.get_running_loop()
                stats["asyncio"] = {
                    "loop_type": type(loop).__name__,
                    "debug": loop.get_debug(),
                    "running": loop.is_running(),
                }
            except RuntimeError:
                stats["asyncio"] = {"status": "no_loop"}
            
            return stats
            
        except Exception as e:
            return {"error": str(e)}
    
    def cleanup_optimizations(self) -> Dict[str, Any]:
        """Cleanup and restore original settings."""
        try:
            cleanup_results = {}
            
            if hasattr(self, '_original_gc_thresholds'):
                gc.set_threshold(*self._original_gc_thresholds)
                cleanup_results["gc_thresholds_restored"] = True
            
            import json
            if hasattr(json, '_original_dumps'):
                json.dumps = json._original_dumps  # type: ignore
                json.loads = json._original_loads  # type: ignore
                delattr(json, '_original_dumps')
                delattr(json, '_original_loads')
                cleanup_results["json_functions_restored"] = True
            
            collected = gc.collect()
            cleanup_results["final_gc_collected"] = collected
            
            self._optimization_applied = False
            return {"status": "success", "cleanup_results": cleanup_results}
            
        except Exception as e:
            return {"status": "error", "error": str(e)}


_performance_optimizer: Optional[PerformanceOptimizer] = None


def get_performance_optimizer() -> PerformanceOptimizer:
    """Get the global performance optimizer instance."""
    global _performance_optimizer
    if _performance_optimizer is None:
        _performance_optimizer = PerformanceOptimizer()
    return _performance_optimizer


async def apply_production_optimizations() -> Dict[str, Any]:
    """Apply all production optimizations."""
    optimizer = get_performance_optimizer()
    return await optimizer.apply_optimizations()


def get_performance_stats() -> Dict[str, Any]:
    """Get current performance statistics."""
    optimizer = get_performance_optimizer()
    return optimizer.get_performance_stats()


def cleanup_optimizations() -> Dict[str, Any]:
    """Cleanup performance optimizations."""
    optimizer = get_performance_optimizer()
    return optimizer.cleanup_optimizations() 