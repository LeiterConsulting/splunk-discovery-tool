"""
LLM Endpoint Health Monitoring System

Provides continuous health tracking, adaptive timeout calculation,
and intelligent retry strategies for LLM endpoints.

Version: 1.1.0
"""

import asyncio
import time
from typing import Dict, Any, Optional, Deque
from collections import deque
from dataclasses import dataclass, field
from enum import Enum


class HealthStatus(Enum):
    """Endpoint health status levels"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthMetrics:
    """Current health metrics for an endpoint"""
    status: HealthStatus = HealthStatus.UNKNOWN
    avg_response_time: float = 0.0  # seconds
    p95_response_time: float = 0.0  # 95th percentile
    error_rate: float = 0.0  # 0.0-1.0
    success_rate: float = 0.0  # 0.0-1.0
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    timeout_count: int = 0
    last_success: Optional[float] = None  # timestamp
    last_failure: Optional[float] = None  # timestamp
    recommended_timeout: int = 30  # seconds
    recommended_max_tokens: int = 16000
    consecutive_failures: int = 0
    uptime_percentage: float = 100.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "status": self.status.value,
            "avg_response_time": round(self.avg_response_time, 2),
            "p95_response_time": round(self.p95_response_time, 2),
            "error_rate": round(self.error_rate * 100, 2),  # percentage
            "success_rate": round(self.success_rate * 100, 2),
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "timeout_count": self.timeout_count,
            "last_success": self.last_success,
            "last_failure": self.last_failure,
            "recommended_timeout": self.recommended_timeout,
            "recommended_max_tokens": self.recommended_max_tokens,
            "consecutive_failures": self.consecutive_failures,
            "uptime_percentage": round(self.uptime_percentage, 2)
        }


class LLMHealthMonitor:
    """
    Monitors LLM endpoint health and provides adaptive recommendations.
    
    Features:
    - Rolling window metrics (last 100 requests)
    - Response time tracking (average + p95)
    - Error rate monitoring
    - Adaptive timeout calculation
    - Dynamic token budget recommendations
    """
    
    def __init__(self, endpoint_url: str, window_size: int = 100):
        self.endpoint_url = endpoint_url
        self.window_size = window_size
        
        # Rolling windows for metrics
        self.response_times: Deque[float] = deque(maxlen=window_size)
        self.request_results: Deque[bool] = deque(maxlen=window_size)  # True=success, False=failure
        self.timeout_events: Deque[float] = deque(maxlen=window_size)  # timestamps
        
        # Current metrics
        self.metrics = HealthMetrics()
        
        # Thresholds for health status
        self.healthy_error_rate = 0.05  # 5%
        self.degraded_error_rate = 0.20  # 20%
        self.healthy_response_time = 10.0  # seconds
        self.degraded_response_time = 30.0  # seconds
        
    def record_request(self, success: bool, response_time: float, is_timeout: bool = False):
        """
        Record a request outcome and update metrics.
        
        Args:
            success: Whether request succeeded
            response_time: Time taken in seconds
            is_timeout: Whether failure was due to timeout
        """
        now = time.time()
        
        # Update rolling windows
        if success:
            self.response_times.append(response_time)
            self.metrics.last_success = now
            self.metrics.consecutive_failures = 0
        else:
            self.metrics.last_failure = now
            self.metrics.consecutive_failures += 1
            
        self.request_results.append(success)
        
        if is_timeout:
            self.timeout_events.append(now)
            self.metrics.timeout_count += 1
        
        # Update counters
        self.metrics.total_requests += 1
        if success:
            self.metrics.successful_requests += 1
        else:
            self.metrics.failed_requests += 1
        
        # Recalculate metrics
        self._calculate_metrics()
    
    def _calculate_metrics(self):
        """Recalculate all derived metrics"""
        # Response time metrics
        if self.response_times:
            self.metrics.avg_response_time = sum(self.response_times) / len(self.response_times)
            sorted_times = sorted(self.response_times)
            p95_index = int(len(sorted_times) * 0.95)
            self.metrics.p95_response_time = sorted_times[p95_index] if sorted_times else 0.0
        
        # Success/error rates
        if self.request_results:
            successes = sum(1 for result in self.request_results if result)
            self.metrics.success_rate = successes / len(self.request_results)
            self.metrics.error_rate = 1.0 - self.metrics.success_rate
        
        # Overall uptime (all time, not just window)
        if self.metrics.total_requests > 0:
            self.metrics.uptime_percentage = (
                self.metrics.successful_requests / self.metrics.total_requests * 100
            )
        
        # Determine health status
        self._update_health_status()
        
        # Calculate recommendations
        self._calculate_recommendations()
    
    def _update_health_status(self):
        """Update health status based on current metrics"""
        error_rate = self.metrics.error_rate
        avg_time = self.metrics.avg_response_time
        consecutive = self.metrics.consecutive_failures
        
        # Critical: 5+ consecutive failures = unhealthy
        if consecutive >= 5:
            self.metrics.status = HealthStatus.UNHEALTHY
            return
        
        # Check error rate and response time
        if error_rate <= self.healthy_error_rate and avg_time <= self.healthy_response_time:
            self.metrics.status = HealthStatus.HEALTHY
        elif error_rate <= self.degraded_error_rate and avg_time <= self.degraded_response_time:
            self.metrics.status = HealthStatus.DEGRADED
        else:
            self.metrics.status = HealthStatus.UNHEALTHY
    
    def _calculate_recommendations(self):
        """Calculate adaptive timeout and token recommendations"""
        status = self.metrics.status
        avg_time = self.metrics.avg_response_time
        p95_time = self.metrics.p95_response_time
        
        # Adaptive timeout calculation
        if status == HealthStatus.HEALTHY:
            # Use p95 + 50% buffer
            base_timeout = max(p95_time * 1.5, 10.0)
            self.metrics.recommended_timeout = int(min(base_timeout, 60))
            self.metrics.recommended_max_tokens = 16000
            
        elif status == HealthStatus.DEGRADED:
            # Use p95 + 100% buffer, reduce tokens
            base_timeout = max(p95_time * 2.0, 20.0)
            self.metrics.recommended_timeout = int(min(base_timeout, 90))
            self.metrics.recommended_max_tokens = 8000
            
        else:  # UNHEALTHY or UNKNOWN
            # Very conservative
            self.metrics.recommended_timeout = 120
            self.metrics.recommended_max_tokens = 4000
    
    def get_metrics(self) -> HealthMetrics:
        """Get current health metrics"""
        return self.metrics
    
    def get_status(self) -> HealthStatus:
        """Get current health status"""
        return self.metrics.status
    
    def should_attempt_request(self) -> bool:
        """Determine if request should be attempted based on health"""
        # Always allow requests unless totally dead (10+ consecutive failures)
        return self.metrics.consecutive_failures < 10
    
    def get_retry_delay(self, attempt: int) -> float:
        """
        Calculate retry delay based on health and attempt number.
        
        Args:
            attempt: Retry attempt number (0-indexed)
        
        Returns:
            Delay in seconds
        """
        status = self.metrics.status
        base_delay = 2 ** attempt  # Exponential backoff
        
        if status == HealthStatus.HEALTHY:
            return min(base_delay, 10)  # Max 10s for healthy
        elif status == HealthStatus.DEGRADED:
            return min(base_delay * 2, 30)  # Max 30s for degraded
        else:  # UNHEALTHY
            return min(base_delay * 4, 120)  # Max 120s for unhealthy
    
    def reset_consecutive_failures(self):
        """Reset consecutive failure counter (call on success)"""
        self.metrics.consecutive_failures = 0


class AdaptiveTimeoutManager:
    """
    Manages adaptive timeouts based on endpoint health and request characteristics.
    """
    
    def __init__(self, health_monitor: LLMHealthMonitor):
        self.health_monitor = health_monitor
        self.min_timeout = 10
        self.max_timeout = 120
    
    def calculate_timeout(self, payload_size: int = 1000) -> int:
        """
        Calculate adaptive timeout for a request.
        
        Args:
            payload_size: Estimated token count in request
        
        Returns:
            Timeout in seconds
        """
        metrics = self.health_monitor.get_metrics()
        
        # Base timeout from health monitor recommendation
        base_timeout = metrics.recommended_timeout
        
        # Adjust for payload size (larger payloads need more time)
        # Assume ~100 tokens/second processing rate
        token_factor = payload_size / 100
        
        # Adjust for recent error rate (higher errors = more buffer)
        error_factor = 1.0 + (metrics.error_rate * 2)
        
        # Calculate final timeout
        timeout = base_timeout + token_factor
        timeout = timeout * error_factor
        
        # Clamp to reasonable bounds
        return int(max(min(timeout, self.max_timeout), self.min_timeout))
    
    def get_read_timeout(self, total_timeout: int) -> int:
        """
        Calculate socket read timeout (shorter than total timeout).
        
        Args:
            total_timeout: Total request timeout
        
        Returns:
            Read timeout in seconds
        """
        # Read timeout should be ~1/3 of total, min 5s
        return max(int(total_timeout / 3), 5)


class HungRequestDetector:
    """
    Detects hung/stuck requests that aren't making progress.
    """
    
    def __init__(self, no_progress_timeout: int = 30):
        self.no_progress_timeout = no_progress_timeout
        self.active_requests: Dict[str, float] = {}  # request_id -> last_progress_time
    
    async def monitor_request(
        self, 
        request_id: str,
        request_future: asyncio.Future,
        timeout: int
    ) -> Any:
        """
        Monitor a request for hung state.
        
        Args:
            request_id: Unique identifier for request
            request_future: The async request future
            timeout: Total timeout in seconds
        
        Returns:
            Result from request_future
        
        Raises:
            asyncio.TimeoutError: If request hangs or times out
        """
        start_time = time.time()
        self.active_requests[request_id] = start_time
        
        try:
            # Use asyncio.wait_for with our adaptive timeout
            result = await asyncio.wait_for(request_future, timeout=timeout)
            
            # Success - remove from tracking
            del self.active_requests[request_id]
            return result
            
        except asyncio.TimeoutError:
            # Clean up
            if request_id in self.active_requests:
                del self.active_requests[request_id]
            
            elapsed = time.time() - start_time
            raise asyncio.TimeoutError(
                f"Request {request_id} timed out after {elapsed:.1f}s (limit: {timeout}s)"
            )
        
        except Exception as e:
            # Clean up on any error
            if request_id in self.active_requests:
                del self.active_requests[request_id]
            raise
    
    def check_for_hung_requests(self) -> list:
        """
        Check for requests that haven't made progress.
        
        Returns:
            List of hung request IDs
        """
        now = time.time()
        hung = []
        
        for request_id, last_progress in list(self.active_requests.items()):
            if now - last_progress > self.no_progress_timeout:
                hung.append(request_id)
        
        return hung
    
    def update_progress(self, request_id: str):
        """Update last progress time for a request"""
        if request_id in self.active_requests:
            self.active_requests[request_id] = time.time()


class PayloadAdapter:
    """
    Adapts payload sizes based on endpoint health.
    """
    
    def __init__(self, health_monitor: LLMHealthMonitor):
        self.health_monitor = health_monitor
    
    def adapt_request(
        self,
        messages: list,
        max_tokens: int
    ) -> tuple[list, int]:
        """
        Adapt request based on endpoint health.
        
        Args:
            messages: List of message dicts
            max_tokens: Requested max_tokens
        
        Returns:
            Tuple of (adapted_messages, adapted_max_tokens)
        """
        status = self.health_monitor.get_status()
        recommended = self.health_monitor.get_metrics().recommended_max_tokens
        
        # Adjust max_tokens based on health
        adapted_tokens = min(max_tokens, recommended)
        
        # Adjust message count/size based on health
        if status == HealthStatus.HEALTHY:
            # No truncation needed
            return messages, adapted_tokens
        
        elif status == HealthStatus.DEGRADED:
            # Reduce to 70% of messages
            truncated = self._truncate_messages(messages, ratio=0.7)
            return truncated, adapted_tokens
        
        else:  # UNHEALTHY
            # Aggressive reduction to 50%
            truncated = self._truncate_messages(messages, ratio=0.5)
            return truncated, adapted_tokens
    
    def _truncate_messages(self, messages: list, ratio: float) -> list:
        """
        Intelligently truncate messages to ratio of original.
        
        Args:
            messages: Original messages
            ratio: Fraction to keep (0.0-1.0)
        
        Returns:
            Truncated messages
        """
        if not messages:
            return messages
        
        # Always keep system messages
        system_msgs = [m for m in messages if m.get('role') == 'system']
        other_msgs = [m for m in messages if m.get('role') != 'system']
        
        # Calculate how many other messages to keep
        target_count = max(1, int(len(other_msgs) * ratio))
        
        # Keep most recent messages (they're usually most relevant)
        kept_msgs = other_msgs[-target_count:]
        
        # Reconstruct with system messages first
        return system_msgs + kept_msgs


# Singleton health monitors (one per endpoint URL)
_health_monitors: Dict[str, LLMHealthMonitor] = {}


def get_health_monitor(endpoint_url: str) -> LLMHealthMonitor:
    """Get or create health monitor for an endpoint"""
    if endpoint_url not in _health_monitors:
        _health_monitors[endpoint_url] = LLMHealthMonitor(endpoint_url)
    return _health_monitors[endpoint_url]


def get_all_health_metrics() -> Dict[str, Dict[str, Any]]:
    """Get health metrics for all monitored endpoints"""
    return {
        url: monitor.get_metrics().to_dict()
        for url, monitor in _health_monitors.items()
    }
