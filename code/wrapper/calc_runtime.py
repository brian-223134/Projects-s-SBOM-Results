"""Utilities for measuring function runtime.

Usage:
	from code.wrapper.calc_runtime import measure_runtime

	@measure_runtime
	def foo():
		...

	@measure_runtime(unit="ms", sink=print)
	def bar(x):
		...
"""

from __future__ import annotations

import asyncio
import time
from functools import wraps
from typing import Any, Callable, Optional, TypeVar, overload


T = TypeVar("T")
F = TypeVar("F", bound=Callable[..., Any])


def _convert_seconds(seconds: float, unit: str) -> tuple[float, str]:
	normalized = unit.strip().lower()
	if normalized in {"s", "sec", "secs", "second", "seconds"}:
		return seconds, "s"
	if normalized in {"ms", "msec", "millisecond", "milliseconds"}:
		return seconds * 1_000.0, "ms"
	if normalized in {"us", "µs", "usec", "microsecond", "microseconds"}:
		return seconds * 1_000_000.0, "µs"
	raise ValueError(f"Unsupported unit: {unit!r} (use 's', 'ms', or 'us')")


@overload
def measure_runtime(func: F) -> F: ...


@overload
def measure_runtime(
	func: None = None,
	*,
	label: Optional[str] = None,
	unit: str = "ms",
	sink: Callable[[str], Any] = print,
	enabled: bool = True,
) -> Callable[[F], F]: ...


def measure_runtime(
	func: Optional[F] = None,
	*,
	label: Optional[str] = None,
	unit: str = "ms",
	sink: Callable[[str], Any] = print,
	enabled: bool = True,
):
	"""Decorator that measures and reports function runtime.

	- Works for both sync and async functions.
	- Preserves function metadata via `functools.wraps`.
	- Stores the last measured runtime (seconds) on the wrapper as `_last_runtime_s`.

	Args:
		label: Optional label to print; defaults to `module.qualname`.
		unit: Output unit: 's', 'ms', or 'us'.
		sink: Callable that receives the formatted message (default: print).
		enabled: If False, returns the original function unchanged.
	"""

	def decorator(target: F) -> F:
		if not enabled:
			return target

		resolved_label = label or f"{target.__module__}.{target.__qualname__}"

		if asyncio.iscoroutinefunction(target):

			@wraps(target)
			async def async_wrapper(*args: Any, **kwargs: Any):
				start = time.perf_counter()
				try:
					return await target(*args, **kwargs)
				finally:
					elapsed_s = time.perf_counter() - start
					async_wrapper._last_runtime_s = elapsed_s  # type: ignore[attr-defined]
					value, suffix = _convert_seconds(elapsed_s, unit)
					sink(f"[runtime] {resolved_label}: {value:.3f} {suffix}")

			return async_wrapper  # type: ignore[return-value]

		@wraps(target)
		def wrapper(*args: Any, **kwargs: Any):
			start = time.perf_counter()
			try:
				return target(*args, **kwargs)
			finally:
				elapsed_s = time.perf_counter() - start
				wrapper._last_runtime_s = elapsed_s  # type: ignore[attr-defined]
				value, suffix = _convert_seconds(elapsed_s, unit)
				sink(f"[runtime] {resolved_label}: {value:.3f} {suffix}")

		return wrapper  # type: ignore[return-value]

	if func is not None:
		return decorator(func)

	return decorator