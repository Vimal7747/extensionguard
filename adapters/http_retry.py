# adapters/http_retry.py - Exponential-backoff retry wrapper for adapter HTTP calls
#
# Why we need this:
#   Transient 5xx errors and network blips happen often enough that without
#   retries we'd be silently dropping alerts. With 3 attempts + exponential
#   backoff (1s, 2s, 4s), a typical 30-second outage no longer loses data.
#
# When NOT to retry:
#   - 4xx client errors (bad credentials, malformed payload, rate-limited by
#     the destination): retrying won't help and could amplify a thundering herd
#   - Timeouts above a sensible ceiling (we'd be backing up the dispatch queue)
#
# Usage from an adapter:
#   from adapters.http_retry import post_with_retry
#   resp = post_with_retry(url, json=payload, headers=headers, timeout=10)
#
# The return value is a (response_or_none, error_message_or_none) tuple so
# adapters can build their existing result dicts without restructuring.

import random
import time

import requests

from logging_setup import get_logger

log = get_logger(__name__)


# Default retry policy - tunable per call
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_BASE_DELAY = 1.0  # seconds
DEFAULT_BACKOFF_FACTOR = 2.0
DEFAULT_JITTER_FRAC = 0.25  # +/- 25% randomness so retries don't sync up


# HTTP status codes that warrant a retry (transient server-side issues)
RETRIABLE_STATUS = {
    429,  # Too Many Requests (some servers respect Retry-After, we ignore for simplicity)
    500,  # Internal Server Error
    502,  # Bad Gateway
    503,  # Service Unavailable
    504,  # Gateway Timeout
}


def post_with_retry(
    url: str,
    *,
    json: dict | None = None,
    data: bytes | None = None,
    headers: dict | None = None,
    timeout: float = 10.0,
    verify: bool = True,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    base_delay: float = DEFAULT_BASE_DELAY,
    sleep_fn=time.sleep,
) -> tuple:
    """
    POST with exponential backoff retries on transient failures.

    Returns (response, error_string):
      - On success: (Response, None)
      - On terminal failure: (None, "human-readable reason")

    Both data= and json= are supported (we pass them through unchanged).

    sleep_fn parameter lets tests inject a no-op sleep instead of waiting.
    """
    last_error = "no attempts made"

    for attempt in range(1, max_attempts + 1):
        try:
            resp = requests.post(
                url,
                json=json,
                data=data,
                headers=headers,
                timeout=timeout,
                verify=verify,
            )
        except requests.exceptions.Timeout:
            last_error = f"timeout after {timeout}s on attempt {attempt}"
            log.debug(last_error)
            _maybe_sleep(attempt, max_attempts, base_delay, sleep_fn)
            continue
        except requests.exceptions.ConnectionError as exc:
            last_error = f"connection error on attempt {attempt}: {exc}"
            log.debug(last_error)
            _maybe_sleep(attempt, max_attempts, base_delay, sleep_fn)
            continue
        except requests.exceptions.RequestException as exc:
            # Other transport-layer errors: don't retry, surface immediately
            return None, f"request error: {exc}"

        # We got a response - decide whether it's retriable
        if resp.status_code in RETRIABLE_STATUS:
            last_error = f"HTTP {resp.status_code} on attempt {attempt} - retriable"
            log.debug(last_error)
            _maybe_sleep(attempt, max_attempts, base_delay, sleep_fn)
            continue

        # Either success or a 4xx that won't improve with retries.
        # Return the response and let the caller decide based on status code.
        return resp, None

    return None, f"exhausted {max_attempts} attempts ({last_error})"


def _maybe_sleep(attempt: int, max_attempts: int, base_delay: float, sleep_fn):
    """Sleep with exponential backoff + jitter, unless this was the final attempt."""
    if attempt >= max_attempts:
        return
    # attempt 1 -> 1.0s, attempt 2 -> 2.0s, attempt 3 -> 4.0s (with 25% jitter)
    delay = base_delay * (DEFAULT_BACKOFF_FACTOR ** (attempt - 1))
    jitter = delay * DEFAULT_JITTER_FRAC * (2 * random.random() - 1)
    sleep_fn(max(0.0, delay + jitter))
