"""Periodically promote every user's WebAuthn-passwordless credential to the top
of their Keycloak credential list.

Keycloak offers the credential ordering to the user as the login "try this first"
order, but nothing keeps it stable: registering a new credential (or an admin
reset) appends to the end. This worker sweeps a realm on an interval and calls
the admin API's moveToFirst on each matching credential that isn't already at the
front.

Configuration is entirely through environment variables; see .env.example.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import requests

LOG = logging.getLogger("passwordless-mover")

HEARTBEAT_PATH = os.environ.get("HEARTBEAT_PATH", "/tmp/heartbeat")

# Refresh the admin token this many seconds before it actually expires, so a
# long page of users can't have the token die out from under it mid-sweep.
TOKEN_EXPIRY_MARGIN_SECONDS = 30

RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class ConfigError(RuntimeError):
    """Raised when the environment is missing or contradicts itself."""


def _env_str(name: str, default: str | None = None, *, required: bool = False) -> str:
    value = os.environ.get(name, default if default is not None else "")
    value = value.strip()
    if required and not value:
        raise ConfigError(f"{name} is required but not set")
    return value


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


def _env_float(name: str, default: float, *, minimum: float = 0.0) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean-ish value, got {raw!r}")


@dataclass(frozen=True)
class Config:
    base_url: str
    realm: str
    token_realm: str
    client_id: str
    client_secret: str = field(repr=False)
    credential_type: str
    interval_seconds: float
    page_size: int
    request_timeout: float
    max_retries: int
    retry_backoff: float
    verify_tls: bool
    dry_run: bool
    run_once: bool

    @classmethod
    def from_env(cls) -> "Config":
        base_url = _env_str("KEYCLOAK_URL", required=True).rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            raise ConfigError(
                f"KEYCLOAK_URL must include a scheme (http:// or https://), got {base_url!r}"
            )
        realm = _env_str("KEYCLOAK_REALM", required=True)
        # Keycloak issues the service-account token from whichever realm owns the
        # client. That is usually the realm we sweep, but allow splitting them.
        token_realm = _env_str("KEYCLOAK_TOKEN_REALM") or realm

        # INTERVAL_MINUTES is the knob from the brief; INTERVAL_SECONDS is an
        # escape hatch for testing, and wins when both are set.
        interval_seconds = _env_float("INTERVAL_SECONDS", 0.0)
        if interval_seconds <= 0:
            interval_seconds = _env_float("INTERVAL_MINUTES", 15.0, minimum=0.0) * 60.0
        if interval_seconds <= 0:
            raise ConfigError("INTERVAL_MINUTES (or INTERVAL_SECONDS) must be > 0")

        return cls(
            base_url=base_url,
            realm=realm,
            token_realm=token_realm,
            client_id=_env_str("KEYCLOAK_CLIENT_ID", required=True),
            client_secret=_env_str("KEYCLOAK_CLIENT_SECRET", required=True),
            credential_type=_env_str("CREDENTIAL_TYPE", "webauthn-passwordless"),
            interval_seconds=interval_seconds,
            page_size=_env_int("PAGE_SIZE", 100),
            request_timeout=_env_float("REQUEST_TIMEOUT", 30.0, minimum=1.0),
            max_retries=_env_int("MAX_RETRIES", 3, minimum=0),
            retry_backoff=_env_float("RETRY_BACKOFF", 2.0, minimum=0.0),
            verify_tls=_env_bool("VERIFY_TLS", True),
            dry_run=_env_bool("DRY_RUN", False),
            run_once=_env_bool("RUN_ONCE", False),
        )


@dataclass
class SweepStats:
    users_scanned: int = 0
    users_with_credential: int = 0
    users_already_ordered: int = 0
    credentials_moved: int = 0
    user_errors: int = 0

    def summary(self) -> str:
        return (
            f"scanned={self.users_scanned} "
            f"with_credential={self.users_with_credential} "
            f"already_first={self.users_already_ordered} "
            f"moved={self.credentials_moved} "
            f"errors={self.user_errors}"
        )


class KeycloakAdminClient:
    """Thin admin-REST wrapper: service-account token, retries, 401 re-auth."""

    def __init__(self, config: Config, stop: threading.Event) -> None:
        self._config = config
        self._stop = stop
        self._session = requests.Session()
        self._session.headers["Accept"] = "application/json"
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    @property
    def _token_url(self) -> str:
        realm = quote(self._config.token_realm, safe="")
        return f"{self._config.base_url}/realms/{realm}/protocol/openid-connect/token"

    def _admin_url(self, path: str) -> str:
        realm = quote(self._config.realm, safe="")
        return f"{self._config.base_url}/admin/realms/{realm}{path}"

    def invalidate_token(self) -> None:
        self._token = None
        self._token_expires_at = 0.0

    def _access_token(self) -> str:
        if self._token and time.monotonic() < self._token_expires_at:
            return self._token

        LOG.debug("Requesting a new service-account token from %s", self._token_url)
        response = self._request_with_retries(
            "POST",
            self._token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self._config.client_id,
                "client_secret": self._config.client_secret,
            },
            authenticated=False,
        )
        payload = response.json()
        token = payload.get("access_token")
        if not token:
            raise RuntimeError("Token endpoint returned no access_token")

        # expires_in is seconds; Keycloak's default for a service account is 60.
        expires_in = float(payload.get("expires_in", 60))
        lifetime = max(expires_in - TOKEN_EXPIRY_MARGIN_SECONDS, 5.0)
        self._token = token
        self._token_expires_at = time.monotonic() + lifetime
        LOG.debug("Obtained token, usable for %.0fs", lifetime)
        return token

    def _request_with_retries(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        authenticated: bool = True,
    ) -> requests.Response:
        attempt = 0
        reauthorized = False

        while True:
            headers: dict[str, str] = {}
            if authenticated:
                headers["Authorization"] = f"Bearer {self._access_token()}"

            try:
                response = self._session.request(
                    method,
                    url,
                    params=params,
                    data=data,
                    headers=headers,
                    timeout=self._config.request_timeout,
                    verify=self._config.verify_tls,
                )
            except requests.RequestException as exc:
                if attempt >= self._config.max_retries:
                    raise
                delay = self._backoff_delay(attempt)
                LOG.warning(
                    "%s %s failed (%s); retrying in %.1fs", method, url, exc, delay
                )
                if not self._sleep(delay):
                    raise
                attempt += 1
                continue

            # A 401 on an authenticated call usually means the token was revoked
            # or the realm restarted. Re-auth once before treating it as fatal.
            if response.status_code == 401 and authenticated and not reauthorized:
                LOG.info("Admin API returned 401; refreshing the service-account token")
                self.invalidate_token()
                reauthorized = True
                continue

            if response.status_code in RETRYABLE_STATUS and attempt < self._config.max_retries:
                delay = self._retry_after(response) or self._backoff_delay(attempt)
                LOG.warning(
                    "%s %s -> HTTP %s; retrying in %.1fs",
                    method,
                    url,
                    response.status_code,
                    delay,
                )
                if not self._sleep(delay):
                    response.raise_for_status()
                attempt += 1
                continue

            if not response.ok:
                raise requests.HTTPError(
                    f"{method} {url} -> HTTP {response.status_code}: "
                    f"{response.text[:500]}",
                    response=response,
                )
            return response

    def _backoff_delay(self, attempt: int) -> float:
        return self._config.retry_backoff * (2**attempt)

    @staticmethod
    def _retry_after(response: requests.Response) -> float | None:
        raw = response.headers.get("Retry-After")
        if not raw:
            return None
        try:
            return max(float(raw), 0.0)
        except ValueError:
            return None

    def _sleep(self, seconds: float) -> bool:
        """Interruptible sleep. Returns False if we were asked to shut down."""
        return not self._stop.wait(seconds)

    def iter_users(self):
        """Yield users a page at a time, using briefRepresentation (we need ids)."""
        first = 0
        while not self._stop.is_set():
            response = self._request_with_retries(
                "GET",
                self._admin_url("/users"),
                params={
                    "first": first,
                    "max": self._config.page_size,
                    "briefRepresentation": "true",
                },
            )
            page = response.json()
            if not page:
                return
            yield from page
            if len(page) < self._config.page_size:
                return
            first += len(page)

    def user_count(self) -> int | None:
        try:
            return int(self._request_with_retries("GET", self._admin_url("/users/count")).json())
        except (requests.RequestException, ValueError, TypeError) as exc:
            LOG.debug("Could not read the user count: %s", exc)
            return None

    def credentials(self, user_id: str) -> list[dict[str, Any]]:
        path = f"/users/{quote(user_id, safe='')}/credentials"
        return self._request_with_retries("GET", self._admin_url(path)).json()

    def move_to_first(self, user_id: str, credential_id: str) -> None:
        path = (
            f"/users/{quote(user_id, safe='')}"
            f"/credentials/{quote(credential_id, safe='')}/moveToFirst"
        )
        self._request_with_retries("POST", self._admin_url(path))

    def close(self) -> None:
        self._session.close()


def _describe(user: dict[str, Any]) -> str:
    return user.get("username") or user.get("email") or user.get("id", "<unknown>")


def promote_user(client: KeycloakAdminClient, config: Config, user: dict[str, Any],
                 stats: SweepStats) -> None:
    user_id = user.get("id")
    if not user_id:
        LOG.debug("Skipping a user record with no id: %r", user)
        return

    credentials = client.credentials(user_id)
    matches = [
        (index, cred)
        for index, cred in enumerate(credentials)
        if cred.get("type") == config.credential_type
    ]
    if not matches:
        return

    stats.users_with_credential += 1

    # Already leading the list (indices 0..n-1)? Nothing to do — moveToFirst
    # would be a no-op write against the DB on every single cycle otherwise.
    if [index for index, _ in matches] == list(range(len(matches))):
        stats.users_already_ordered += 1
        LOG.debug("%s: %s already first", _describe(user), config.credential_type)
        return

    # Move in reverse so the matched credentials keep their relative order once
    # they are all at the front.
    for _, cred in reversed(matches):
        credential_id = cred.get("id")
        if not credential_id:
            LOG.warning("%s: credential has no id, skipping: %r", _describe(user), cred)
            continue
        if config.dry_run:
            LOG.info(
                "[dry-run] would move %s credential %s to first for %s",
                config.credential_type,
                credential_id,
                _describe(user),
            )
        else:
            client.move_to_first(user_id, credential_id)
            LOG.info(
                "Moved %s credential %s to first for %s",
                config.credential_type,
                credential_id,
                _describe(user),
            )
        stats.credentials_moved += 1


def run_sweep(client: KeycloakAdminClient, config: Config, stop: threading.Event) -> SweepStats:
    stats = SweepStats()
    started = time.monotonic()

    total = client.user_count()
    LOG.info(
        "Starting sweep of realm %r for %s credentials%s%s",
        config.realm,
        config.credential_type,
        f" ({total} users)" if total is not None else "",
        " [dry-run]" if config.dry_run else "",
    )

    for user in client.iter_users():
        if stop.is_set():
            LOG.info("Shutdown requested; stopping this sweep early")
            break
        stats.users_scanned += 1
        try:
            promote_user(client, config, user, stats)
        except requests.RequestException as exc:
            # One bad user must not abort the whole sweep.
            stats.user_errors += 1
            LOG.error("Failed to process %s: %s", _describe(user), exc)

    LOG.info("Sweep finished in %.1fs: %s", time.monotonic() - started, stats.summary())
    return stats


def _format_interval(seconds: float) -> str:
    return f"{seconds:.0f}s" if seconds < 90 else f"{seconds / 60.0:.1f}min"


def _touch_heartbeat() -> None:
    try:
        with open(HEARTBEAT_PATH, "w", encoding="utf-8") as handle:
            handle.write(str(time.time()))
    except OSError as exc:
        LOG.debug("Could not write the heartbeat file %s: %s", HEARTBEAT_PATH, exc)


def _configure_logging() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        stream=sys.stdout,
    )


def main() -> int:
    _configure_logging()

    try:
        config = Config.from_env()
    except ConfigError as exc:
        LOG.error("Configuration error: %s", exc)
        return 2

    stop = threading.Event()

    def _handle_signal(signum: int, _frame: Any) -> None:
        LOG.info("Received %s; shutting down after the current step", signal.Signals(signum).name)
        stop.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    LOG.info(
        "keycloak-passwordless-mover-upper starting: url=%s realm=%s client=%s interval=%s",
        config.base_url,
        config.realm,
        config.client_id,
        _format_interval(config.interval_seconds),
    )

    client = KeycloakAdminClient(config, stop)
    exit_code = 0
    try:
        while not stop.is_set():
            cycle_started = time.monotonic()
            try:
                run_sweep(client, config, stop)
                _touch_heartbeat()
            except Exception as exc:  # noqa: BLE001 - the loop must survive anything
                LOG.exception("Sweep failed: %s", exc)
                if config.run_once:
                    exit_code = 1

            if config.run_once:
                break

            # Interval is measured cycle-start to cycle-start, so a slow sweep
            # doesn't push every later run further out.
            elapsed = time.monotonic() - cycle_started
            delay = max(config.interval_seconds - elapsed, 0.0)
            if elapsed > config.interval_seconds:
                LOG.warning(
                    "Sweep took %.1fs, longer than the %.1fs interval; starting the next one now",
                    elapsed,
                    config.interval_seconds,
                )
            else:
                LOG.info("Next sweep in %s", _format_interval(delay))
            stop.wait(delay)
    finally:
        client.close()

    LOG.info("Stopped.")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
