"""
OOB Profile — Out-of-band proof configuration.

Used to confirm blind SSRF/XXE-style issues by correlating a unique token
with a callback observed by an OOB server.

Local-first design:
- Users can self-host the included `oob_server.py` on a VPS/domain.
- The scanner can optionally poll the server API to auto-confirm callbacks.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from utils.logger import log


@dataclass
class OOBProfile:
    enabled: bool = False
    # Base URL of the OOB server, e.g. "https://oob.example.com/"
    base_url: str = ""
    # Optional shared key required by the OOB server API
    api_key: str = ""
    # Polling configuration (used for auto-confirm)
    poll_enabled: bool = True
    poll_timeout_s: float = 12.0
    poll_interval_s: float = 1.0

    def is_configured(self) -> bool:
        return bool(self.enabled and self.base_url.strip())

    def normalize(self) -> None:
        if self.base_url:
            self.base_url = self.base_url.strip()
            if not self.base_url.endswith("/"):
                self.base_url += "/"

    def new_token(self) -> str:
        return uuid.uuid4().hex

    def callback_url(self, token: str) -> str:
        """
        URL injected into payloads. The OOB server records hits to /c/<token>.
        """
        self.normalize()
        return urljoin(self.base_url, f"c/{token}")

    def events_api_url(self, token: str) -> str:
        self.normalize()
        return urljoin(self.base_url, f"api/events/{token}")

    async def poll_for_hit(self, token: str) -> dict | None:
        """
        Poll the OOB server for events for the token.
        Returns the latest event dict if found; otherwise None.
        """
        if not self.is_configured() or not self.poll_enabled:
            return None

        url = self.events_api_url(token)
        headers = {}
        if self.api_key:
            headers["X-OOB-Key"] = self.api_key
        # If server requires API key and it's missing, don't spin.
        if not headers.get("X-OOB-Key"):
            log.warning("OOB polling enabled but no API key provided; set OOB_API_KEY on server and provide --oob-key")
            return None

        deadline = time.monotonic() + float(self.poll_timeout_s or 0)
        timeout = httpx.Timeout(connect=3.0, read=3.0, write=3.0, pool=3.0)

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
            while time.monotonic() < deadline:
                try:
                    r = await client.get(url, headers=headers)
                    if r.status_code == 200:
                        data = r.json()
                        events = data.get("events") or []
                        if events:
                            return events[-1]
                    elif r.status_code in (401, 403):
                        log.warning("OOB poll unauthorized (check API key)")
                        return None
                except Exception as e:
                    log.debug(f"OOB poll error: {e}")
                await _sleep(self.poll_interval_s)

        return None


async def _sleep(s: float) -> None:
    try:
        import asyncio
        await asyncio.sleep(max(0.0, float(s)))
    except Exception:
        pass


# Global OOB profile — shared during a scan session
oob_profile = OOBProfile()


def reset_oob() -> None:
    global oob_profile
    oob_profile = OOBProfile()

