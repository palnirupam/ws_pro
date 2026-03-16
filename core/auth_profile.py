"""
Auth Profile — Manages authentication for WebSocket scans.
Supports username/password login, token, cookie, custom headers.
"""
import asyncio
import json
import re
import time
import httpx
from urllib.parse import urlparse
from utils.logger import log


class AuthProfile:
    """
    Holds authentication credentials for a scan session.
    Created once, passed to all WS connections.
    """

    def __init__(self):
        self.enabled       = False
        self.method        = None   # 'login', 'token', 'cookie', 'headers'
        self.username      = ''
        self.password      = ''
        self.token         = ''
        self.cookie        = ''
        self.custom_headers = {}
        self.login_url     = ''
        self.token_field   = 'token'  # JSON field name in login response

        # Resolved after login
        self._auth_headers = {}
        self._cookies      = {}

    def is_configured(self) -> bool:
        """Returns True if auth is set up and ready to use"""
        return self.enabled and self.method is not None

    def get_ws_headers(self) -> dict:
        """Return headers to attach to every WebSocket connection"""
        headers = {}
        headers.update(self._auth_headers)
        headers.update(self.custom_headers)

        # Add cookie header if present
        if self._cookies:
            cookie_str = '; '.join(f"{k}={v}" for k, v in self._cookies.items())
            headers['Cookie'] = cookie_str
        elif self.cookie:
            headers['Cookie'] = self.cookie

        return headers

    async def resolve(self, target_url: str) -> bool:
        """
        Resolve credentials — perform login if needed.
        Returns True if auth is ready, False if failed.
        """
        if not self.enabled:
            return True  # No auth needed

        if self.method == 'token':
            # Token provided directly
            if self.token:
                self._auth_headers = {'Authorization': f'Bearer {self.token}'}
                log.info("Auth: using provided Bearer token")
                return True
            return False

        if self.method == 'cookie':
            # Cookie provided directly
            if self.cookie:
                self._cookies = {}
                # Parse cookie string: "name=value; name2=value2"
                for part in self.cookie.split(';'):
                    part = part.strip()
                    if '=' in part:
                        k, v = part.split('=', 1)
                        self._cookies[k.strip()] = v.strip()
                log.info(f"Auth: using provided cookie ({len(self._cookies)} values)")
                return True
            return False

        if self.method == 'headers':
            # Custom headers provided
            self._auth_headers = dict(self.custom_headers)
            log.info(f"Auth: using custom headers ({len(self._auth_headers)} headers)")
            return True

        if self.method == 'login':
            # Username + password — auto-login
            return await self._do_login(target_url)

        return False

    async def _do_login(self, target_url: str) -> bool:
        """
        Try to login using username/password.
        Tries multiple common login endpoints and formats.
        Extracts JWT/token from response.
        """
        parsed = urlparse(target_url)
        base_http = f"{'https' if parsed.scheme in ('https','wss') else 'http'}://{parsed.netloc}"

        # If user provided an explicit login URL, fail fast on that URL only.
        if self.login_url:
            login_endpoints = [self.login_url]
        else:
            # Common login endpoints to try
            login_endpoints = [
            f"{base_http}/api/login",
            f"{base_http}/api/auth/login",
            f"{base_http}/api/v1/login",
            f"{base_http}/login",
            f"{base_http}/auth/login",
            f"{base_http}/api/authenticate",
            f"{base_http}/api/token",
            f"{base_http}/api/auth/token",
            f"{base_http}/user/login",
            ]

        # Login body formats to try
        login_bodies = [
            {'username': self.username, 'password': self.password},
            {'email':    self.username, 'password': self.password},
            {'user':     self.username, 'password': self.password},
            {'login':    self.username, 'password': self.password},
            {'user':     self.username, 'pass':     self.password},
        ]

        # Token patterns in response
        token_patterns = [
            r'"(?:access_token|accessToken|token|jwt|auth_token|authToken)"\s*:\s*"([^"]+)"',
            r'"(?:Bearer|bearer)"\s*:\s*"([^"]+)"',
        ]

        ssl_ctx_kwargs = {'verify': False}
        # Keep login snappy: don't hang the scan/UI on unreachable auth endpoints.
        timeout = httpx.Timeout(connect=3.0, read=3.0, write=3.0, pool=3.0)
        deadline_s = 8.0
        start = time.monotonic()

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                     **ssl_ctx_kwargs) as client:
            for endpoint in login_endpoints:
                if time.monotonic() - start > deadline_s:
                    break
                for body in login_bodies:
                    try:
                        if time.monotonic() - start > deadline_s:
                            break
                        # Try JSON login
                        resp = await client.post(
                            endpoint,
                            json=body,
                            headers={'Content-Type': 'application/json',
                                     'Accept': 'application/json'}
                        )

                        if resp.status_code in (200, 201):
                            resp_text = resp.text

                            # Extract token from JSON response
                            for pattern in token_patterns:
                                m = re.search(pattern, resp_text)
                                if m:
                                    token = m.group(1)
                                    self._auth_headers = {
                                        'Authorization': f'Bearer {token}'
                                    }
                                    log.info(f"Auth: login successful at {endpoint}, "
                                             f"token extracted ({token[:20]}...)")
                                    return True

                            # Extract cookies from response
                            if resp.cookies:
                                self._cookies = dict(resp.cookies)
                                log.info(f"Auth: login successful at {endpoint}, "
                                         f"session cookies obtained ({len(self._cookies)} cookies)")
                                return True

                            # Check for token in headers
                            auth_header = resp.headers.get('Authorization', '')
                            if auth_header:
                                self._auth_headers = {'Authorization': auth_header}
                                log.info(f"Auth: token found in response header")
                                return True

                        # Try form-encoded login if JSON failed
                        resp2 = await client.post(
                            endpoint,
                            data=body,
                            headers={'Content-Type': 'application/x-www-form-urlencoded'}
                        )
                        if resp2.status_code in (200, 201) and resp2.cookies:
                            self._cookies = dict(resp2.cookies)
                            log.info(f"Auth: form login successful, cookies obtained")
                            return True

                    except Exception as e:
                        log.debug(f"Auth login attempt failed [{endpoint}]: {e}")
                        continue

        log.warning(f"Auth: could not login with provided credentials")
        return False


# Global auth profile — shared across all modules during a scan
auth_profile = AuthProfile()


def reset_auth():
    """Reset auth profile for new scan"""
    global auth_profile
    auth_profile = AuthProfile()

