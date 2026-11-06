"""DLKLAP client for Tapo DL-series locks."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import uuid4

import aiohttp
from Crypto.Cipher import AES

Json = dict[str, Any]


class DlklapError(Exception):
    """Base error class."""


class DlklapAuthError(DlklapError):
    """Authentication error."""


class DlklapIntegrityError(DlklapError):
    """An invalid authenticated response; never retry an uncertain operation."""


@lru_cache(maxsize=1)
def _control_key_ssl_context() -> ssl.SSLContext:
    """Use verified TLS with the app's private CA for control-key requests only."""
    context = ssl.create_default_context()
    context.load_verify_locations(
        cafile=str(Path(__file__).with_name("certs") / "tp-link-root-ca.pem")
    )
    return context


def _sha(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()


def _pkcs7_pad(data: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise DlklapIntegrityError("Invalid DLKLAP padded payload length")
    pad = data[-1]
    if not 1 <= pad <= 16 or data[-pad:] != bytes([pad]) * pad:
        raise DlklapIntegrityError("Invalid DLKLAP response padding")
    return data[:-pad]


def _aes_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def _aes_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def _extract_json(data: bytes) -> Json:
    text = data.decode("utf-8")
    start = text.find("{")
    if start < 0:
        raise DlklapError("No JSON object start in response")
    depth = 0
    in_str = False
    esc = False
    for idx in range(start, len(text)):
        char = text[idx]
        if in_str:
            if esc:
                esc = False
            elif char == "\\":
                esc = True
            elif char == '"':
                in_str = False
        elif char == '"':
            in_str = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start : idx + 1])
    raise DlklapError("No complete JSON object in response")


@dataclass
class DeviceInfo:
    """DL-series device state."""

    lock_status: int
    battery_percentage: int | None
    at_low_battery: bool | None
    raw: Json


class _Session:
    """A live DLKLAP session."""

    def __init__(
        self,
        ip: str,
        lsk: bytes,
        ldk: bytes,
        ivb: bytes,
        seq: int,
        cookie: str,
        websession: aiohttp.ClientSession,
    ) -> None:
        self._ip = ip
        self._lsk = lsk
        self._ldk = ldk
        self._ivb = ivb
        self._seq = seq
        self._cookie = cookie
        self._websession = websession

    async def call(self, requests: list[Json]) -> Json:
        return await self._request({"method": "multipleRequest", "params": {"requests": requests}})

    async def _request(self, plaintext: Json) -> Json:
        self._seq += 1
        seqb = self._seq.to_bytes(4, "big", signed=False)
        iv = self._ivb + seqb
        payload = json.dumps(plaintext).encode("utf-8")
        ciphertext = _aes_encrypt(self._lsk, iv, _pkcs7_pad(payload))
        mac = _sha(self._ldk, seqb, ciphertext)
        body = mac + ciphertext

        status, _, raw = await _post(
            self._websession,
            f"http://{self._ip}:80/app/request?seq={self._seq}",
            headers={
                "Referer": f"http://{self._ip}:80/",
                "Accept": "application/json",
                "requestByApp": "true",
                "Content-Type": "text/plain",
                "Cookie": self._cookie,
            },
            body=body,
        )
        if status != 200:
            raise DlklapError(f"/app/request HTTP {status} (seq={self._seq})")
        # Authenticate before decryption, as DoorLockKLAPTransport does in the app.
        if len(raw) < 48 or (len(raw) - 32) % 16:
            raise DlklapIntegrityError("Invalid DLKLAP response length")
        response_mac, response_ciphertext = raw[:32], raw[32:]
        expected_mac = _sha(self._ldk, seqb, response_ciphertext)
        if not hmac.compare_digest(response_mac, expected_mac):
            raise DlklapIntegrityError("DLKLAP response authentication failed")
        decrypted = _pkcs7_unpad(_aes_decrypt(self._lsk, iv, response_ciphertext))
        return _extract_json(decrypted)


async def _post(
    websession: aiohttp.ClientSession,
    url: str,
    headers: dict[str, str],
    body: bytes | str,
    ssl_context: ssl.SSLContext | None = None,
) -> tuple[int, aiohttp.typedefs.LooseHeaders, bytes]:
    kwargs: dict[str, Any] = {
        "headers": headers,
        "data": body,
        "ssl": ssl_context if ssl_context is not None else True,
        "allow_redirects": False,
    }
    async with websession.post(url, **kwargs) as response:
        return response.status, response.headers, await response.read()


class DlklapApi:
    """Async client for TP-Link DLKLAP endpoints used by DL-series locks."""

    def __init__(
        self,
        ip: str,
        cloud_username: str,
        cloud_password: str,
        lock_name: str,
        websession: aiohttp.ClientSession,
        logger: logging.Logger,
        terminal_uuid: str | None = None,
        device_id: str | None = None,
    ) -> None:
        self.ip = ip
        self.cloud_username = cloud_username
        self.cloud_password = cloud_password
        self.lock_name = lock_name
        self.websession = websession
        self.log = logger

        self.terminal_uuid = terminal_uuid
        self.device_id = device_id
        self._token: str | None = None
        self._account_id: str | None = None
        self._session: _Session | None = None
        self._lock = asyncio.Lock()
        self.last_connect_error: str | None = None
        self.last_success_at: str | None = None

    def _hint_for_error(self, err: Exception) -> str:
        """Return actionable hint for known connection/auth/SSL failures."""
        err_text = str(err).lower()
        if isinstance(
            err,
            (
                aiohttp.ClientConnectorSSLError,
                aiohttp.ClientConnectorCertificateError,
                aiohttp.ClientSSLError,
            ),
        ) or "ssl" in err_text:
            return (
                "SSL handshake failed while contacting TP-Link cloud endpoints. "
                "Check outbound network filtering, DNS, and TLS interception."
            )
        if isinstance(err, (aiohttp.ClientConnectionError, asyncio.TimeoutError)):
            return (
                "Network request failed. Check internet/local connectivity, IP address, "
                "and whether the lock/device is reachable."
            )
        if isinstance(err, DlklapAuthError) or any(
            token in err_text for token in ("login", "token", "control-key", "10000", "auth")
        ):
            return (
                "Authentication failed. Verify cloud username/password, then reload "
                "the integration to refresh token and identifiers."
            )
        return (
            "Unexpected service failure. Enable debug logs for this integration and "
            "check Home Assistant logs for the full traceback."
        )

    async def get_device_info(self) -> DeviceInfo:
        async def _do_call(session: _Session) -> DeviceInfo:
            result = await session.call([{"method": "getDeviceInfo"}])
            info = result["result"]["responses"][0]["result"]
            return DeviceInfo(
                lock_status=info["lock_status"],
                battery_percentage=info.get("battery_percentage"),
                at_low_battery=info.get("at_low_battery"),
                raw=info,
            )

        return await self._with_session(_do_call)

    async def set_lock(self, locked: bool) -> None:
        async def _do_call(session: _Session) -> None:
            target_status = 0 if locked else 1
            response = await session.call(
                [
                    {
                        "method": "setLockStatus",
                        "params": {
                            "lock_status": target_status,
                            "sa_user_id": "local_1",
                        },
                    }
                ]
            )
            resp = response.get("result", {}).get("responses", [{}])[0]
            if resp.get("error_code") != 0:
                raise DlklapError(f"setLockStatus failed: {response}")

            # Some battery-saving states can acknowledge the command before
            # the lock actually applies it. Verify final status explicitly.
            for _ in range(3):
                verify = await session.call([{"method": "getDeviceInfo"}])
                info = verify["result"]["responses"][0]["result"]
                if info.get("lock_status") == target_status:
                    return
                await asyncio.sleep(0.5)

            raise DlklapError(
                f"Lock state verification failed: expected {target_status}, "
                f"got {info.get('lock_status')}"
            )

        await self._with_session(_do_call)

    async def call_methods(self, methods: list[str], batch_size: int = 4) -> dict[str, Json]:
        """Call arbitrary methods and return each raw response, including errors."""

        async def _do_call(session: _Session) -> dict[str, Json]:
            results: dict[str, Json] = {}
            for start in range(0, len(methods), batch_size):
                batch = methods[start : start + batch_size]
                response = await session.call([{"method": m} for m in batch])
                responses = response.get("result", {}).get("responses")
                if not isinstance(responses, list):
                    for method in batch:
                        results[method] = {"batch_response": response}
                    continue
                for method, resp in zip(batch, responses):
                    results[method] = resp
                for method in batch[len(responses) :]:
                    results[method] = {"error": "no response returned"}
            return results

        return await self._with_session(_do_call)

    async def _with_session(self, fn):
        async with self._lock:
            last_err: Exception | None = None
            for attempt in range(2):
                try:
                    await self._ensure_identifiers()
                    if self._session is None:
                        self._session = await self._handshake()
                        self.log.debug("New DLKLAP session established.")
                    result = await fn(self._session)
                    self.last_connect_error = None
                    self.last_success_at = (
                        datetime.now(UTC).isoformat().replace("+00:00", "Z")
                    )
                    return result
                except DlklapIntegrityError as err:
                    # The operation might already have reached the bolt. Do not resend it.
                    self._session = None
                    self.last_connect_error = str(err)
                    raise
                except Exception as err:  # noqa: BLE001
                    last_err = err
                    self.last_connect_error = str(err)
                    self.log.warning("Session attempt %s failed: %s", attempt + 1, err)
                    self.log.error("Tapo DL100 connection hint: %s", self._hint_for_error(err))

                    self._session = None
                    err_text = str(err).lower()
                    if (
                        "login" in err_text
                        or "token" in err_text
                        or "control-key" in err_text
                        or "10000" in err_text
                    ):
                        self._token = None
                    await asyncio.sleep(0.5)
            raise DlklapError(f"Session retries exhausted: {last_err}") from last_err

    async def _ensure_identifiers(self) -> None:
        if not self.terminal_uuid:
            self.terminal_uuid = str(uuid4()).upper()
            self.log.debug("Generated terminal_uuid: %s", self.terminal_uuid)
        if self.device_id:
            return

        await self._ensure_token()
        status, _, raw = await _post(
            self.websession,
            f"https://wap.tplinkcloud.com/?token={self._token}",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"method": "getDeviceList"}),
        )
        if status != 200:
            raise DlklapError(f"getDeviceList HTTP {status}")
        payload = json.loads(raw.decode("utf-8"))
        if payload.get("error_code") != 0:
            raise DlklapError(f"getDeviceList failed: {payload}")
        devices = payload.get("result", {}).get("deviceList", [])
        dl_locks = [
            d
            for d in devices
            if str(d.get("deviceModel", "")).upper().startswith("DL")
        ]
        found_aliases = [str(d.get("alias") or "<unknown>") for d in dl_locks]
        self.log.debug(
            "DL device discovery: requested lock alias='%s', found %s DL devices: %s",
            self.lock_name,
            len(dl_locks),
            found_aliases,
        )
        if not dl_locks:
            self.log.error(
                "No DL-series devices found on account after successful login. "
                "Verify this TP-Link account owns at least one DL lock in the Tapo app."
            )
            raise DlklapError("No DL-series lock devices found on this TP-Link account")
        if len(dl_locks) == 1:
            self.device_id = dl_locks[0]["deviceId"]
            return
        match = next((d for d in dl_locks if d.get("alias") == self.lock_name), None)
        if not match:
            aliases = ", ".join(d.get("alias", "<unknown>") for d in dl_locks)
            self.log.error(
                "Lock alias mismatch: configured name='%s', available DL aliases=[%s]. "
                "Update integration name to match the Tapo app alias exactly.",
                self.lock_name,
                aliases,
            )
            raise DlklapError(
                f"Multiple DL-series lock devices found ({aliases}). "
                "Set name to match alias in Tapo app exactly."
            )
        self.device_id = match["deviceId"]

    async def _ensure_token(self) -> None:
        if self._token:
            return
        if not self.terminal_uuid:
            self.terminal_uuid = str(uuid4()).upper()
        body = {
            "method": "login",
            "params": {
                "appType": "Tapo_Android",
                "cloudUserName": self.cloud_username,
                "cloudPassword": self.cloud_password,
                "terminalUUID": self.terminal_uuid,
                "refreshTokenNeeded": False,
            },
        }
        status, _, raw = await _post(
            self.websession,
            "https://wap.tplinkcloud.com/",
            headers={"Content-Type": "application/json"},
            body=json.dumps(body),
        )
        if status != 200:
            raise DlklapAuthError(f"login HTTP {status}")
        payload = json.loads(raw.decode("utf-8"))
        if payload.get("error_code") != 0:
            raise DlklapAuthError(f"login failed: {payload}")
        self._token = payload["result"]["token"]
        self._account_id = str(payload["result"]["accountId"])
        self.log.debug("TP-Link cloud login succeeded for '%s'.", self.cloud_username)

    async def _handshake(self) -> _Session:
        if not self._account_id:
            await self._ensure_token()
        base = f"http://{self.ip}:80"
        local_headers = {"Content-Type": "text/plain", "Referer": f"{base}/"}

        random4 = b""
        control_key = None
        await self._ensure_token()
        for attempt in range(2):
            random4 = os.urandom(4)
            digest = _sha((random4.hex() + self._account_id).upper().encode("ascii"))
            hs0_body = digest[:32] + b"\x00"
            hs0_status, _, hs0_raw = await _post(
                self.websession,
                f"{base}/app/handshake0",
                headers=local_headers,
                body=hs0_body,
            )
            if hs0_status != 200:
                raise DlklapError(f"handshake0 HTTP {hs0_status}")
            secret = hs0_raw.decode("utf-8").strip()

            ck_status, _, ck_raw = await _post(
                self.websession,
                f"https://use1-app-server.iot.i.tplinknbu.com/v1/things/{self.device_id}/control-key",
                headers={
                    "Authorization": f"ut|{self._token}",
                    "app-cid": f"app:Tapo_Android:{self.terminal_uuid}",
                    "App-Type": "Tapo_Android",
                    "x-app-name": "Tapo_Android",
                    "UUID": self.terminal_uuid,
                    "Terminal-Id": self.terminal_uuid,
                    "x-term-id": self.terminal_uuid,
                    "Platform": "ANDROID",
                    "X-App-Os": "android",
                    "Content-Type": "application/json",
                },
                body=json.dumps(
                    {"secret": secret, "random": random4.hex().upper()}
                ),
                ssl_context=await asyncio.to_thread(_control_key_ssl_context),
            )
            if ck_status != 200:
                raise DlklapError(f"control-key HTTP {ck_status}")
            ck_payload = json.loads(ck_raw.decode("utf-8"))
            ck_code = int(
                ck_payload.get("code")
                or ck_payload.get("error_code")
                or ck_payload.get("result", {}).get("code")
                or 0
            )
            ck_obj = ck_payload.get("result") or ck_payload.get("data") or ck_payload
            control_key = ck_obj.get("controlKey") or ck_obj.get("control_key")
            if control_key:
                break
            if ck_code == 10000 and attempt == 0:
                self._token = None
                await self._ensure_token()
                continue
            raise DlklapError(f"control-key missing: {ck_payload}")

        if not control_key:
            raise DlklapError("control-key retry exhausted")

        control_key_bytes = control_key.upper().encode("ascii")
        lmk = _sha(control_key_bytes)
        local_random = os.urandom(16)
        hs1_body = local_random + _sha(local_random + control_key_bytes)
        hs1_status, hs1_headers, hs1_raw = await _post(
            self.websession,
            f"{base}/app/handshake1",
            headers=local_headers,
            body=hs1_body,
        )
        if hs1_status != 200:
            raise DlklapError(f"handshake1 HTTP {hs1_status}")

        cookie_token = ""
        for cookie_line in hs1_headers.getall("Set-Cookie", []):
            for part in cookie_line.split(";"):
                token = part.strip()
                if token.startswith("TP_SESSIONID="):
                    cookie_token = token
                    break
            if cookie_token:
                break
        if not cookie_token:
            raise DlklapError("No TP_SESSIONID cookie on handshake1")

        remote_random = hs1_raw[:16]
        server_proof = hs1_raw[16:48]
        expected_proof = _sha(local_random + remote_random + lmk)
        if len(hs1_raw) != 48 or not hmac.compare_digest(expected_proof, server_proof):
            raise DlklapError("handshake1 server proof mismatch")

        hs2_status, _, _ = await _post(
            self.websession,
            f"{base}/app/handshake2",
            headers={**local_headers, "Cookie": cookie_token},
            body=_sha(remote_random + local_random + lmk),
        )
        if hs2_status != 200:
            raise DlklapError(f"handshake2 HTTP {hs2_status}")

        def kdf(tag: str) -> bytes:
            return _sha(tag.encode("ascii") + local_random + remote_random + lmk)

        lsk = kdf("lsk")[:16]
        ldk = kdf("ldk")[:28]
        iv_full = kdf("iv")
        ivb = iv_full[:12]
        seq0 = int.from_bytes(iv_full[28:32], "big") & 0x7FFFFFFF

        return _Session(
            ip=self.ip,
            lsk=lsk,
            ldk=ldk,
            ivb=ivb,
            seq=seq0,
            cookie=cookie_token,
            websession=self.websession,
        )
