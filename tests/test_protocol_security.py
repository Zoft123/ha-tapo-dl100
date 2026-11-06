"""Offline protocol and TLS regression tests; never contact a lock or cloud account."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import ssl
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("dlklap_test_api", ROOT / "custom_components/tapo_dl100/api.py")
api = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = api
spec.loader.exec_module(api)

KEY = bytes(range(16))
LDK = bytes(range(28))
IVB = bytes(range(12))
PAYLOAD = {"result": {"responses": [{"error_code": 0, "result": {"lock_status": 0}}]}}


def device_packet(seq=11, plaintext=None):
    """Build device-side wire data independently using cryptography's AES."""
    data = json.dumps(PAYLOAD).encode() if plaintext is None else plaintext
    padder = PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(KEY), modes.CBC(IVB + seq.to_bytes(4, "big"))).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    mac = hashlib.sha256(LDK + seq.to_bytes(4, "big") + encrypted).digest()
    return mac + encrypted


def session():
    return api._Session("192.0.2.1", KEY, LDK, IVB, 10, "TP_SESSIONID=test", object())


@pytest.mark.asyncio
async def test_valid_authenticated_response_and_outbound_packet():
    post = AsyncMock(return_value=(200, {}, device_packet()))
    with patch.object(api, "_post", post):
        result = await session().call([{"method": "getDeviceInfo"}])
    assert result == PAYLOAD
    sent = post.call_args.kwargs["body"]
    assert sent[:32] == hashlib.sha256(LDK + (11).to_bytes(4, "big") + sent[32:]).digest()
    assert post.call_args.args[1].endswith("?seq=11")


@pytest.mark.asyncio
@pytest.mark.parametrize("mutate", [
    lambda raw: bytes([raw[0] ^ 1]) + raw[1:],
    lambda raw: raw[:-1] + bytes([raw[-1] ^ 1]),
    lambda raw: raw[:31],
    lambda raw: raw[:32],
    lambda raw: raw[:-1],
    lambda raw: b"",
    lambda raw: device_packet(seq=12),
])
async def test_tampered_truncated_or_wrong_sequence_rejected_before_decrypt(mutate):
    post = AsyncMock(return_value=(200, {}, mutate(device_packet())))
    with patch.object(api, "_post", post), patch.object(api, "_aes_decrypt") as decrypt:
        with pytest.raises(api.DlklapIntegrityError):
            await session().call([{"method": "getDeviceInfo"}])
        decrypt.assert_not_called()


@pytest.mark.asyncio
async def test_authenticated_invalid_padding_rejected():
    # Correct MAC, but an invalid PKCS7 final block: no zero-length padding.
    seqb = (11).to_bytes(4, "big")
    encryptor = Cipher(algorithms.AES(KEY), modes.CBC(IVB + seqb)).encryptor()
    encrypted = encryptor.update(b"x" * 15 + bytes([0])) + encryptor.finalize()
    raw = hashlib.sha256(LDK + seqb + encrypted).digest() + encrypted
    with (
        patch.object(api, "_post", AsyncMock(return_value=(200, {}, raw))),
        pytest.raises(api.DlklapIntegrityError, match="padding"),
    ):
        await session().call([{"method": "getDeviceInfo"}])


@pytest.mark.parametrize("data", [b"", b"x", b"x" * 15 + bytes([0]), b"x" * 15 + bytes([17]), b"x" * 14 + bytes([1, 2])])
def test_invalid_padding(data):
    with pytest.raises(api.DlklapIntegrityError):
        api._pkcs7_unpad(data)


@pytest.mark.parametrize("data", [b"", b"x", b"x" * 16, b"x" * 31])
def test_valid_padding(data):
    assert api._pkcs7_unpad(api._pkcs7_pad(data)) == data


@pytest.mark.asyncio
async def test_integrity_failure_never_retries_bolt_command():
    client = api.DlklapApi(
        "192.0.2.1", "owner@example.invalid", "test-only", "Test",
        object(), logging.getLogger("test"), terminal_uuid="test", device_id="test"
    )
    existing = AsyncMock()
    existing.call.side_effect = api.DlklapIntegrityError("bad MAC")
    client._session = existing
    with (
        patch.object(client, "_ensure_identifiers", AsyncMock()),
        patch.object(client, "_handshake", AsyncMock()) as handshake,
        pytest.raises(api.DlklapIntegrityError),
    ):
        await client.set_lock(locked=True)
    existing.call.assert_awaited_once()
    handshake.assert_not_awaited()
    assert client._session is None
    assert client.last_connect_error == "bad MAC"


def test_vendor_context_verifies_chain_and_hostname_and_contains_expected_root():
    context = api._control_key_ssl_context()
    assert context.check_hostname
    assert context.verify_mode == ssl.CERT_REQUIRED
    roots = {hashlib.sha256(cert).hexdigest() for cert in context.get_ca_certs(binary_form=True)}
    assert "8b54f0364e840fb010d517324725f0d30245d35b45f9be4b6e50b84f03fdec19" in roots


def test_configuration_and_runtime_have_no_tls_bypass():
    for path in (ROOT / "custom_components/tapo_dl100").glob("*.py"):
        source = path.read_text()
        assert "ssl_verify=False" not in source
        assert "CERT_NONE" not in source
        assert "check_hostname = False" not in source


@pytest.mark.asyncio
async def test_post_defaults_to_verified_tls_and_refuses_redirects():
    """A redirect must not forward cloud credentials to another endpoint."""
    response = AsyncMock()
    response.status = 302
    response.headers = {"Location": "https://other.invalid/"}
    response.read.return_value = b""
    context_manager = AsyncMock()
    context_manager.__aenter__.return_value = response
    websession = type("FakeSession", (), {})()
    from unittest.mock import Mock
    websession.post = Mock(return_value=context_manager)
    assert (await api._post(websession, "https://cloud.invalid/", {}, b"secret"))[0] == 302
    assert websession.post.call_args.kwargs["ssl"] is True
    assert websession.post.call_args.kwargs["allow_redirects"] is False


@pytest.mark.asyncio
async def test_handshake_uses_private_ca_only_for_control_key():
    """Exercise the complete handshake with a fake device/cloud, no live endpoints."""
    client = api.DlklapApi("192.0.2.1", "owner@example.invalid", "test-only", "Test",
                          object(), logging.getLogger("test"), terminal_uuid="test", device_id="test")
    client._token = "fake-token"
    client._account_id = "123"
    from multidict import CIMultiDict
    control = "AB" * 32
    local = b"L" * 16
    remote = b"R" * 16
    lmk = hashlib.sha256(control.encode()).digest()
    calls = []

    async def post(websession, url, headers, body, **kwargs):
        calls.append((url, kwargs))
        if url.endswith("handshake0"):
            return 200, {}, b"fake-challenge"
        if url.endswith("control-key"):
            return 200, {}, json.dumps({"result": {"controlKey": control}}).encode()
        if url.endswith("handshake1"):
            assert body == local + hashlib.sha256(local + control.encode()).digest()
            return 200, CIMultiDict({"Set-Cookie": "TP_SESSIONID=fake; Path=/"}), remote + hashlib.sha256(local + remote + lmk).digest()
        if url.endswith("handshake2"):
            assert body == hashlib.sha256(remote + local + lmk).digest()
            return 200, {}, b""
        raise AssertionError(url)

    with patch.object(api, "_post", post), patch.object(api.os, "urandom", side_effect=[b"rand", local]):
        established = await client._handshake()
    assert isinstance(established, api._Session)
    for url, kwargs in calls:
        if url.endswith("control-key"):
            assert kwargs["ssl_context"].check_hostname
            assert kwargs["ssl_context"].verify_mode == ssl.CERT_REQUIRED
        else:
            assert not kwargs


@pytest.mark.asyncio
async def test_real_tls_rejects_unknown_ca_and_wrong_hostname(tmp_path):
    """Use a real loopback TLS server to exercise aiohttp certificate enforcement."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    certfile = tmp_path / "cert.pem"
    keyfile = tmp_path / "key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile, keyfile)
    app = web.Application()

    async def handler(request):
        return web.Response(body=b"ok")

    app.router.add_post("/", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=server_context)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    trusted = ssl.create_default_context(cafile=str(certfile))
    try:
        async with aiohttp.ClientSession() as http:
            with pytest.raises(aiohttp.ClientConnectorCertificateError):
                await api._post(http, f"https://localhost:{port}/", {}, b"test")
            assert (await api._post(http, f"https://localhost:{port}/", {}, b"test", ssl_context=trusted))[2] == b"ok"
            with pytest.raises(aiohttp.ClientConnectorCertificateError):
                await api._post(http, f"https://127.0.0.1:{port}/", {}, b"test", ssl_context=trusted)
    finally:
        await runner.cleanup()
