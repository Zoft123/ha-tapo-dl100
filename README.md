# Tapo DL-Series Home Assistant Integration

Fork of [angelvals/ha-tapo-dl100](https://github.com/angelvals/ha-tapo-dl100), with verified cloud TLS and authenticated DLKLAP responses.

## Install with HACS

1. Open **HACS → ⋮ → Custom repositories**.
2. Add **https://github.com/Zoft123/ha-tapo-dl100**, category **Integration**.
3. Download **Tapo DL100** and restart Home Assistant.
4. Open **Settings → Devices & services → Add integration → Tapo DL100**.
5. Enter the lock's local IP, its exact Tapo app name, and the **owner** TP-Link account credentials.

Keep the integration domain `tapo_dl100` and displayed name **Tapo DL100** for compatibility with upstream installations. If replacing the upstream integration, remove its HACS repository entry first and install this fork; do not install two copies of the same domain. Back up your HA configuration before replacing an existing integration.

For manual installation, copy `custom_components/tapo_dl100` into Home Assistant's `custom_components` directory and restart Home Assistant.

## Features and compatibility

- Lock/unlock entity, observed lock state and battery sensor.
- DL-series cloud model selection already accepts DL105.
- A DL105(US) was discovered advertising `SMART.TAPOLOCK`, `DLKLAP`, login version 2, HTTP port 80. Its Tapo APK contains the matching local transport.
- **Authenticated DL105 operation and Home Assistant installation have not yet been hardware-tested for this fork.** Protocol/TLS regression tests run offline.
- This backend targets DLKLAP HTTP locks. Other DL-series models or firmware may use different transports.
- Cloud login/control-key provisioning is required when establishing or renewing sessions; routine established-session requests use encrypted LAN HTTP.
- The control-key service remains the upstream **US use1** endpoint. Other account regions are not validated.
- With multiple locks, the configured name must exactly match the cloud alias; upstream's Base64-alias limitation remains.
- State `0` is locked, `1` unlocked; other values are not reported as either state.
- Battery-powered Wi-Fi may sleep. Avoid aggressive polling.

## Changes in 0.1.1

- Removed disabled TLS verification from setup, options and runtime.
- Added the public TP-Link CA from the Tapo APK for the control-key endpoint only. Certificate-chain, expiry and hostname checks stay enabled. Cloud login/device-list calls retain system trust.
- Verified the live public US endpoint's TLS handshake against this CA without account credentials.
- Authenticate every DLKLAP response with SHA256(LDK || sequence || ciphertext), using constant-time comparison, **before** AES decryption.
- Reject malformed/truncated frames, invalid padding and invalid handshake proofs.
- Clear the session and stop immediately on an integrity failure; do not automatically resend an uncertain bolt command.
- Disable HTTP redirects for protocol POSTs to avoid forwarding authentication material.
- Added offline regression tests, including a real local TLS server.

See [CA provenance](custom_components/tapo_dl100/certs/README.md) and [CHANGELOG.md](CHANGELOG.md).

## Development

Use Python 3.12 or newer. Install `requirements-test.txt`, then run:

```sh
python -m pytest -q
python -m compileall -q custom_components tests
ruff check custom_components/tapo_dl100/api.py tests
```

Tests use fake device/cloud responses and a loopback TLS server; they never send real lock/unlock commands or require owner credentials.

## Credits

Original integration: [angelvals/ha-tapo-dl100](https://github.com/angelvals/ha-tapo-dl100).
Protocol research: [tedholtz/homebridge-tapo-dl100](https://github.com/tedholtz/homebridge-tapo-dl100).
Project code retains the upstream MIT license. The bundled vendor CA is public certificate material and contains no private key.
