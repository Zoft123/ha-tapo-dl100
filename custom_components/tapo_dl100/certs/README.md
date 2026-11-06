# TP-Link cloud trust anchor

Public CA certificate extracted from mergedCA.pem in the owner-provided Tapo APK.
APK SHA256: fbe289942c3a8bee5bb93789edc06207d64a88a80761cf3bcf942c51ef25218f
Subject/issuer: CN=tp-link-CA (self-signed).
Certificate SHA256: 8b54f0364e840fb010d517324725f0d30245d35b45f9be4b6e50b84f03fdec19

Only the control-key HTTPS request uses this additional trust anchor. Hostname,
chain, and validity verification stay enabled. Public cloud login/device-list
requests use system trust. No private keys or account/device credentials are bundled.
The trust anchor is public vendor certificate material, not project-authored code.
