# TLS Extractor

The TLS extractor parses TLS handshake messages to extract fingerprints, cipher suites, and metadata useful for encrypted traffic classification.

## Feature Group

```python
config = Config(features=["tls"])
```

## Features

### Basic TLS

| Feature | Type | Description |
|---------|------|-------------|
| `tls_version` | int\|None | TLS version (e.g., 0x0303 for TLS 1.2) |
| `tls_version_str` | str\|None | TLS version as string ("TLS 1.2", "TLS 1.3") |
| `tls_handshake_type` | int\|None | First handshake message type |
| `tls_cipher_suite` | int\|None | Selected cipher suite |
| `tls_cipher_suite_name` | str\|None | Cipher suite name |

### Server Name Indication (SNI)

| Feature | Type | Description |
|---------|------|-------------|
| `sni` | str\|None | Server Name Indication (hostname) |
| `sni_len` | int | SNI length (0 if not present) |

### JA3 Fingerprints

| Feature | Type | Description |
|---------|------|-------------|
| `ja3_hash` | str\|None | JA3 fingerprint (MD5 of ClientHello params) |
| `ja3_str` | str\|None | Raw JA3 string |
| `ja3s_hash` | str\|None | JA3S fingerprint (MD5 of ServerHello params) |
| `ja3s_str` | str\|None | Raw JA3S string |

### Extensions

| Feature | Type | Description |
|---------|------|-------------|
| `tls_extensions_count` | int | Number of TLS extensions |
| `tls_extensions_len` | int | Total extensions length |
| `tls_supported_versions` | list[int]\|None | Supported versions extension |
| `tls_supported_groups` | list[int]\|None | Supported groups (curves) |
| `tls_ec_point_formats` | list[int]\|None | EC point formats |
| `tls_alpn` | list[str]\|None | Application-Layer Protocol Negotiation |

### Cipher Suites Offered

| Feature | Type | Description |
|---------|------|-------------|
| `tls_cipher_suites_count` | int | Number of cipher suites offered |
| `tls_cipher_suites` | list[int]\|None | List of cipher suites |

### Certificate Info

| Feature | Type | Description |
|---------|------|-------------|
| `tls_cert_issuer` | str\|None | Certificate issuer CN |
| `tls_cert_subject` | str\|None | Certificate subject CN |
| `tls_cert_validity_days` | int\|None | Certificate validity period |
| `tls_cert_is_self_signed` | bool | Self-signed certificate |

## Example Output

```python
{
    "tls_version": 771,
    "tls_version_str": "TLS 1.2",
    "sni": "example.com",
    "sni_len": 11,
    "ja3_hash": "769,47-53-5-10-49171-49172-49161-49162,0-5-10-11-13-35-15,23-24,0",
    "ja3_str": "e7d705a3286e19ea42f587b344ee6865",
    "ja3s_hash": "771,49199,65281-0-11-35-23",
    "ja3s_str": "ae4edc6faf64d08308082ad26be60767",
    "tls_cipher_suite": 49199,
    "tls_cipher_suite_name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "tls_extensions_count": 12,
    "tls_alpn": ["h2", "http/1.1"],
}
```

## JA3 Fingerprinting

JA3 is a method to fingerprint TLS clients based on ClientHello parameters:

```
JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
```

**Common JA3 hashes:**
- Chrome/Edge: `66918128f1b9b03303d77c6f2eefd128`
- Firefox: `839bbe3ed07fed922ded5aaf714d6842`
- Safari: `50a5e45d8280a85e46e12f67f67a3d17`
- Tor Browser: `e7d705a3286e19ea42f587b344ee6865`

## TLS Version Detection

| Value | Version |
|-------|---------|
| 0x0301 | TLS 1.0 |
| 0x0302 | TLS 1.1 |
| 0x0303 | TLS 1.2 |
| 0x0304 | TLS 1.3 |

**Note:** TLS 1.3 still advertises 0x0303 in the record layer for backward compatibility, but uses the `supported_versions` extension.

## Use Cases

- TLS client fingerprinting
- Browser identification
- Malware detection (unique JA3 patterns)
- TLS version compliance auditing
- Certificate analysis
- ALPN-based protocol detection

## Related Extractors

- [QUIC](quic.md) - QUIC protocol features
- [Fingerprint](fingerprint.md) - Traffic type detection
- [Entropy](entropy.md) - Payload entropy
