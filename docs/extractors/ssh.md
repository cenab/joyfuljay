# SSH Extractor

The SSH extractor parses SSH protocol banners and generates HASSH fingerprints for client/server identification.

## Feature Group

```python
config = Config(features=["ssh"])
```

## Features

### Protocol Detection

| Feature | Type | Description |
|---------|------|-------------|
| `is_ssh` | bool | SSH protocol detected |
| `ssh_version` | str\|None | SSH protocol version |
| `ssh_client_banner` | str\|None | Client identification string |
| `ssh_server_banner` | str\|None | Server identification string |

### HASSH Fingerprints

| Feature | Type | Description |
|---------|------|-------------|
| `hassh` | str\|None | Client HASSH fingerprint |
| `hassh_str` | str\|None | Raw HASSH string |
| `hassh_server` | str\|None | Server HASSH fingerprint |
| `hassh_server_str` | str\|None | Raw server HASSH string |

### Algorithm Negotiation

| Feature | Type | Description |
|---------|------|-------------|
| `ssh_kex_algorithms` | list[str]\|None | Key exchange algorithms |
| `ssh_encryption_algorithms` | list[str]\|None | Encryption algorithms |
| `ssh_mac_algorithms` | list[str]\|None | MAC algorithms |
| `ssh_compression_algorithms` | list[str]\|None | Compression algorithms |

### Connection Info

| Feature | Type | Description |
|---------|------|-------------|
| `ssh_auth_attempts` | int | Authentication attempts |
| `ssh_channels_opened` | int | Channels opened |

## HASSH Fingerprinting

HASSH fingerprints SSH clients/servers based on Key Exchange Init:

```
HASSH = MD5(kex_algorithms;encryption_algorithms_client_to_server;mac_algorithms_client_to_server;compression_algorithms_client_to_server)
```

### Common HASSH Values

| Client | HASSH |
|--------|-------|
| OpenSSH 8.x | `b12d2871a1189eff20364cf5333619ee` |
| PuTTY | `6b83b26b9a649b0d1a6c8f6c0499e24e` |
| libssh | `0df0eb2a4b6a8c52d2a0be3b9fb6a8a7` |

## Example Output

```python
{
    "is_ssh": True,
    "ssh_version": "2.0",
    "ssh_client_banner": "SSH-2.0-OpenSSH_8.9",
    "ssh_server_banner": "SSH-2.0-OpenSSH_8.4",
    "hassh": "b12d2871a1189eff20364cf5333619ee",
    "hassh_server": "f1e5e4c9a6d8b3b5c7d9e1f3a5b7c9d1",
    "ssh_kex_algorithms": [
        "curve25519-sha256",
        "ecdh-sha2-nistp256",
    ],
}
```

## SSH Banner Format

```
SSH-protoversion-softwareversion comments
```

Examples:
- `SSH-2.0-OpenSSH_8.9`
- `SSH-2.0-PuTTY_Release_0.78`
- `SSH-2.0-libssh2_1.10.0`

## Use Cases

- **Client identification**: Identify SSH clients by HASSH
- **Server inventory**: Catalog SSH servers
- **Anomaly detection**: Unusual SSH implementations
- **Compliance**: Verify algorithm usage

## Detection Example

```python
import joyfuljay as jj

df = jj.extract("capture.pcap", features=["ssh"])

# Find SSH traffic
ssh_flows = df[df["is_ssh"] == True]

# Group by client fingerprint
client_stats = ssh_flows.groupby("hassh").size()
print("SSH clients by HASSH:")
print(client_stats)

# Check for unusual clients
KNOWN_HASSH = {
    "b12d2871a1189eff20364cf5333619ee",  # OpenSSH
    "6b83b26b9a649b0d1a6c8f6c0499e24e",  # PuTTY
}

unknown = ssh_flows[~ssh_flows["hassh"].isin(KNOWN_HASSH)]
print(f"Unknown SSH clients: {len(unknown)}")
```

## Related Extractors

- [TLS](tls.md) - TLS/JA3 fingerprints
- [Fingerprint](fingerprint.md) - Traffic classification
- [Entropy](entropy.md) - Payload analysis
