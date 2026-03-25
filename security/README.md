# LiteLLM Supply Chain Attack Detector & Remediator

Detects and remediates indicators of compromise from the **TeamPCP supply chain attack** targeting LiteLLM versions **1.82.7** and **1.82.8** (March 24, 2026).

## Background

On March 24, 2026, threat actor **TeamPCP** published trojanized versions of the `litellm` Python package (v1.82.7 and v1.82.8) to PyPI. The malicious versions:

- Injected obfuscated code into `litellm/proxy/proxy_server.py`
- Installed a persistent `.pth` file (`litellm_init.pth`) that executes on every Python startup
- Deployed a `sysmon.py` backdoor with systemd persistence
- Exfiltrated environment variables (API keys, cloud credentials, database URLs) to C2 domains
- Attempted lateral movement in Kubernetes environments via `node-setup-*` pods

**Advisory:** [MAL-2026-2144](https://osv.dev/vulnerability/MAL-2026-2144) (OSV) / PYSEC-2026-2
**C2 Domains:** `models.litellm.cloud`, `checkmarx.zone`

## Quick Start

```bash
# Detection only
python3 check_litellm_compromise.py

# Verbose output (show all check details)
python3 check_litellm_compromise.py --verbose

# JSON output (for SIEM / automation)
python3 check_litellm_compromise.py --json

# Auto-remediate (interactive confirmation)
python3 check_litellm_compromise.py --fix

# Dry run (show what --fix would do)
python3 check_litellm_compromise.py --fix --dry-run

# Pin litellm to safe version range (blocks compromised versions)
python3 check_litellm_compromise.py --pin

# Full remediate + pin
python3 check_litellm_compromise.py --fix --pin

# Pin dry run
python3 check_litellm_compromise.py --pin --dry-run
```

## What It Checks

| Check | Description |
|-------|-------------|
| **Installed version** | Flags litellm 1.82.7 / 1.82.8 as compromised |
| **Malicious .pth file** | Searches site-packages for `litellm_init.pth` (SHA-256 verified) |
| **Proxy server injection** | Scans `proxy_server.py` for obfuscated payload patterns (requires C2 domain or base64+subprocess co-occurrence to flag — reduces false positives) |
| **Persistence backdoor** | Checks for `sysmon.py`, `sysmon.service`, and staging files |
| **Package cache** | Scans pip and uv caches for cached malicious wheels |
| **C2 connections** | Checks active network connections to known C2 domains |
| **Kubernetes IOCs** | Looks for `node-setup-*` lateral movement pods |
| **Credential exposure** | Identifies high-value env vars that may have been exfiltrated |

## What `--fix` Does

1. Stops and disables the `sysmon` systemd backdoor service
2. Removes persistence files (`~/.config/sysmon/`, `/tmp/p.py`, etc.) — skips symlinks for safety
3. Deletes malicious `litellm_init.pth` from site-packages — skips symlinks for safety
4. Uninstalls the compromised litellm package
5. Purges pip and uv caches of malicious wheels
6. Reinstalls `litellm==1.82.6` (last known clean version)
7. Verifies the clean installation
8. Displays a mandatory credential rotation checklist

## What `--pin` Does

Installs litellm with a version constraint (`litellm>=1.82.4,<1.82.7`) that prevents pip from upgrading into the compromised version range. Can be used standalone or combined with `--fix`.

## Requirements

- Python 3.9+
- No external dependencies (stdlib only)
- Optional: `kubectl` (for Kubernetes IOC checks)
- Optional: `ss` or `netstat` (for network connection checks)

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No critical indicators found |
| `1` | One or more critical indicators detected |
| `2` | Remediation attempted but one or more steps failed |

## References

- [LiteLLM Official Security Advisory](https://docs.litellm.ai/blog/security-update-march-2026)
- [Wiz Research: TeamPCP Trojanizes LiteLLM](https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign)
- [GitHub Issue #24518](https://github.com/BerriAI/litellm/issues/24518)
- [OSV MAL-2026-2144](https://osv.dev/vulnerability/MAL-2026-2144)

## License

MIT
