#!/usr/bin/env python3
"""
LiteLLM Supply Chain Attack Detector

Detects indicators of compromise from the TeamPCP supply chain attack
targeting LiteLLM versions 1.82.7 and 1.82.8 (March 24, 2026).

CVE Reference: PyPI Advisory - litellm 1.82.7 / 1.82.8
Threat Actor: TeamPCP
C2 Domains: models.litellm.cloud, checkmarx.zone

Usage:
    python3 check_litellm_compromise.py                  # detect only
    python3 check_litellm_compromise.py --verbose        # verbose detect
    python3 check_litellm_compromise.py --json           # JSON output
    python3 check_litellm_compromise.py --fix            # detect + auto-remediate
    python3 check_litellm_compromise.py --fix --dry-run  # show what --fix would do
    python3 check_litellm_compromise.py --pin            # pin litellm to safe version range
    python3 check_litellm_compromise.py --fix --pin      # remediate + pin

References:
    https://docs.litellm.ai/blog/security-update-march-2026
    https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign
"""

import sys
import os
import subprocess
import importlib.util
import json
import hashlib
import argparse
import platform
from pathlib import Path
from datetime import datetime, timezone

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

COMPROMISED_VERSIONS  = {"1.82.7", "1.82.8"}
SAFE_VERSIONS_BELOW   = "1.82.6"   # last known clean release
SAFE_REINSTALL_VERSION = "1.82.6"  # version to pin on --fix
SAFE_PIN_CONSTRAINT    = "litellm>=1.82.4,<1.82.7"  # pip constraint to block compromised range

# Known SHA-256 of the malicious .pth file (from GitHub issue #24512)
MALICIOUS_PTH_SHA256 = "71da6fc30c099cd1ebe57a28c6161a6c99e5f56bdf9bcbf06be0fc19d1b534e2"

# Indicators of compromise
IOC_FILES = [
    "~/.config/sysmon/sysmon.py",
    "~/.config/systemd/user/sysmon.service",
    "~/.sysmon.py",
    "/tmp/p.py",
    "/tmp/.p.py",
]

IOC_DIRS = [
    "~/.config/sysmon",
]

C2_DOMAINS = [
    "models.litellm.cloud",
    "checkmarx.zone",
]

MALICIOUS_PTH_NAME = "litellm_init.pth"

# Strings to look for in proxy_server.py (obfuscated payload indicators)
PROXY_SERVER_SUSPICIOUS_STRINGS = [
    "base64.b64decode",
    "subprocess.Popen",
    "exec(base64",
    "models.litellm.cloud",
    "checkmarx.zone",
    "__import__('base64')",
]

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"


def c(color, text):
    """Colorize if stdout is a TTY."""
    if sys.stdout.isatty():
        return f"{color}{text}{RESET}"
    return text


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str]) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


# ──────────────────────────────────────────────
# Check functions — each returns a dict result
# ──────────────────────────────────────────────

def check_installed_version(verbose: bool) -> dict:
    """Check what version of litellm pip reports."""
    result = {
        "check": "installed_version",
        "description": "Verify installed LiteLLM version via pip",
        "status": "unknown",
        "detail": "",
        "critical": False,
    }

    code, out, err = run([sys.executable, "-m", "pip", "show", "litellm"])
    if code != 0:
        result["status"] = "not_installed"
        result["detail"] = "litellm not found in current Python environment."
        return result

    version = None
    for line in out.splitlines():
        if line.lower().startswith("version:"):
            version = line.split(":", 1)[1].strip()
            break

    if not version:
        result["status"] = "unknown"
        result["detail"] = "Could not parse version from pip output."
        return result

    result["version"] = version
    if version in COMPROMISED_VERSIONS:
        result["status"] = "COMPROMISED"
        result["critical"] = True
        result["detail"] = (
            f"CRITICAL: litellm {version} is a known-malicious version. "
            f"Remove immediately and rotate ALL credentials."
        )
    else:
        result["status"] = "ok"
        result["detail"] = f"litellm {version} is not a known-compromised version."

    return result


def check_pth_file(verbose: bool) -> dict:
    """Search all site-packages for the malicious litellm_init.pth file."""
    result = {
        "check": "malicious_pth_file",
        "description": f"Search for {MALICIOUS_PTH_NAME} in site-packages",
        "status": "ok",
        "critical": False,
        "detail": "",
        "found_paths": [],
    }

    # Get all site-packages directories
    import site
    candidates = set(site.getsitepackages())
    if site.getusersitepackages():
        candidates.add(site.getusersitepackages())

    found = []
    for sp in candidates:
        sp_path = Path(sp)
        if not sp_path.exists():
            continue
        pth_path = sp_path / MALICIOUS_PTH_NAME
        if pth_path.exists():
            file_hash = sha256_file(pth_path)
            entry = {
                "path": str(pth_path),
                "size_bytes": pth_path.stat().st_size,
                "sha256": file_hash,
                "hash_matches_known_malicious": file_hash == MALICIOUS_PTH_SHA256,
            }
            found.append(entry)

    if found:
        result["status"] = "COMPROMISED"
        result["critical"] = True
        result["found_paths"] = found
        result["detail"] = (
            f"CRITICAL: {MALICIOUS_PTH_NAME} found. This file executes on every "
            f"Python startup — your environment is actively backdoored."
        )
    else:
        result["detail"] = f"{MALICIOUS_PTH_NAME} not found in site-packages."

    return result


def check_proxy_server_injection(verbose: bool) -> dict:
    """Inspect litellm/proxy/proxy_server.py for injected obfuscated code."""
    result = {
        "check": "proxy_server_injection",
        "description": "Inspect litellm/proxy/proxy_server.py for obfuscated payload",
        "status": "unknown",
        "critical": False,
        "detail": "",
        "hits": [],
    }

    spec = importlib.util.find_spec("litellm")
    if not spec or not spec.origin:
        result["status"] = "not_installed"
        result["detail"] = "litellm package not found."
        return result

    litellm_dir = Path(spec.origin).parent
    proxy_server = litellm_dir / "proxy" / "proxy_server.py"

    if not proxy_server.exists():
        result["status"] = "not_found"
        result["detail"] = f"proxy_server.py not found at {proxy_server}"
        return result

    try:
        content = proxy_server.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        result["status"] = "error"
        result["detail"] = f"Could not read proxy_server.py: {e}"
        return result

    hits = []
    for pattern in PROXY_SERVER_SUSPICIOUS_STRINGS:
        if pattern in content:
            # Find line numbers
            lines = [
                (i + 1, line.strip())
                for i, line in enumerate(content.splitlines())
                if pattern in line
            ]
            hits.append({"pattern": pattern, "lines": lines[:5]})

    result["proxy_server_path"] = str(proxy_server)
    result["file_size_bytes"] = proxy_server.stat().st_size
    result["sha256"] = sha256_file(proxy_server)

    if hits:
        # Reduce false positives: subprocess.Popen alone is legitimate.
        # Only flag as critical if we see a C2 domain OR the combination
        # of base64 obfuscation with subprocess (the actual attack pattern).
        hit_patterns = {h["pattern"] for h in hits}
        has_c2 = bool(hit_patterns & {"models.litellm.cloud", "checkmarx.zone"})
        has_base64 = bool(hit_patterns & {"base64.b64decode", "exec(base64", "__import__('base64')"})
        has_subprocess = bool(hit_patterns & {"subprocess.Popen"})

        if has_c2 or (has_base64 and has_subprocess):
            result["status"] = "SUSPICIOUS"
            result["critical"] = True
            result["hits"] = hits
            result["detail"] = (
                "CRITICAL: proxy_server.py contains suspicious obfuscated patterns. "
                "This is consistent with the TeamPCP payload injection."
            )
        else:
            result["status"] = "ok"
            result["critical"] = False
            result["hits"] = hits
            result["detail"] = (
                "Some patterns matched (e.g. subprocess.Popen) but without C2 domains "
                "or base64 obfuscation — likely legitimate usage."
            )
    else:
        result["status"] = "ok"
        result["detail"] = "No suspicious patterns found in proxy_server.py."

    return result


def check_persistence_files(verbose: bool) -> dict:
    """Look for sysmon persistence backdoor files."""
    result = {
        "check": "persistence_backdoor",
        "description": "Check for sysmon.py / sysmon.service persistence files",
        "status": "ok",
        "critical": False,
        "detail": "",
        "found": [],
    }

    found = []
    for ioc in IOC_FILES + IOC_DIRS:
        expanded = Path(ioc).expanduser()
        if expanded.exists():
            entry = {
                "path": str(expanded),
                "type": "dir" if expanded.is_dir() else "file",
            }
            if expanded.is_file():
                entry["size_bytes"] = expanded.stat().st_size
                try:
                    entry["sha256"] = sha256_file(expanded)
                except Exception:
                    entry["sha256"] = "unreadable"
            found.append(entry)

    if found:
        result["status"] = "COMPROMISED"
        result["critical"] = True
        result["found"] = found
        result["detail"] = (
            "CRITICAL: Backdoor persistence artifacts found. "
            "These are left by the TeamPCP sysmon.service payload."
        )
    else:
        result["detail"] = "No persistence artifacts found."

    return result


def check_pip_cache(verbose: bool) -> dict:
    """Look for the malicious .pth in pip and uv caches."""
    result = {
        "check": "package_cache",
        "description": "Scan pip/uv caches for cached malicious wheels",
        "status": "ok",
        "critical": False,
        "detail": "",
        "found": [],
    }

    cache_dirs = []

    # pip cache
    code, pip_cache, _ = run([sys.executable, "-m", "pip", "cache", "dir"])
    if code == 0 and pip_cache:
        cache_dirs.append(Path(pip_cache))

    # uv cache (common location)
    uv_cache = Path.home() / ".cache" / "uv"
    if uv_cache.exists():
        cache_dirs.append(uv_cache)

    found = []
    for cache_dir in cache_dirs:
        for pth_file in cache_dir.rglob(MALICIOUS_PTH_NAME):
            found.append({
                "path": str(pth_file),
                "cache_root": str(cache_dir),
            })

    if found:
        result["status"] = "WARNING"
        result["critical"] = False  # cached, not yet active
        result["found"] = found
        result["detail"] = (
            "WARNING: Malicious .pth found in package cache. "
            "Run 'pip cache purge' and 'rm -rf ~/.cache/uv' to clean."
        )
    else:
        result["detail"] = "No malicious wheels found in pip/uv cache."

    return result


def check_network_connections(verbose: bool) -> dict:
    """Check for active connections to known C2 domains (best-effort)."""
    result = {
        "check": "c2_network_connections",
        "description": "Check for active connections to C2 domains",
        "status": "ok",
        "critical": False,
        "detail": "",
        "suspicious_connections": [],
    }

    if platform.system() == "Windows":
        code, out, _ = run(["netstat", "-ano"])
    else:
        # Try ss first, fall back to netstat
        code, out, _ = run(["ss", "-tnp"])
        if code != 0:
            code, out, _ = run(["netstat", "-tnp"])

    if code != 0 or not out:
        result["status"] = "skipped"
        result["detail"] = "Could not run network socket inspection (ss/netstat unavailable)."
        return result

    suspicious = []
    for domain in C2_DOMAINS:
        if domain in out:
            suspicious.append(domain)

    if suspicious:
        result["status"] = "SUSPICIOUS"
        result["critical"] = True
        result["suspicious_connections"] = suspicious
        result["detail"] = (
            f"CRITICAL: Active connections detected to C2 domain(s): {suspicious}. "
            "Kill the process and isolate the host immediately."
        )
    else:
        result["detail"] = f"No active connections to known C2 domains ({', '.join(C2_DOMAINS)})."

    return result


def check_kubernetes_ioc(verbose: bool) -> dict:
    """Check for malicious Kubernetes pods if kubectl is available."""
    result = {
        "check": "kubernetes_lateral_movement",
        "description": "Check for node-setup-* pods in Kubernetes (if kubectl available)",
        "status": "skipped",
        "critical": False,
        "detail": "",
        "suspicious_pods": [],
    }

    code, out, err = run(["kubectl", "get", "pods", "--all-namespaces", "--no-headers"])
    if code != 0:
        result["detail"] = "kubectl not available or not connected to a cluster — skipping."
        return result

    suspicious = []
    for line in out.splitlines():
        if "node-setup-" in line:
            suspicious.append(line.strip())

    if suspicious:
        result["status"] = "SUSPICIOUS"
        result["critical"] = True
        result["suspicious_pods"] = suspicious
        result["detail"] = (
            "CRITICAL: Kubernetes pods matching 'node-setup-*' found. "
            "These are consistent with the TeamPCP lateral movement toolkit. "
            "Audit kube-system and rotate ALL cluster secrets immediately."
        )
    else:
        result["status"] = "ok"
        result["detail"] = "No suspicious Kubernetes pods found."

    return result


def check_environment_vars_exposure(verbose: bool) -> dict:
    """Warn about high-value env vars that may have been exfiltrated."""
    result = {
        "check": "sensitive_env_vars_present",
        "description": "Identify high-value credentials in current environment",
        "status": "info",
        "critical": False,
        "detail": "",
        "exposed_vars": [],
    }

    HIGH_VALUE_PREFIXES = [
        "AWS_", "GOOGLE_", "GCP_", "AZURE_", "ANTHROPIC_",
        "OPENAI_", "DATABASE_URL", "DB_", "SECRET", "TOKEN",
        "API_KEY", "PRIVATE_KEY", "KUBECONFIG",
    ]

    found = [
        k for k in os.environ
        if any(k.upper().startswith(p.upper()) for p in HIGH_VALUE_PREFIXES)
    ]

    result["exposed_vars"] = found
    if found:
        result["detail"] = (
            f"Found {len(found)} high-value environment variable(s) in current process scope. "
            f"If this environment ran litellm 1.82.7/1.82.8, rotate these credentials immediately: "
            f"{', '.join(found)}"
        )
    else:
        result["detail"] = "No high-value credential env vars detected in current process scope."

    return result


# ──────────────────────────────────────────────
# Report rendering
# ──────────────────────────────────────────────

STATUS_ICONS = {
    "ok": c(GREEN, "✔ SAFE"),
    "not_installed": c(GREEN, "✔ NOT INSTALLED"),
    "COMPROMISED": c(RED, "✘ COMPROMISED"),
    "SUSPICIOUS": c(YELLOW, "⚠ SUSPICIOUS"),
    "WARNING": c(YELLOW, "⚠ WARNING"),
    "info": c(CYAN, "ℹ INFO"),
    "skipped": "– SKIPPED",
    "unknown": "? UNKNOWN",
    "error": c(YELLOW, "⚠ ERROR"),
    "not_found": c(GREEN, "✔ FILE NOT FOUND"),
}


def render_text_report(results: list[dict], verbose: bool):
    print()
    print(c(BOLD, "=" * 65))
    print(c(BOLD, "  LiteLLM Supply Chain Attack Detector (TeamPCP / March 2026)"))
    print(c(BOLD, "=" * 65))
    print(f"  Host      : {platform.node()}")
    print(f"  Python    : {sys.version.split()[0]}")
    print(f"  Timestamp : {datetime.now(timezone.utc).isoformat()}Z")
    print(c(BOLD, "=" * 65))
    print()

    any_critical = False
    for r in results:
        icon = STATUS_ICONS.get(r["status"], r["status"])
        label = r["description"]
        print(f"  [{icon}]  {label}")
        if verbose or r.get("critical") or r["status"] not in ("ok", "not_installed", "skipped", "not_found"):
            print(f"           → {r['detail']}")
            # Extra detail fields
            for key in ("found_paths", "found", "hits", "suspicious_connections",
                        "suspicious_pods", "exposed_vars"):
                val = r.get(key)
                if val:
                    if isinstance(val, list) and len(val) > 0:
                        for item in val:
                            print(f"             • {item}")
        if r.get("critical"):
            any_critical = True
        print()

    print(c(BOLD, "─" * 65))
    if any_critical:
        print(c(RED, c(BOLD, "  ⛔  RESULT: ONE OR MORE CRITICAL INDICATORS FOUND")))
        print()
        print(c(RED, "  IMMEDIATE ACTIONS REQUIRED:"))
        print("   1. pip uninstall litellm -y && pip cache purge")
        print("   2. rm -rf ~/.cache/uv  (if using uv)")
        print("   3. Rotate ALL credentials: SSH keys, AWS/GCP/Azure tokens,")
        print("      API keys, database passwords, Kubernetes secrets, .env files")
        print("   4. Check ~/.config/sysmon/ and systemd user services")
        print("   5. If on K8s: audit kube-system for node-setup-* pods")
        print("   6. Contact your security team and file an incident")
        print(f"   7. Reference: https://docs.litellm.ai/blog/security-update-march-2026")
    else:
        print(c(GREEN, c(BOLD, "  ✔  RESULT: No critical indicators of compromise detected")))
        print()
        print("  Recommendations:")
        print(f"   • Pin litellm to v1.82.6 or a later verified release")
        print(f"   • Monitor: https://docs.litellm.ai/blog/security-update-march-2026")
    print(c(BOLD, "─" * 65))
    print()


def render_json_report(results: list[dict]):
    report = {
        "tool": "litellm_compromise_detector",
        "timestamp_utc": datetime.now(timezone.utc).isoformat() + "Z",
        "host": platform.node(),
        "python": sys.version.split()[0],
        "compromised_versions": list(COMPROMISED_VERSIONS),
        "overall_status": (
            "COMPROMISED"
            if any(r.get("critical") for r in results)
            else "CLEAN"
        ),
        "checks": results,
    }
    print(json.dumps(report, indent=2))


# ──────────────────────────────────────────────
# Remediation engine
# ──────────────────────────────────────────────

class RemediationAction:
    """Represents a single remediation step with dry-run support."""
    def __init__(self, title: str, detail: str, fn, dry_run: bool):
        self.title   = title
        self.detail  = detail
        self._fn     = fn
        self.dry_run = dry_run
        self.status  = "pending"   # pending | ok | skipped | failed | dry_run
        self.output  = ""

    def execute(self):
        if self.dry_run:
            self.status = "dry_run"
            self.output = "[dry-run] would execute"
            return
        try:
            self.output = self._fn() or ""
            self.status = "ok"
        except Exception as e:
            self.status = "failed"
            self.output = str(e)


def build_remediation_plan(results: list[dict], dry_run: bool, pin: bool = False) -> list[RemediationAction]:
    """
    Given the list of check results, build an ordered list of
    RemediationActions needed to clean the environment.
    """
    actions: list[RemediationAction] = []
    has_litellm = any(
        r["check"] == "installed_version" and r.get("version")
        for r in results
    )
    is_compromised_version = any(
        r["check"] == "installed_version" and r.get("status") == "COMPROMISED"
        for r in results
    )
    has_pth = any(
        r["check"] == "malicious_pth_file" and r.get("status") == "COMPROMISED"
        for r in results
    )
    has_persistence = any(
        r["check"] == "persistence_backdoor" and r.get("status") == "COMPROMISED"
        for r in results
    )
    has_cache = any(
        r["check"] == "package_cache" and r.get("status") == "WARNING"
        for r in results
    )
    has_proxy_injection = any(
        r["check"] == "proxy_server_injection" and r.get("status") == "SUSPICIOUS"
        for r in results
    )

    # ── Step 1: Kill sysmon systemd service if running ──────────────────────
    if has_persistence:
        def _stop_sysmon():
            lines = []
            for cmd in (
                ["systemctl", "--user", "stop", "sysmon"],
                ["systemctl", "--user", "disable", "sysmon"],
            ):
                rc, out, err = run(cmd)
                lines.append(f"$ {' '.join(cmd)} → rc={rc}")
                if out: lines.append(out)
                if err: lines.append(err)
            return "\n".join(lines)

        actions.append(RemediationAction(
            title="Stop sysmon backdoor service",
            detail="systemctl --user stop sysmon && systemctl --user disable sysmon",
            fn=_stop_sysmon,
            dry_run=dry_run,
        ))

    # ── Step 2: Remove persistence files ────────────────────────────────────
    if has_persistence:
        persistence_result = next(
            (r for r in results if r["check"] == "persistence_backdoor"), {}
        )
        found_files = persistence_result.get("found", [])

        def _remove_persistence(files=found_files):
            removed, failed, skipped = [], [], []
            for entry in files:
                p = Path(entry["path"])
                try:
                    if p.is_symlink():
                        skipped.append(f"{p} (symlink → {os.readlink(p)}, skipped for safety)")
                        continue
                    if p.is_dir():
                        import shutil
                        shutil.rmtree(p)
                    else:
                        p.unlink()
                    removed.append(str(p))
                except Exception as e:
                    failed.append(f"{p}: {e}")
            msg = ""
            if removed: msg += "Removed: " + ", ".join(removed)
            if skipped: msg += "\nSkipped: " + ", ".join(skipped)
            if failed:  msg += "\nFailed:  " + ", ".join(failed)
            return msg or "Nothing to remove."

        file_list = ", ".join(e["path"] for e in found_files)
        actions.append(RemediationAction(
            title="Remove persistence/backdoor files",
            detail=f"Delete: {file_list}",
            fn=_remove_persistence,
            dry_run=dry_run,
        ))

    # ── Step 3: Remove malicious .pth files ─────────────────────────────────
    if has_pth:
        pth_result = next(
            (r for r in results if r["check"] == "malicious_pth_file"), {}
        )
        pth_paths = [Path(e["path"]) for e in pth_result.get("found_paths", [])]

        def _remove_pth(paths=pth_paths):
            removed, failed, skipped = [], [], []
            for p in paths:
                try:
                    if p.is_symlink():
                        skipped.append(f"{p} (symlink → {os.readlink(p)}, skipped for safety)")
                        continue
                    p.unlink()
                    removed.append(str(p))
                except Exception as e:
                    failed.append(f"{p}: {e}")
            msg = ""
            if removed: msg += "Removed: " + ", ".join(removed)
            if skipped: msg += "\nSkipped: " + ", ".join(skipped)
            if failed:  msg += "\nFailed:  " + ", ".join(failed)
            return msg or "Nothing to remove."

        actions.append(RemediationAction(
            title=f"Delete malicious {MALICIOUS_PTH_NAME}",
            detail=f"Remove from: {[str(p) for p in pth_paths]}",
            fn=_remove_pth,
            dry_run=dry_run,
        ))

    # ── Step 4: Uninstall litellm ────────────────────────────────────────────
    if is_compromised_version or has_proxy_injection:
        def _uninstall():
            rc, out, err = run([sys.executable, "-m", "pip", "uninstall", "litellm", "-y"])
            return out or err

        actions.append(RemediationAction(
            title="Uninstall compromised litellm",
            detail="pip uninstall litellm -y",
            fn=_uninstall,
            dry_run=dry_run,
        ))

    # ── Step 5: Purge pip cache ──────────────────────────────────────────────
    if has_cache or is_compromised_version:
        def _purge_pip_cache():
            rc, out, err = run([sys.executable, "-m", "pip", "cache", "purge"])
            return out or err or "pip cache purged."

        actions.append(RemediationAction(
            title="Purge pip cache",
            detail="pip cache purge",
            fn=_purge_pip_cache,
            dry_run=dry_run,
        ))

    # ── Step 6: Purge uv cache ───────────────────────────────────────────────
    uv_cache = Path.home() / ".cache" / "uv"
    if uv_cache.exists() and (has_cache or is_compromised_version):
        def _purge_uv_cache(cache_dir=uv_cache):
            import shutil
            # Only remove litellm-related entries to be surgical
            removed = []
            for match in cache_dir.rglob("*litellm*"):
                try:
                    if match.is_dir():
                        shutil.rmtree(match)
                    else:
                        match.unlink()
                    removed.append(str(match))
                except Exception:
                    pass
            return f"Removed {len(removed)} litellm cache entries from {cache_dir}"

        actions.append(RemediationAction(
            title="Purge litellm entries from uv cache",
            detail=f"rm -rf {uv_cache}/*litellm*",
            fn=_purge_uv_cache,
            dry_run=dry_run,
        ))

    # ── Step 7: Reinstall safe version ──────────────────────────────────────
    if is_compromised_version or has_proxy_injection:
        def _reinstall():
            rc, out, err = run([
                sys.executable, "-m", "pip", "install",
                f"litellm=={SAFE_REINSTALL_VERSION}", "--no-cache-dir"
            ])
            if rc == 0:
                return f"Installed litellm=={SAFE_REINSTALL_VERSION} successfully."
            return f"Install failed (rc={rc}): {err or out}"

        actions.append(RemediationAction(
            title=f"Reinstall safe litellm=={SAFE_REINSTALL_VERSION}",
            detail=f"pip install litellm=={SAFE_REINSTALL_VERSION} --no-cache-dir",
            fn=_reinstall,
            dry_run=dry_run,
        ))

    # ── Step 8: Verify clean install ────────────────────────────────────────
    if is_compromised_version or has_proxy_injection:
        def _verify():
            rc, out, err = run([sys.executable, "-m", "pip", "show", "litellm"])
            for line in out.splitlines():
                if line.lower().startswith("version:"):
                    ver = line.split(":", 1)[1].strip()
                    if ver in COMPROMISED_VERSIONS:
                        return f"⛔ Still showing compromised version {ver}!"
                    return f"✔ Verified: litellm=={ver} installed."
            return "litellm not installed (or pip show failed)."

        actions.append(RemediationAction(
            title="Verify clean installation",
            detail="pip show litellm → confirm safe version",
            fn=_verify,
            dry_run=dry_run,
        ))

    # ── Step 9: Pin to safe version range ──────────────────────────────────
    if pin:
        def _pin():
            rc, out, err = run([
                sys.executable, "-m", "pip", "install",
                SAFE_PIN_CONSTRAINT, "--no-cache-dir"
            ])
            if rc == 0:
                return f"Pinned: {SAFE_PIN_CONSTRAINT} — compromised versions are now blocked."
            return f"Pin failed (rc={rc}): {err or out}"

        actions.append(RemediationAction(
            title=f"Pin litellm to safe range ({SAFE_PIN_CONSTRAINT})",
            detail=f"pip install '{SAFE_PIN_CONSTRAINT}' --no-cache-dir",
            fn=_pin,
            dry_run=dry_run,
        ))

    return actions


def render_remediation_plan(actions: list[RemediationAction], dry_run: bool):
    print()
    mode = c(YELLOW, "[DRY RUN] ") if dry_run else ""
    print(c(BOLD, f"  {mode}Remediation Plan — {len(actions)} action(s)"))
    print(c(BOLD, "─" * 65))
    for i, action in enumerate(actions, 1):
        print(f"  {c(CYAN, f'[{i}/{len(actions)}]')} {action.title}")
        print(f"          {c(YELLOW, action.detail)}")
    print()


def execute_remediation(actions: list[RemediationAction], dry_run: bool):
    mode_label = "DRY RUN — " if dry_run else ""

    print(c(BOLD, f"  {mode_label}Executing remediation steps..."))
    print(c(BOLD, "─" * 65))
    for i, action in enumerate(actions, 1):
        prefix = f"  [{i}/{len(actions)}] {action.title}"
        sys.stdout.write(f"{prefix} ... ")
        sys.stdout.flush()
        action.execute()

        STATUS_COLOR = {
            "ok":      (GREEN,  "✔ done"),
            "dry_run": (YELLOW, "~ dry-run"),
            "failed":  (RED,    "✘ FAILED"),
            "skipped": (CYAN,   "– skipped"),
        }
        color, label = STATUS_COLOR.get(action.status, (RESET, action.status))
        print(c(color, label))
        if action.output:
            for line in action.output.strip().splitlines():
                print(f"           {line}")
    print()


def render_credential_rotation_checklist(results: list[dict]):
    """Always shown after a fix — credential rotation is mandatory."""
    exposed_vars = next(
        (r.get("exposed_vars", []) for r in results
         if r["check"] == "sensitive_env_vars_present"), []
    )

    print(c(BOLD, "─" * 65))
    print(c(BOLD + YELLOW, "  ⚠  MANDATORY: Rotate These Credentials"))
    print(c(BOLD, "─" * 65))
    print()
    print("  Regardless of which files were cleaned, if your system ran")
    print("  litellm 1.82.7 or 1.82.8 — assume ALL secrets are exfiltrated.")
    print()

    checklist = [
        ("SSH keys",             "~/.ssh/id_* — revoke authorized_keys on all servers"),
        ("AWS credentials",      "~/.aws/credentials — rotate in IAM console"),
        ("GCP credentials",      "~/.config/gcloud/ — revoke ADC, rotate service account keys"),
        ("Azure tokens",         "~/.azure/ — revoke tokens in Azure AD"),
        ("Anthropic API keys",   "console.anthropic.com → API Keys"),
        ("OpenAI API keys",      "platform.openai.com → API Keys"),
        ("LiteLLM Master Key",   "Set LITELLM_MASTER_KEY, rotate in proxy config"),
        ("Database passwords",   ".env, config files — rotate in your DB console"),
        ("Kubernetes secrets",   "kubectl get secrets --all-namespaces, then rotate"),
        ("Docker Hub / registry","Rotate credentials in registry settings"),
        (".env files",           "Rotate all secrets referenced in any .env"),
    ]

    if exposed_vars:
        print(c(YELLOW, f"  Env vars detected in this process (prioritize these):"))
        for v in exposed_vars:
            print(f"    ⚠  {v}")
        print()

    print("  Full credential rotation checklist:")
    for name, hint in checklist:
        print(f"    ☐  {c(BOLD, name)}")
        print(f"       {hint}")
    print()
    print(c(CYAN, "  Reference: https://docs.litellm.ai/blog/security-update-march-2026"))
    print()


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Detect and remediate LiteLLM supply chain compromise (TeamPCP, March 2026)"
    )
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detail for every check, not just failures")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON (for SIEM / automation ingestion)")
    parser.add_argument("--fix", action="store_true",
                        help="Auto-remediate: remove malicious files, uninstall, reinstall safe version")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what --fix would do without making any changes")
    parser.add_argument("--pin", action="store_true",
                        help="Pin litellm to a safe version range that blocks compromised versions")
    args = parser.parse_args()

    # --dry-run implies --fix (show the plan)
    if args.dry_run:
        args.fix = True

    # ── Run all detection checks ─────────────────────────────────────────
    checks = [
        check_installed_version,
        check_pth_file,
        check_proxy_server_injection,
        check_persistence_files,
        check_pip_cache,
        check_network_connections,
        check_kubernetes_ioc,
        check_environment_vars_exposure,
    ]

    results = []
    for fn in checks:
        try:
            results.append(fn(args.verbose))
        except Exception as e:
            results.append({
                "check": fn.__name__,
                "description": fn.__doc__ or fn.__name__,
                "status": "error",
                "critical": False,
                "detail": f"Check raised an exception: {e}",
            })

    any_critical = any(r.get("critical") for r in results)

    # ── Render detection report ──────────────────────────────────────────
    if args.json and not args.fix:
        render_json_report(results)
        sys.exit(1 if any_critical else 0)

    if not args.json:
        render_text_report(results, args.verbose)

    # ── Remediation ──────────────────────────────────────────────────────
    if args.fix or args.pin:
        actions = build_remediation_plan(results, dry_run=args.dry_run, pin=args.pin)

        if not actions:
            print(c(GREEN, "  ✔ Nothing to remediate — environment appears clean.\n"))
            sys.exit(0)

        render_remediation_plan(actions, dry_run=args.dry_run)

        if not args.dry_run:
            # Confirm before making changes (unless no TTY / piped)
            if sys.stdin.isatty():
                confirm = input(
                    c(YELLOW, "  Proceed with remediation? [y/N] ")
                ).strip().lower()
                if confirm not in ("y", "yes"):
                    print("  Aborted. No changes made.\n")
                    sys.exit(0)

        execute_remediation(actions, dry_run=args.dry_run)

        # Show credential rotation checklist after a fix (not for pin-only)
        if not args.dry_run and args.fix:
            render_credential_rotation_checklist(results)

        # Post-fix summary
        failed = [a for a in actions if a.status == "failed"]
        if failed:
            print(c(RED, f"  ⚠  {len(failed)} action(s) failed — manual cleanup may be required."))
            for a in failed:
                print(f"     • {a.title}: {a.output}")
            sys.exit(2)
        elif not args.dry_run:
            print(c(GREEN, c(BOLD, "  ✔ Remediation complete. Restart any affected processes.")))
            print()

    sys.exit(1 if any_critical else 0)


if __name__ == "__main__":
    main()
