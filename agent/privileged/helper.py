#!/usr/bin/env python3

import json
import re
import subprocess
import sys


# =========================
# LYNIS PARSER
# =========================

HARDENING_RE = re.compile(
    r"Hardening index\s*:\s*(\d+)"
)

TESTS_RE = re.compile(
    r"Tests performed\s*:\s*(\d+)"
)

PLUGINS_RE = re.compile(
    r"Plugins enabled\s*:\s*(\d+)"
)

WARNINGS_RE = re.compile(
    r"Warnings \((\d+)\):"
)

SUGGESTIONS_RE = re.compile(
    r"Suggestions \((\d+)\):"
)

FIREWALL_RE = re.compile(
    r"- Firewall\s+\[([VX?])\]"
)

MALWARE_RE = re.compile(
    r"- Malware scanner\s+\[([VX?])\]"
)


def parse_lynis(output):
    hardening = HARDENING_RE.search(output)
    tests = TESTS_RE.search(output)
    plugins = PLUGINS_RE.search(output)
    warnings = WARNINGS_RE.search(output)
    suggestions = SUGGESTIONS_RE.search(output)
    firewall = FIREWALL_RE.search(output)
    malware = MALWARE_RE.search(output)

    if not hardening:
        raise RuntimeError(
            "Could not parse Lynis hardening index"
        )

    return {
        "hardening_index": int(
            hardening.group(1)
        ),
        "tests_performed": (
            int(tests.group(1))
            if tests
            else None
        ),
        "plugins_enabled": (
            int(plugins.group(1))
            if plugins
            else None
        ),
        "warnings": (
            int(warnings.group(1))
            if warnings
            else 0
        ),
        "suggestions": (
            int(suggestions.group(1))
            if suggestions
            else 0
        ),
        "firewall": (
            firewall.group(1) == "V"
            if firewall
            else None
        ),
        "malware_scanner": (
            malware.group(1) == "V"
            if malware
            else None
        ),
    }


# =========================
# SAMBA PARSER
# =========================

def parse_samba_status(output):
    sessions = []

    for line in output.splitlines():
        line = line.strip()

        if not line:
            continue

       

        if not re.match(r"^\d+\s+", line):
            continue

        parts = line.split()

        if len(parts) < 6:
            continue

        pid = parts[0]
        username = parts[1]
        group = parts[2]
        machine = parts[3]

        connection = parts[4]
        protocol = parts[5]

        ip_match = re.search(
            r"ipv4:(\d+\.\d+\.\d+\.\d+):\d+",
            connection
        )

        if ip_match:
            ip = ip_match.group(1)
        else:
            ip_match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)",
                machine
            )

            if not ip_match:
                continue

            ip = ip_match.group(1)

        sessions.append(
            {
                "pid": int(pid),
                "username": username,
                "group": group,
                "ip": ip,
                "protocol": protocol,
            }
        )

    return sessions

# =========================
# LYNIS
# =========================

def run_lynis():
    try:
        result = subprocess.run(
            [
                "lynis",
                "audit",
                "system",
                "--quick",
                "--no-colors",
            ],
            capture_output=True,
            text=True,
            timeout=900,
        )

        if result.returncode != 0:
            return {
                "ok": False,
                "error": (
                    result.stderr.strip()
                    or "Lynis failed"
                ),
            }

        try:
            report = parse_lynis(
                result.stdout
            )

        except Exception as exc:
            return {
                "ok": False,
                "error": (
                    f"Lynis parse error: {exc}"
                ),
            }

        return {
            "ok": True,
            "data": report,
        }

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": "Lynis timeout",
        }

    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
        }


# =========================
# SAMBA STATUS
# =========================

def run_samba_status():
    try:
        result = subprocess.run(
            [
                "smbstatus",
                
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return {
                "ok": False,
                "error": (
                    result.stderr.strip()
                    or "smbstatus failed"
                ),
            }

        try:
            sessions = parse_samba_status(
                result.stdout
            )

        except Exception as exc:
            return {
                "ok": False,
                "error": (
                    f"Samba parse error: {exc}"
                ),
            }

        return {
            "ok": True,
            "data": {
                "sessions": sessions,
            },
        }

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": "smbstatus timeout",
        }

    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
        }


# =========================
# LEGACY DIRECT HELPER
# =========================

def main():
    if len(sys.argv) != 2:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "invalid command",
                }
            )
        )
        sys.exit(1)

    command = sys.argv[1]

    if command == "lynis":
        response = run_lynis()

    elif command == "samba-status":
        response = run_samba_status()

    else:
        response = {
            "ok": False,
            "error": "unsupported command",
        }

        print(
            json.dumps(response)
        )

        sys.exit(1)

    print(
        json.dumps(
            response,
            ensure_ascii=False
        )
    )


if __name__ == "__main__":
    main()
