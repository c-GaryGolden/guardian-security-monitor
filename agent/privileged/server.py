#!/usr/bin/env python3
import ipaddress
import grp
import json
import os
import socket
import subprocess
import threading
from pathlib import Path

from helper import parse_lynis, parse_samba_status

# =========================
# CONFIG
# =========================

SOCKET_PATH = Path(
    "/home/garygolden/agent/privileged/guardian.sock"
)

SOCKET_GROUP = "guardian"
SOCKET_MODE = 0o660

ALLOWED_RESTART_SERVICES = {
    "apache2",
}
PROTECTED_IPS = {
    "",
    "",
}

BLOCK_CHAIN = "guardian"



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
                "error": f"Lynis parse error: {exc}",
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
# REQUEST DISPATCHER
# =========================

def handle_request(request):
    if not isinstance(request, dict):
        return {
            "ok": False,
            "error": "request must be a JSON object",
        }

    action = request.get("action")

    if action == "lynis":
        return run_lynis()

    if action == "samba_status":
        return run_samba_status()

    if action == "ping":
        return {
            "ok": True,
            "data": {
                "service": "guardian-privileged",
            },
        }

    if action == "restart_service":
        service = request.get(
            "parameters",
            {},
        ).get("service")

        return run_restart_service(
            service
        )

    if action == "block_ip":
        ip = request.get(
            "parameters",
            {},
        ).get("ip")

        return run_block_ip(
            ip
        )

    if action == "unblock_ip":
        ip = request.get(
            "parameters",
            {},
        ).get("ip")

        return run_unblock_ip(
            ip
        )

    return {
        "ok": False,
        "error": "unsupported action",
    }
# =========================
# SERVICE RESTART
# =========================

def run_restart_service(service):
    if not isinstance(service, str):
        return {
            "ok": False,
            "error": "service must be a string",
        }

    if service not in ALLOWED_RESTART_SERVICES:
        return {
            "ok": False,
            "error": (
                f"service '{service}' "
                "is not allowed"
            ),
        }

    try:
        result = subprocess.run(
            [
                "systemctl",
                "restart",
                service,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            return {
                "ok": False,
                "error": (
                    result.stderr.strip()
                    or (
                        f"failed to restart "
                        f"{service}"
                    )
                ),
            }

        return {
            "ok": True,
            "data": {
                "service": service,
                "action": "restart",
                "message": (
                    f"service {service} "
                    "restarted"
                ),
            },
        }

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": (
                f"restart {service} timeout"
            ),
        }

    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
        }

# =========================
# BLOCK IP
# =========================

def run_block_ip(ip):
    if not isinstance(ip, str):
        return {
            "ok": False,
            "error": "ip must be a string",
        }

    ip = ip.strip()

    if not ip:
        return {
            "ok": False,
            "error": "ip is required",
        }

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {
            "ok": False,
            "error": f"invalid IP address: {ip}",
        }

    normalized_ip = str(address)

    if normalized_ip in PROTECTED_IPS:
        return {
            "ok": False,
            "error": (
                f"protected IP cannot be blocked: "
                f"{normalized_ip}"
            ),
        }

    if address.version != 4:
        return {
            "ok": False,
            "error": (
                "block_ip currently supports "
                "IPv4 only"
            ),
        }

    try:
        # Ensure Guardian table exists.
        table_check = subprocess.run(
            [
                "nft",
                "list",
                "table",
                "inet",
                BLOCK_CHAIN,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if table_check.returncode != 0:
            create_table = subprocess.run(
                [
                    "nft",
                    "add",
                    "table",
                    "inet",
                    BLOCK_CHAIN,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if create_table.returncode != 0:
                return {
                    "ok": False,
                    "error": (
                        create_table.stderr.strip()
                        or "failed to create guardian nft table"
                    ),
                }

        # Ensure Guardian input chain exists.
        chain_check = subprocess.run(
            [
                "nft",
                "list",
                "chain",
                "inet",
                BLOCK_CHAIN,
                "guardian_input",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if chain_check.returncode != 0:
            create_chain = subprocess.run(
                [
                    "nft",
                    "add",
                    "chain",
                    "inet",
                    BLOCK_CHAIN,
                    "guardian_input",
                    "{",
                    "type",
                    "filter",
                    "hook",
                    "input",
                    "priority",
                    "0;",
                    "policy",
                    "accept;",
                    "}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if create_chain.returncode != 0:
                return {
                    "ok": False,
                    "error": (
                        create_chain.stderr.strip()
                        or "failed to create guardian_input chain"
                    ),
                }

        # Check for an existing rule.
        rules = subprocess.run(
            [
                "nft",
                "list",
                "chain",
                "inet",
                BLOCK_CHAIN,
                "guardian_input",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if rules.returncode != 0:
            return {
                "ok": False,
                "error": (
                    rules.stderr.strip()
                    or "failed to list guardian rules"
                ),
            }

        if (
            f"ip saddr {normalized_ip} drop"
            in rules.stdout
        ):
            return {
                "ok": True,
                "data": {
                    "ip": normalized_ip,
                    "action": "block_ip",
                    "message": "IP is already blocked",
                    "enforced": True,
                    "existing": True,
                },
            }

        # Add the block rule.
        add_rule = subprocess.run(
            [
                "nft",
                "add",
                "rule",
                "inet",
                BLOCK_CHAIN,
                "guardian_input",
                "ip",
                "saddr",
                normalized_ip,
                "drop",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if add_rule.returncode != 0:
            return {
                "ok": False,
                "error": (
                    add_rule.stderr.strip()
                    or "failed to add block rule"
                ),
            }

        return {
            "ok": True,
            "data": {
                "ip": normalized_ip,
                "action": "block_ip",
                "message": f"IP {normalized_ip} blocked",
                "enforced": True,
                "existing": False,
            },
        }

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": "nft command timeout",
        }

    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
        }
        # =========================
        # ENSURE TABLE
        # =========================

        table_check = subprocess.run(
            [
                "nft",
                "list",
                "table",
                "inet",
                BLOCK_CHAIN,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if table_check.returncode != 0:
            create_table = subprocess.run(
                [
                    "nft",
                    "add",
                    "table",
                    "inet",
                    BLOCK_CHAIN,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if create_table.returncode != 0:
                return {
                    "ok": False,
                    "error": (
                        create_table.stderr.strip()
                        or (
                            "failed to create "
                            "guardian nft table"
                        )
                    ),
                }

        # =========================
        # ENSURE CHAIN
        # =========================

        chain_check = subprocess.run(
            [
                "nft",
                "list",
                "chain",
                "inet",
                BLOCK_CHAIN,
                "guardian_input",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if chain_check.returncode != 0:
            create_chain = subprocess.run(
                [
                    "nft",
                    "add",
                    "chain",
                    "inet",
                    BLOCK_CHAIN,
                    "guardian_input",
                    "{",
                    "type",
                    "filter",
                    "hook",
                    "input",
                    "priority",
                    "0;",
                    "policy",
                    "accept;",
                    "}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if create_chain.returncode != 0:
                return {
                    "ok": False,
                    "error": (
                        create_chain.stderr.strip()
                        or (
                            "failed to create "
                            "guardian_input chain"
                        )
                    ),
                }

        # =========================
        # CHECK EXISTING RULE
        # =========================

        rules = subprocess.run(
            [
                "nft",
                "list",
                "chain",
                "inet",
                BLOCK_CHAIN,
                "guardian_input",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if rules.returncode != 0:
            return {
                "ok": False,
                "error": (
                    rules.stderr.strip()
                    or "failed to list guardian rules"
                ),
            }

        rule_text = rules.stdout

        if (
            f"ip saddr {normalized_ip} drop"
            in rule_text
        ):
            return {
                "ok": True,
                "data": {
                    "ip": normalized_ip,
                    "action": "block_ip",
                    "message": (
                        "IP is already blocked"
                    ),
                    "enforced": True,
                    "existing": True,
                },
            }

        # =========================
        # ADD BLOCK RULE
        # =========================

        add_rule = subprocess.run(
            [
                "nft",
                "add",
                "rule",
                "inet",
                BLOCK_CHAIN,
                "guardian_input",
                "ip",
                "saddr",
                normalized_ip,
                "drop",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if add_rule.returncode != 0:
            return {
                "ok": False,
                "error": (
                    add_rule.stderr.strip()
                    or (
                        "failed to add "
                        "block rule"
                    )
                ),
            }

        return {
            "ok": True,
            "data": {
                "ip": normalized_ip,
                "action": "block_ip",
                "message": (
                    f"IP {normalized_ip} "
                    "blocked"
                ),
                "enforced": True,
                "existing": False,
            },
        }

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": "nft command timeout",
        }

    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
        }

# =========================
# UNBLOCK IP
# =========================

def run_unblock_ip(ip):
    if not isinstance(ip, str):
        return {
            "ok": False,
            "error": "ip must be a string",
        }

    ip = ip.strip()

    if not ip:
        return {
            "ok": False,
            "error": "ip is required",
        }

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {
            "ok": False,
            "error": f"invalid IP address: {ip}",
        }

    normalized_ip = str(address)

    if address.version != 4:
        return {
            "ok": False,
            "error": (
                "unblock_ip currently supports "
                "IPv4 only"
            ),
        }

    try:
        rules = subprocess.run(
            [
                "nft",
                "-a",
                "list",
                "chain",
                "inet",
                BLOCK_CHAIN,
                "guardian_input",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if rules.returncode != 0:
            return {
                "ok": False,
                "error": (
                    rules.stderr.strip()
                    or "failed to list guardian rules"
                ),
            }

        rule_handle = None

        for line in rules.stdout.splitlines():
            if (
                f"ip saddr {normalized_ip} drop"
                in line
                and "handle " in line
            ):
                rule_handle = line.rsplit(
                    "handle ",
                    1,
                )[1].strip()
                break

        if not rule_handle:
            return {
                "ok": True,
                "data": {
                    "ip": normalized_ip,
                    "action": "unblock_ip",
                    "message": (
                        "IP is not currently blocked"
                    ),
                    "removed": False,
                },
            }

        delete_rule = subprocess.run(
            [
                "nft",
                "delete",
                "rule",
                "inet",
                BLOCK_CHAIN,
                "guardian_input",
                "handle",
                rule_handle,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if delete_rule.returncode != 0:
            return {
                "ok": False,
                "error": (
                    delete_rule.stderr.strip()
                    or "failed to remove block rule"
                ),
            }

        return {
            "ok": True,
            "data": {
                "ip": normalized_ip,
                "action": "unblock_ip",
                "message": (
                    f"IP {normalized_ip} unblocked"
                ),
                "removed": True,
            },
        }

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": "nft command timeout",
        }

    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
        }




# =========================
# CLIENT HANDLER
# =========================

def handle_client(conn):
    try:
        raw = conn.recv(65536)

        if not raw:
            return

        request = json.loads(
            raw.decode("utf-8")
        )

        response = handle_request(
            request
        
            
        )

        payload = json.dumps(
            response,
            ensure_ascii=False
        ).encode("utf-8")

        conn.sendall(
            payload
        )

    except json.JSONDecodeError as exc:
        response = {
            "ok": False,
            "error": f"invalid JSON: {exc}",
        }

        try:
            conn.sendall(
                json.dumps(
                    response
                ).encode("utf-8")
            )
        except Exception:
            pass

    except Exception as exc:
        response = {
            "ok": False,
            "error": str(exc),
        }

        try:
            conn.sendall(
                json.dumps(
                    response
                ).encode("utf-8")
            )
        except Exception:
            pass

    finally:
        conn.close()


# =========================
# SOCKET SETUP
# =========================

def setup_socket():
    if SOCKET_PATH.exists():
        SOCKET_PATH.unlink()

    server = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM
    )

    server.bind(
        str(SOCKET_PATH)
    )

    guardian_gid = grp.getgrnam(
        SOCKET_GROUP
    ).gr_gid

    os.chown(
        SOCKET_PATH,
        0,
        guardian_gid
    )

    os.chmod(
        SOCKET_PATH,
        SOCKET_MODE
    )

    server.listen(5)

    return server


# =========================
# MAIN
# =========================

def main():
    if os.geteuid() != 0:
        raise SystemExit(
            "Privileged server must run as root"
        )

    try:
        server = setup_socket()

    except KeyError:
        raise SystemExit(
            f"Group '{SOCKET_GROUP}' does not exist"
        )

    print(
        "[*] Privileged server listening on "
        f"{SOCKET_PATH}",
        flush=True
    )

    try:
        while True:
            conn, _ = server.accept()

            thread = threading.Thread(
                target=handle_client,
                args=(conn,),
                daemon=True,
                name="privileged-client",
            )

            thread.start()

    except KeyboardInterrupt:
        print(
            "\n[*] Privileged server stopping",
            flush=True
        )

    finally:
        server.close()

        try:
            if SOCKET_PATH.exists():
                SOCKET_PATH.unlink()
        except OSError:
            pass


if __name__ == "__main__":
    main()
