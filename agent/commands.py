import ipaddress
import time

import yaml

from privileged.client import PrivilegedClient


class CommandHandler:

    SAFE_ACTIONS = {
        "notify",
        "log",
        "alert",
    }

    ALLOWED_SERVICES = {
        "apache2",
    }

    def __init__(
        self,
        config=None,
        cooldown_seconds=60,
        max_actions=10,
        window_seconds=300,
    ):
        if config is None:
            try:
                with open(
                    "config.yaml",
                    "r",
                    encoding="utf-8",
                ) as f:
                    config = yaml.safe_load(f) or {}
            except FileNotFoundError:
                config = {}

        reaction_config = config.get(
            "reaction",
            {},
        )

        self.privileged = PrivilegedClient()

        self.cooldown_seconds = cooldown_seconds
        self.max_actions = max_actions
        self.window_seconds = window_seconds

        self.protected_host = (
            reaction_config.get(
                "protected_host"
            )
        )

        self.protected_ips = {
            str(ip)
            for ip in reaction_config.get(
                "protected_ips",
                [],
            )
        }

        self.blocked_ip_cooldown = (
            reaction_config.get(
                "blocked_ip_cooldown",
                300,
            )
        )

        self.max_block_actions = (
            reaction_config.get(
                "max_block_actions",
                5,
            )
        )

        self.block_window = (
            reaction_config.get(
                "block_window",
                300,
            )
        )

        self._last_action = {}
        self._action_history = []
        self._block_history = []

    def execute(self, command):
        if not isinstance(command, dict):
            return self._rejected(
                "command must be an object"
            )

        action = command.get("action")
        parameters = command.get(
            "parameters",
            {},
        )

        if not isinstance(action, str):
            return self._rejected(
                "action must be a string"
            )

        if not isinstance(parameters, dict):
            return self._rejected(
                "parameters must be an object"
            )

        if action in self.SAFE_ACTIONS:
            return self._execute_safe(
                action,
                parameters,
            )

        if action == "restart_service":
            return self._restart_service(
                parameters
            )

        if action == "block_ip":
            return self._block_ip(
                parameters
            )

        if action == "unblock_ip":
            return self._unblock_ip(
                parameters
            )

        return self._rejected(
            f"Action '{action}' is not allowed"
        )

    def _execute_safe(
        self,
        action,
        parameters,
    ):
        if action == "notify":
            return {
                "status": "executed",
                "result": {
                    "ok": True,
                    "message": parameters.get(
                        "message",
                        "Guardian notification",
                    ),
                },
            }

        if action == "log":
            return {
                "status": "executed",
                "result": {
                    "ok": True,
                    "message": "Guardian log action",
                },
            }

        if action == "alert":
            return {
                "status": "executed",
                "result": {
                    "ok": True,
                    "message": "Guardian alert",
                },
            }

        return self._rejected(
            "Unsupported safe action"
        )

    def _restart_service(
        self,
        parameters,
    ):
        service = parameters.get("service")

        if not isinstance(service, str):
            return self._rejected(
                "restart_service requires service"
            )

        if service not in self.ALLOWED_SERVICES:
            return self._rejected(
                f"Service '{service}' is not allowed"
            )

        rate_check = self._check_rate_limit(
            action="restart_service",
            target=service,
        )

        if not rate_check["ok"]:
            return self._rejected(
                rate_check["reason"]
            )

        try:
            response = self.privileged.request(
                {
                    "action": "restart_service",
                    "parameters": {
                        "service": service,
                    },
                }
            )

            if not response.get("ok"):
                return {
                    "status": "failed",
                    "result": response,
                }

            self._record_action(
                action="restart_service",
                target=service,
            )

            return {
                "status": "executed",
                "result": response.get(
                    "data",
                    response,
                ),
            }

        except Exception as exc:
            return {
                "status": "failed",
                "result": {
                    "ok": False,
                    "reason": str(exc),
                },
            }

    def _block_ip(self, parameters):
        ip = parameters.get("ip")

        validation = self._validate_ip(ip)

        if not validation["ok"]:
            return self._rejected(
                validation["reason"]
            )

        normalized_ip = validation["ip"]

        if normalized_ip in self.protected_ips:
            return self._rejected(
                f"Protected IP cannot be blocked: {normalized_ip}"
            )

        rate_check = self._check_block_rate_limit(
            normalized_ip
        )

        if not rate_check["ok"]:
            return self._rejected(
                rate_check["reason"]
            )

        try:
            response = self.privileged.request(
                {
                    "action": "block_ip",
                    "parameters": {
                        "ip": normalized_ip,
                    },
                }
            )

            if not response.get("ok"):
                return {
                    "status": "failed",
                    "result": response,
                }

            self._record_block(
                normalized_ip
            )

            return {
                "status": "executed",
                "result": response.get(
                    "data",
                    response,
                ),
            }

        except Exception as exc:
            return {
                "status": "failed",
                "result": {
                    "ok": False,
                    "reason": str(exc),
                },
            }

    def _unblock_ip(self, parameters):
        ip = parameters.get("ip")

        validation = self._validate_ip(ip)

        if not validation["ok"]:
            return self._rejected(
                validation["reason"]
            )

        normalized_ip = validation["ip"]

        try:
            response = self.privileged.request(
                {
                    "action": "unblock_ip",
                    "parameters": {
                        "ip": normalized_ip,
                    },
                }
            )

            if not response.get("ok"):
                return {
                    "status": "failed",
                    "result": response,
                }

            return {
                "status": "executed",
                "result": response.get(
                    "data",
                    response,
                ),
            }

        except Exception as exc:
            return {
                "status": "failed",
                "result": {
                    "ok": False,
                    "reason": str(exc),
                },
            }

    @staticmethod
    def _validate_ip(ip):
        if not isinstance(ip, str):
            return {
                "ok": False,
                "reason": "ip must be a string",
            }

        ip = ip.strip()

        if not ip:
            return {
                "ok": False,
                "reason": "ip is required",
            }

        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return {
                "ok": False,
                "reason": f"Invalid IP address: {ip}",
            }

        if address.version != 4:
            return {
                "ok": False,
                "reason": (
                    "block_ip/unblock_ip "
                    "currently support IPv4 only"
                ),
            }

        return {
            "ok": True,
            "ip": str(address),
        }

    def _check_rate_limit(
        self,
        action,
        target,
    ):
        now = time.monotonic()

        key = (
            action,
            target,
        )

        last = self._last_action.get(key)

        if (
            last is not None
            and now - last < self.cooldown_seconds
        ):
            remaining = (
                self.cooldown_seconds
                - (now - last)
            )

            return {
                "ok": False,
                "reason": (
                    f"Cooldown active for "
                    f"{action}:{target}; "
                    f"retry in {remaining:.1f}s"
                ),
            }

        cutoff = now - self.window_seconds

        self._action_history = [
            timestamp
            for timestamp in self._action_history
            if timestamp >= cutoff
        ]

        if len(
            self._action_history
        ) >= self.max_actions:
            return {
                "ok": False,
                "reason": (
                    "Global reaction rate "
                    "limit exceeded"
                ),
            }

        return {
            "ok": True,
        }

    def _record_action(
        self,
        action,
        target,
    ):
        now = time.monotonic()

        self._last_action[
            (action, target)
        ] = now

        self._action_history.append(now)

    def _check_block_rate_limit(self, ip):
        now = time.monotonic()

        for entry in self._block_history:
            if entry["ip"] != ip:
                continue

            elapsed = now - entry["time"]

            if elapsed < self.blocked_ip_cooldown:
                remaining = (
                    self.blocked_ip_cooldown
                    - elapsed
                )

                return {
                    "ok": False,
                    "reason": (
                        f"Block cooldown active "
                        f"for {ip}; retry in "
                        f"{remaining:.1f}s"
                    ),
                }

        cutoff = now - self.block_window

        self._block_history = [
            entry
            for entry in self._block_history
            if entry["time"] >= cutoff
        ]

        if len(
            self._block_history
        ) >= self.max_block_actions:
            return {
                "ok": False,
                "reason": (
                    "Global block_ip rate "
                    "limit exceeded"
                ),
            }

        return {
            "ok": True,
        }

    def _record_block(self, ip):
        self._block_history.append(
            {
                "ip": ip,
                "time": time.monotonic(),
            }
        )

    @staticmethod
    def _rejected(reason):
        return {
            "status": "rejected",
            "result": {
                "ok": False,
                "reason": reason,
            },
        }
