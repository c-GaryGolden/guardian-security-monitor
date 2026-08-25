from datetime import datetime, timezone


class ReactionEngine:

    SAFE_ACTIONS = {
        "alert",
        "log",
        "notify",
    }

    def __init__(
        self,
        mode="dry_run",
    ):
        if mode not in {
            "dry_run",
            "enforce_safe",
            "enforce",
        }:
            raise ValueError(
                "mode must be "
                "'dry_run', "
                "'enforce_safe' "
                "or 'enforce'"
            )

        self.mode = mode

    def execute(self, incident):
        action = incident.get(
            "action"
        )

        if action not in self.SAFE_ACTIONS:
            return {
                "ok": False,
                "status": "rejected",
                "reason": (
                    f"Action '{action}' "
                    "is not allowed"
                ),
            }

        if self.mode == "dry_run":
            return self._simulate(
                incident
            )

        if self.mode == "enforce_safe":
            return self._execute_safe(
                incident
            )

        return {
            "ok": False,
            "status": "rejected",
            "reason": (
                "Full enforce mode is not "
                "implemented yet"
            ),
        }

    def _simulate(self, incident):
        action = incident["action"]

        message = (
            incident.get("reason")
            or "Guardian reaction"
        )

        result = {
            "ok": True,
            "status": "simulated",
            "action": action,
            "message": message,
        }

        self._print_reaction(
            result
        )

        return result

    def _execute_safe(self, incident):
        action = incident["action"]

        message = (
            incident.get("reason")
            or "Guardian safe reaction"
        )

        result = {
            "ok": True,
            "status": "executed",
            "action": action,
            "message": message,
        }

        self._print_reaction(
            result
        )

        return result

    @staticmethod
    def _print_reaction(result):
        timestamp = datetime.now(
            timezone.utc
        ).isoformat()

        print(
            "[REACTION] "
            f"time={timestamp} "
            f"action={result['action']} "
            f"status={result['status']} "
            f"message={result['message']}",
            flush=True,
        )
