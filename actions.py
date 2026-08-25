class ActionRegistry:

    SAFE_ACTIONS = {
        "alert",
        "log",
        "notify",
    }

    REMOTE_ACTIONS = {
        "block_ip",
        "restart_service",
    }

    def is_known(self, action):
        return (
            action in self.SAFE_ACTIONS
            or action in self.REMOTE_ACTIONS
        )

    def is_safe(self, action):
        return action in self.SAFE_ACTIONS

    def is_remote(self, action):
        return action in self.REMOTE_ACTIONS

    def validate(self, action, data=None):
        data = data or {}

        if not self.is_known(action):
            return {
                "ok": False,
                "reason": (
                    f"Unknown action: {action}"
                ),
            }

        if action == "block_ip":
            ip = data.get("ip")

            if not ip:
                return {
                    "ok": False,
                    "reason": (
                        "block_ip requires ip"
                    ),
                }

        if action == "restart_service":
            service = data.get("service")

            if not service:
                return {
                    "ok": False,
                    "reason": (
                        "restart_service requires service"
                    ),
                }

        return {
            "ok": True,
        }
