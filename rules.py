class RuleEngine:

    def evaluate(self, event):
        matches = []

        # =========================
        # SSH BRUTE FORCE
        # =========================

        if (
            event.get("type") == "ssh_bruteforce"
            and event.get("severity") == "high"
        ):
            matches.append(
                {
                    "rule": "ssh_bruteforce_high",
                    "action": "alert",
                    "reason": (
                        "High severity SSH brute-force event"
                    ),
                }
            )

        # =========================
        # CRITICAL SERVICE CHANGE
        # =========================

        if (
            event.get("type") == "service_status"
            and event.get("severity") == "high"
        ):
            matches.append(
                {
                    "rule": "critical_service_change",
                    "action": "alert",
                    "reason": (
                        "High severity service state change"
                    ),
                }
            )

        # =========================
        # LYNIS REGRESSION
        # =========================

        if event.get("type") == "lynis_audit_change":
            data = event.get(
                "data",
                {}
            )

            previous = data.get(
                "previous",
                {}
            )

            current = data.get(
                "current",
                {}
            )

            old_score = previous.get(
                "hardening_index"
            )

            new_score = current.get(
                "hardening_index"
            )

            if (
                old_score is not None
                and new_score is not None
                and new_score < old_score
            ):
                matches.append(
                    {
                        "rule": "lynis_regression",
                        "action": "alert",
                        "reason": (
                            f"Lynis hardening dropped "
                            f"from {old_score} to {new_score}"
                        ),
                    }
                )

        # =========================
        # SAMBA SESSION CLOSED
        # =========================

        if (
            event.get("type") == "samba_session"
            and event.get("data", {}).get("status")
            == "disconnected"
        ):
            matches.append(
                {
                    "rule": "samba_session_closed",
                    "action": "log",
                    "reason": (
                        "SMB session disconnected"
                    ),
                }
            )

        return matches
