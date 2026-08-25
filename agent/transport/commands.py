import requests


class CommandClient:

    def __init__(
        self,
        config,
        host,
        timeout=5,
    ):
        self.host = host
        self.timeout = timeout

        self.base_url = (
            config.get("guardian_api_url")
            or ""
        ).rstrip("/")

        if not self.base_url:
            raise ValueError(
                "guardian_url is not configured"
            )

    def poll(self):
        response = requests.post(
            f"{self.base_url}/commands/poll",
            json={
                "host": self.host,
            },
            timeout=self.timeout,
        )

        response.raise_for_status()

        payload = response.json()

        if not payload.get("ok"):
            raise RuntimeError(
                payload.get(
                    "error",
                    "Guardian command poll failed",
                )
            )

        return payload.get(
            "commands",
            [],
        )

    def report_result(
        self,
        command_id,
        status,
        result,
    ):
        response = requests.post(
            f"{self.base_url}/commands/"
            f"{command_id}/result",
            json={
                "status": status,
                "result": result,
            },
            timeout=self.timeout,
        )

        response.raise_for_status()

        return response.json()
