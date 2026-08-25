import requests


class GuardianTransport:

    def __init__(
        self,
        config,
        timeout=3,
    ):
        self.guardian_url = config.get(
            "guardian_url"
        )

        self.timeout = timeout

        if not self.guardian_url:
            raise ValueError(
                "guardian_url is not configured"
            )

    def send(self, event):

        response = requests.post(
            self.guardian_url,
            json=event.to_dict(),
            timeout=self.timeout,
        )

        response.raise_for_status()

        print(
            "[GUARDIAN] Event sent "
            f"type={event.type} "
            f"status={response.status_code}",
            flush=True,
        )
