import threading
import time

import requests

from privileged.client import PrivilegedClient


class HeartbeatClient:

    def __init__(
        self,
        config,
        host,
        interval=10,
    ):
        self.config = config
        self.host = host
        self.interval = interval

        self.guardian_api_url = config.get(
            "guardian_api_url",
            "http://192.168.10.200:8000",
        )

        self.privileged = PrivilegedClient(
            socket_path=config.get(
                "samba",
                {},
            ).get(
                "socket_path",
                "/home/garygolden/agent/privileged/guardian.sock",
            ),
            timeout=5,
        )

        self._thread = None
        self._stop_event = threading.Event()

    def start(self):
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="guardian-heartbeat",
        )

        self._thread.start()

        print(
            f"[*] Guardian heartbeat started "
            f"(interval={self.interval}s)",
            flush=True,
        )

    def stop(self):
        self._stop_event.set()

        if self._thread is not None:
            self._thread.join(
                timeout=5
            )

    def _run(self):
        while not self._stop_event.is_set():

            privileged_ok = False

            try:
                response = self.privileged.request(
                    {
                        "action": "ping",
                    }
                )

                privileged_ok = bool(
                    response.get("ok")
                )

            except Exception:
                privileged_ok = False

            try:
                requests.post(
                    f"{self.guardian_api_url}/heartbeat",
                    json={
                        "host": self.host,
                        "privileged": privileged_ok,
                    },
                    timeout=5,
                )

            except Exception as exc:
                print(
                    f"[!] Heartbeat error: {exc}",
                    flush=True,
                )

            self._stop_event.wait(
                self.interval
            )
