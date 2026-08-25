import json
import socket


class PrivilegedClient:

    def __init__(
        self,
        socket_path="/home/garygolden/agent/privileged/guardian.sock",
        timeout=15,
    ):
        self.socket_path = socket_path
        self.timeout = timeout

    def request(self, request):
        if not isinstance(
            request,
            dict,
        ):
            raise TypeError(
                "request must be a dict"
            )

        action = request.get(
            "action"
        )

        if not isinstance(
            action,
            str,
        ):
            raise ValueError(
                "request.action must be a string"
            )

        request_timeout = self.timeout

        if action == "lynis":
            request_timeout = 900

        sock = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )

        sock.settimeout(
            request_timeout
        )

        try:
            sock.connect(
                self.socket_path
            )

            payload = json.dumps(
                request,
                ensure_ascii=False,
            ).encode("utf-8")

            sock.sendall(
                payload
            )

            response = sock.recv(
                1024 * 1024
            )

            if not response:
                raise RuntimeError(
                    "Privileged server returned empty response"
                )

            return json.loads(
                response.decode("utf-8")
            )

        finally:
            sock.close()
