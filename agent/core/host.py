import socket
import subprocess


def get_host_ip() -> str:

    try:
        output = subprocess.check_output(
            ["hostname", "-I"],
            text=True
        )

        for address in output.split():

            if ":" not in address and not address.startswith("127."):
                return address

    except Exception:
        pass

    try:
        return socket.gethostbyname(
            socket.gethostname()
        )

    except Exception:
        return "unknown"
