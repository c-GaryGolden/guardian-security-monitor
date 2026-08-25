import threading
import time


class CommandPoller:

    def __init__(
        self,
        client,
        handler,
        interval=10,
    ):
        self.client = client
        self.handler = handler
        self.interval = interval

        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if (
            self._thread is not None
            and self._thread.is_alive()
        ):
            return

        self._thread = threading.Thread(
            target=self._run,
            name="guardian-command-poller",
            daemon=True,
        )

        self._thread.start()

        print(
            "[*] Guardian command poller started "
            f"(interval={self.interval}s)",
            flush=True,
        )

    def stop(self):
        self._stop_event.set()

        if self._thread is not None:
            self._thread.join(
                timeout=self.interval + 2
            )

        print(
            "[*] Guardian command poller stopped",
            flush=True,
        )

    def _run(self):
        while not self._stop_event.is_set():

            try:
                self._poll_once()

            except Exception as exc:
                print(
                    "[!] Command poller error: "
                    f"{exc}",
                    flush=True,
                )

            self._stop_event.wait(
                self.interval
            )

    def _poll_once(self):
        commands = self.client.poll()

        if not commands:
            return

        print(
            f"[COMMAND] received={len(commands)}",
            flush=True,
        )

        for command in commands:
            self._process(command)

    def _process(self, command):
        command_id = command.get(
            "id"
        )

        action = command.get(
            "action"
        )

        print(
            "[COMMAND] "
            f"id={command_id} "
            f"action={action}",
            flush=True,
        )

        try:
            result = self.handler.execute(
                command
            )

            status = result.get(
                "status",
                "failed",
            )

            payload = result.get(
                "result",
                {
                    "ok": False,
                    "message": (
                        "Command handler "
                        "returned no result"
                    ),
                },
            )

        except Exception as exc:
            status = "failed"

            payload = {
                "ok": False,
                "message": str(exc),
            }

        try:
            response = self.client.report_result(
                command_id=command_id,
                status=status,
                result=payload,
            )

            print(
                "[COMMAND] "
                f"id={command_id} "
                f"status={status} "
                f"reported={response.get('ok')}",
                flush=True,
            )

        except Exception as exc:
            print(
                "[!] Command result report error "
                f"id={command_id}: {exc}",
                flush=True,
            )
