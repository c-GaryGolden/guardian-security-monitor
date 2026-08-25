import json
import threading
import time
from pathlib import Path

from privileged.client import PrivilegedClient


class LynisScanner:

    def __init__(
        self,
        emitter,
        interval=7200,
        state_file=None,
        socket_path=(
            "/home/garygolden/agent/"
            "privileged/guardian.sock"
        ),
    ):
        self.emitter = emitter
        self.interval = interval

        self.state_file = Path(
            state_file
            or "/home/garygolden/agent/state/lynis.json"
        )

        self.state_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.privileged = PrivilegedClient(
            socket_path=socket_path,
            timeout=900,
        )

    def start(self):

        thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="lynis-scanner"
        )

        thread.start()

        print(
            f"[*] Lynis scanner started "
            f"(interval={self.interval}s)",
            flush=True
        )

    def _run(self):

        self._scan()

        while True:

            time.sleep(
                self.interval
            )

            self._scan()

    def _scan(self):

        try:

            response = self.privileged.request(
                {
                    "action": "lynis",
                }
            )

            if not response.get("ok"):

                print(
                    f"[!] Lynis privileged server error: "
                    f"{response.get('error', 'unknown error')}",
                    flush=True
                )

                return

            report = response.get(
                "data"
            )

            if not isinstance(
                report,
                dict
            ):

                print(
                    "[!] Invalid Lynis response",
                    flush=True
                )

                return

            print(
                "[AUDIT] "
                f"hardening={report.get('hardening_index')} "
                f"tests={report.get('tests_performed')} "
                f"warnings={report.get('warnings')} "
                f"suggestions={report.get('suggestions')}",
                flush=True
            )

            previous = self._load_state()

            if previous is None:

                self._save_state(
                    report
                )

                print(
                    "[AUDIT] Initial Lynis baseline created",
                    flush=True
                )

                return

            if report == previous:

                print(
                    "[AUDIT] No changes detected",
                    flush=True
                )

                return

            severity = self._calculate_severity(
                previous,
                report
            )

            event = self.emitter.create_event(
                event_type="lynis_audit_change",
                severity=severity,
                source="lynis",
                data={
                    "previous": previous,
                    "current": report,
                },
            )

            self.emitter.emit(
                event
            )

            self._save_state(
                report
            )

        except Exception as exc:

            print(
                f"[!] Lynis scanner error: {exc}",
                flush=True
            )
