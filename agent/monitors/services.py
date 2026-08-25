import subprocess
import threading
import time


class ServiceMonitor:
    def __init__(self, emitter, services, interval=30):
        self.emitter = emitter
        self.services = services
        self.interval = interval
        self.previous_states = {}

    def _get_status(self, service):
        try:
            result = subprocess.run(
                ["systemctl", "is-active", service],
                capture_output=True,
                text=True,
                timeout=5,
            )

            status = result.stdout.strip()

            if not status:
                status = "unknown"

            return status

        except Exception as exc:
            print(
                f"[!] Service status error ({service}): {exc}",
                flush=True
            )
            return "unknown"

    def _check_services(self):
        for service in self.services:
            status = self._get_status(service)
            previous = self.previous_states.get(service)

            print(
                f"[SERVICE] {service} = {status}",
                flush=True
            )

            # Pierwszy odczyt — zapamiętujemy stan,
            # ale nie generujemy alarmu.
            if previous is None:
                self.previous_states[service] = status
                continue

            # Event tylko przy zmianie stanu.
            if status != previous:
                severity = (
                    "high"
                    if status not in ("active", "activating")
                    else "info"
                )

                event = self.emitter.create_event(
                    event_type="service_status",
                    severity=severity,
                    source="systemd",
                    data={
                        "service": service,
                        "previous_status": previous,
                        "status": status,
                    },
                )

                self.emitter.emit(event)

                print(
                    f"[SERVICE] CHANGE "
                    f"{service}: {previous} -> {status}",
                    flush=True
                )

                self.previous_states[service] = status

    def _run(self):
        print(
            "[*] Service monitor active",
            flush=True
        )

        while True:
            self._check_services()
            time.sleep(self.interval)

    def start(self):
        if not self.services:
            print(
                "[!] Service monitor disabled: "
                "no services configured",
                flush=True
            )
            return

        thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="service-monitor",
        )

        thread.start()
