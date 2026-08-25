import re
import threading
import time


class ApacheCollector:

    HTTP_REQUEST = re.compile(
        r'^(\S+) \S+ \S+ \[([^\]]+)\] '
        r'"([^"]*)" (\d{3}) (\S+)'
    )

    def __init__(self, config, emitter):

        self.config = config
        self.emitter = emitter

        self.access_log = config.get(
            "apache_access_log",
            "/var/log/apache2/access.log"
        )

        self.error_log = config.get(
            "apache_error_log",
            "/var/log/apache2/error.log"
        )

    def start(self):

        threading.Thread(
            target=self._watch_access,
            name="apache-access",
            daemon=True
        ).start()

        threading.Thread(
            target=self._watch_error,
            name="apache-error",
            daemon=True
        ).start()

        print(
            f"[*] Apache collector started: {self.access_log}",
            flush=True
        )

        print(
            f"[*] Apache error watcher started: {self.error_log}",
            flush=True
        )

    def _watch_access(self):

        self._watch_file(
            self.access_log,
            self._process_access
        )

    def _watch_error(self):

        self._watch_file(
            self.error_log,
            self._process_error
        )

    def _watch_file(self, path, handler):

        try:

            with open(
                path,
                "r",
                encoding="utf-8",
                errors="replace"
            ) as log:

                log.seek(0, 2)

                while True:

                    line = log.readline()

                    if not line:
                        time.sleep(0.5)
                        continue

                    handler(line.strip())

        except PermissionError:

            print(
                f"[!] Apache collector: "
                f"permission denied: {path}",
                flush=True
            )

        except FileNotFoundError:

            print(
                f"[!] Apache collector: "
                f"log not found: {path}",
                flush=True
            )

        except Exception as e:

            print(
                f"[!] Apache collector error: {e}",
                flush=True
            )

    def _process_access(self, line):

        match = self.HTTP_REQUEST.match(line)

        if not match:
            return

        ip = match.group(1)
        request = match.group(3)
        status = int(match.group(4))
        size = match.group(5)

        severity = "info"

        if status >= 500:
            severity = "high"

        elif status >= 400:
            severity = "medium"

        self.emitter.emit(
            self.emitter.create_event(
                event_type="apache_request",
                severity=severity,
                source="apache_access_log",
                data={
                    "ip": ip,
                    "request": request,
                    "status": status,
                    "size": size
                }
            )
        )

    def _process_error(self, line):

        if not line:
            return

        severity = "medium"

        if any(
            keyword in line.lower()
            for keyword in (
                "critical",
                "emerg",
                "alert"
            )
        ):
            severity = "high"

        self.emitter.emit(
            self.emitter.create_event(
                event_type="apache_error",
                severity=severity,
                source="apache_error_log",
                data={
                    "message": line
                }
            )
        )
