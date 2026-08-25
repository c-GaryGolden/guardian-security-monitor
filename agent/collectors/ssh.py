import re
import threading
import time
from collections import defaultdict


class SSHCollector:

    FAILED_PASSWORD = re.compile(
        r"Failed password for (?:invalid user )?(\S+) from "
        r"(\d+\.\d+\.\d+\.\d+)"
    )

    ACCEPTED_PASSWORD = re.compile(
        r"Accepted password for (\S+) from "
        r"(\d+\.\d+\.\d+\.\d+)"
    )

    ACCEPTED_KEY = re.compile(
        r"Accepted publickey for (\S+) from "
        r"(\d+\.\d+\.\d+\.\d+)"
    )

    INVALID_USER = re.compile(
        r"Invalid user (\S+) from "
        r"(\d+\.\d+\.\d+\.\d+)"
    )

    def __init__(self, config, emitter):

        self.config = config
        self.emitter = emitter

        self.log_file = config.get(
            "ssh_log_file",
            "/var/log/auth.log"
        )

        self.threshold = int(
            config.get("ssh_threshold", 5)
        )

        self.failed_attempts = defaultdict(int)

    def start(self):

        thread = threading.Thread(
            target=self._watch,
            name="ssh-collector",
            daemon=True
        )

        thread.start()

        print(
            f"[*] SSH collector started: {self.log_file}",
            flush=True
        )

    def _watch(self):

        try:

            with open(
                self.log_file,
                "r",
                encoding="utf-8",
                errors="replace"
            ) as log:

                # Przechodzimy na koniec istniejącego logu.
                # Agent interesuje się nowymi wpisami.
                log.seek(0, 2)

                while True:

                    line = log.readline()

                    if not line:
                        time.sleep(0.5)
                        continue

                    self._process_line(line)

        except PermissionError:

            print(
                f"[!] SSH collector: "
                f"permission denied: {self.log_file}",
                flush=True
            )

        except FileNotFoundError:

            print(
                f"[!] SSH collector: "
                f"log not found: {self.log_file}",
                flush=True
            )

        except Exception as e:

            print(
                f"[!] SSH collector error: {e}",
                flush=True
            )

    def _process_line(self, line):

        match = self.FAILED_PASSWORD.search(line)

        if match:

            username = match.group(1)
            ip = match.group(2)

            self.failed_attempts[ip] += 1

            attempts = self.failed_attempts[ip]

            print(
                f"[SSH] failed login "
                f"ip={ip} user={username} "
                f"attempts={attempts}",
                flush=True
            )

            self.emitter.emit(
                self.emitter.create_event(
                    event_type="ssh_auth_failure",
                    severity="medium",
                    source="auth_log",
                    data={
                        "ip": ip,
                        "username": username,
                        "attempts": attempts
                    }
                )
            )

            if attempts >= self.threshold:

                self.emitter.emit(
                    self.emitter.create_event(
                        event_type="ssh_bruteforce",
                        severity="high",
                        source="auth_log",
                        data={
                            "ip": ip,
                            "username": username,
                            "attempts": attempts
                        }
                    )
                )

                print(
                    f"[SSH] BRUTE FORCE DETECTED "
                    f"ip={ip} attempts={attempts}",
                    flush=True
                )

                self.failed_attempts[ip] = 0

            return

        match = self.ACCEPTED_PASSWORD.search(line)

        if match:

            username = match.group(1)
            ip = match.group(2)

            self.failed_attempts.pop(ip, None)

            self.emitter.emit(
                self.emitter.create_event(
                    event_type="ssh_login",
                    severity="info",
                    source="auth_log",
                    data={
                        "ip": ip,
                        "username": username,
                        "method": "password"
                    }
                )
            )

            return

        match = self.ACCEPTED_KEY.search(line)

        if match:

            username = match.group(1)
            ip = match.group(2)

            self.failed_attempts.pop(ip, None)

            self.emitter.emit(
                self.emitter.create_event(
                    event_type="ssh_login",
                    severity="info",
                    source="auth_log",
                    data={
                        "ip": ip,
                        "username": username,
                        "method": "publickey"
                    }
                )
            )

            return

        match = self.INVALID_USER.search(line)

        if match:

            username = match.group(1)
            ip = match.group(2)

            self.emitter.emit(
                self.emitter.create_event(
                    event_type="ssh_invalid_user",
                    severity="medium",
                    source="auth_log",
                    data={
                        "ip": ip,
                        "username": username
                    }
                )
            )   
            return
