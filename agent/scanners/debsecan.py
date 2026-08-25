import json
import subprocess
import threading
import time
from pathlib import Path


class DebsecanScanner:
    def __init__(self, emitter, interval=3600, state_file=None):
        self.emitter = emitter
        self.interval = interval

        self.state_file = Path(
            state_file
            or "/home/garygolden/agent/state/debsecan.json"
        )

        self.state_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

    def start(self):
        thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="debsecan-scanner",
        )

        thread.start()

        print(
            f"[*] Debsecan scanner started "
            f"(interval={self.interval}s)",
            flush=True
        )

    def _run(self):
        self._scan()

        while True:
            time.sleep(self.interval)
            self._scan()

    def _scan(self):
        try:
            result = subprocess.run(
                ["debsecan"],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode != 0:
                print(
                    f"[!] Debsecan returned code "
                    f"{result.returncode}: "
                    f"{result.stderr.strip()}",
                    flush=True
                )
                return

            current_state = self._parse_output(
                result.stdout
            )

            statistics = self._build_statistics(
                current_state
            )

            print(
                "[VULN] "
                f"relations={statistics['relation_count']} "
                f"unique_cves={statistics['unique_cve_count']} "
                f"packages={statistics['affected_package_count']}",
                flush=True
            )

            previous_state = self._load_state()

            # ------------------------------------------------
            # Pierwszy skan
            # ------------------------------------------------

            if previous_state is None:

                self._save_state(
                    current_state
                )

                print(
                    "[VULN] Initial baseline created",
                    flush=True
                )

                return

            added = current_state - previous_state
            removed = previous_state - current_state

            # ------------------------------------------------
            # Brak zmian
            # ------------------------------------------------

            if not added and not removed:

                print(
                    "[VULN] No changes detected",
                    flush=True
                )

                return

            # ------------------------------------------------
            # Severity
            # ------------------------------------------------

            severity = "info"

            if added:
                severity = "medium"

            if len(added) >= 10:
                severity = "high"

            # ------------------------------------------------
            # Event
            # ------------------------------------------------

            event = self.emitter.create_event(
                event_type="vulnerability_change",
                severity=severity,
                source="debsecan",
                data={
                    "statistics": statistics,
                    "added": [
                        {
                            "cve": cve,
                            "package": package,
                        }
                        for cve, package in sorted(added)
                    ],
                    "removed": [
                        {
                            "cve": cve,
                            "package": package,
                        }
                        for cve, package in sorted(removed)
                    ],
                },
            )

            self.emitter.emit(event)

            self._save_state(
                current_state
            )

            print(
                "[VULN] Vulnerability state changed",
                flush=True
            )

        except FileNotFoundError:
            print(
                "[!] debsecan not found",
                flush=True
            )

        except subprocess.TimeoutExpired:
            print(
                "[!] Debsecan scan timed out",
                flush=True
            )

        except Exception as exc:
            print(
                f"[!] Debsecan scanner error: {exc}",
                flush=True
            )

    @staticmethod
    def _parse_output(output):
        vulnerabilities = set()

        for line in output.splitlines():

            line = line.strip()

            if not line:
                continue

            parts = line.split()

            if len(parts) < 2:
                continue

            cve = parts[0]
            package = parts[1]

            if not cve.startswith("CVE-"):
                continue

            vulnerabilities.add(
                (
                    cve,
                    package
                )
            )

        return vulnerabilities

    @staticmethod
    def _build_statistics(vulnerabilities):

        unique_cves = {
            cve
            for cve, _ in vulnerabilities
        }

        packages = {
            package
            for _, package in vulnerabilities
        }

        return {
            "relation_count": len(vulnerabilities),
            "unique_cve_count": len(unique_cves),
            "affected_package_count": len(packages),
        }

    def _load_state(self):

        if not self.state_file.exists():
            return None

        try:
            with self.state_file.open(
                "r",
                encoding="utf-8"
            ) as f:

                data = json.load(f)

            return {
                (
                    item["cve"],
                    item["package"]
                )
                for item in data
                if "cve" in item and "package" in item
            }

        except Exception as exc:

            print(
                f"[!] Could not load "
                f"Debsecan state: {exc}",
                flush=True
            )

            return None

    def _save_state(self, vulnerabilities):

        data = [
            {
                "cve": cve,
                "package": package
            }
            for cve, package
            in sorted(vulnerabilities)
        ]

        temp_file = self.state_file.with_suffix(
            ".json.tmp"
        )

        try:

            with temp_file.open(
                "w",
                encoding="utf-8"
            ) as f:

                json.dump(
                    data,
                    f,
                    indent=2
                )

            temp_file.replace(
                self.state_file
            )

        except Exception as exc:

            print(
                f"[!] Could not save "
                f"Debsecan state: {exc}",
                flush=True
            )
