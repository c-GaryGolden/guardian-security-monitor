import subprocess
import threading


class FileMonitor:
    def __init__(self, emitter, paths):
        self.emitter = emitter
        self.paths = paths

    def _watch_path(self, path):
        cmd = [
            "inotifywait",
            "-m",
            "-r",
            "-e",
            "modify,create,delete,move",
            "--format",
            "%w|%e|%f",
            path,
        ]

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            print(
                f"[*] File monitor active: {path}",
                flush=True
            )

            for line in process.stdout:
                line = line.strip()

                if not line:
                    continue

                parts = line.split("|", 2)

                if len(parts) != 3:
                    continue

                directory, action, filename = parts

                full_path = f"{directory}{filename}"

                print(
                    f"[FILE] path={full_path} action={action}",
                    flush=True
                )

                event = self.emitter.create_event(
                    event_type="file_change",
                    severity="medium",
                    source="inotify",
                    data={
                        "path": full_path,
                        "action": action,
                    },
                )

                self.emitter.emit(event)

            stderr = process.stderr.read().strip()

            if stderr:
                print(
                    f"[!] inotify error ({path}): {stderr}",
                    flush=True
                )

        except FileNotFoundError:
            print(
                "[!] inotifywait not found. "
                "Install package: inotify-tools",
                flush=True
            )

        except Exception as exc:
            print(
                f"[!] File monitor error ({path}): {exc}",
                flush=True
            )

    def start(self):
        if not self.paths:
            print(
                "[!] File monitor disabled: no paths configured",
                flush=True
            )
            return

        for path in self.paths:
            print(
                f"[*] Starting file monitor: {path}",
                flush=True
            )

            thread = threading.Thread(
                target=self._watch_path,
                args=(path,),
                daemon=True,
                name=f"file-monitor-{path}",
            )

            thread.start()
