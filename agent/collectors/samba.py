import threading
import time

from privileged.client import PrivilegedClient


class SambaCollector:

    def __init__(
        self,
        emitter,
        interval=10,
        socket_path="/home/garygolden/agent/privileged/guardian.sock",
    ):
        self.emitter = emitter
        self.interval = interval

        self.privileged = PrivilegedClient(
            socket_path=socket_path,
            timeout=15,
        )

        self.previous_sessions = {}
        self.baseline_initialized = False

    def start(self):
        thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="samba-collector",
        )

        thread.start()

        print(
            f"[*] Samba collector started "
            f"(interval={self.interval}s)",
            flush=True,
        )

    def _run(self):
        while True:
            self._scan()
            time.sleep(self.interval)

    def _scan(self):
        try:
            response = self.privileged.request(
                {
                    "action": "samba_status",
                }
            )

            if not response.get("ok"):
                print(
                    f"[!] Samba privileged server error: "
                    f"{response.get('error', 'unknown error')}",
                    flush=True,
                )
                return

            sessions = response.get(
                "data",
                {}
            ).get(
                "sessions",
                []
            )

            current_sessions = {
                self._session_key(session): session
                for session in sessions
            }

            # =========================
            # FIRST BASELINE
            # =========================

            if not self.baseline_initialized:
                self.previous_sessions = current_sessions
                self.baseline_initialized = True

                print(
                    f"[SAMBA] baseline sessions="
                    f"{len(current_sessions)}",
                    flush=True,
                )

                return

            # =========================
            # CHANGES
            # =========================

            connected = (
                set(current_sessions)
                - set(self.previous_sessions)
            )

            disconnected = (
                set(self.previous_sessions)
                - set(current_sessions)
            )

            # =========================
            # CONNECTED
            # =========================

            for key in sorted(connected):
                session = current_sessions[key]

                print(
                    f"[SAMBA] CONNECTED "
                    f"ip={session['ip']} "
                    f"user={session['username']} "
                    f"pid={session['pid']}",
                    flush=True,
                )

                event = self.emitter.create_event(
                    event_type="samba_session",
                    severity="info",
                    source="smbstatus",
                    data={
                        "status": "connected",
                        **session,
                    },
                )

                self.emitter.emit(event)

            # =========================
            # DISCONNECTED
            # =========================

            for key in sorted(disconnected):
                session = self.previous_sessions[key]

                print(
                    f"[SAMBA] DISCONNECTED "
                    f"ip={session['ip']} "
                    f"user={session['username']} "
                    f"pid={session['pid']}",
                    flush=True,
                )

                event = self.emitter.create_event(
                    event_type="samba_session",
                    severity="info",
                    source="smbstatus",
                    data={
                        "status": "disconnected",
                        **session,
                    },
                )

                self.emitter.emit(event)

            # =========================
            # SAVE CURRENT STATE
            # =========================

            self.previous_sessions = current_sessions

        except TimeoutError:
            print(
                "[!] Samba status request timed out",
                flush=True,
            )

        except Exception as exc:
            print(
                f"[!] Samba collector error: {exc}",
                flush=True,
            )

    @staticmethod
    def _session_key(session):
        return (
            session.get("pid"),
            session.get("username"),
            session.get("ip"),
        )
