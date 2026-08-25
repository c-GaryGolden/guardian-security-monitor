import json
import threading

from core.event import create_event


class EventEmitter:

    def __init__(self, config, host):

        self.config = config
        self.host = host

        self.buffer = []
        self.lock = threading.Lock()

        self.transports = []

    def add_transport(self, transport):

        self.transports.append(transport)

    def create_event(
        self,
        event_type,
        severity,
        source,
        data
    ):

        return create_event(
            event_type=event_type,
            severity=severity,
            source=source,
            data=data,
            host=self.host
        )

    def emit(self, event):

        print(
            "[EVENT]",
            json.dumps(
                event.to_dict(),
                ensure_ascii=False
            ),
            flush=True
        )

        with self.lock:
            self.buffer.append(event)

        for transport in self.transports:

            try:
                transport.send(event)

            except Exception as e:

                print(
                    f"[!] Transport error: {e}",
                    flush=True
                )
