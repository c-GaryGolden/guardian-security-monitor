import json
from pathlib import Path


class LocalTransport:

    def __init__(self, config):

        self.event_log = Path(
            config.get(
                "event_log",
                "/var/log/guardian-agent/events.jsonl"
            )
        )

        self.event_log.parent.mkdir(
            parents=True,
            exist_ok=True
        )


    def send(self, event):

        with self.event_log.open(
            "a",
            encoding="utf-8"
        ) as f:

            f.write(
                json.dumps(
                    event.to_dict(),
                    ensure_ascii=False
                )
                + "\n"
            )
