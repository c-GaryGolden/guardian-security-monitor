from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class Event:
    type: str
    severity: str
    source: str
    data: dict[str, Any]
    host: str
    timestamp: str

    def to_dict(self) -> dict:
        return asdict(self)


def create_event(
    event_type: str,
    severity: str,
    source: str,
    data: dict[str, Any],
    host: str,
) -> Event:

    return Event(
        type=event_type,
        severity=severity,
        source=source,
        data=data,
        host=host,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
