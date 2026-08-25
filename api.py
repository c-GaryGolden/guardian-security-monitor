from typing import Any
from datetime import datetime, timezone
import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from reactions import ReactionEngine
from rules import RuleEngine
from storage import EventStorage


# =========================
# CONFIGURATION
# =========================

def load_config():
    try:
        with open(
            "config.yaml",
            "r",
            encoding="utf-8",
        ) as f:
            return yaml.safe_load(f) or {}

    except FileNotFoundError:
        return {}


config = load_config()

reaction_config = config.get(
    "reaction",
    {},
)

reaction_mode = reaction_config.get(
    "mode",
    "dry_run",
)


# =========================
# APPLICATION
# =========================
HEARTBEATS = {}
HEARTBEAT_TIMEOUT = 30
app = FastAPI(
    title="Guardian API",
    version="0.1.0",
)


# =========================
# STORAGE
# =========================

storage = EventStorage(
    db_path="data/guardian.db",
    max_size_mb=1024,
    maintenance_every=100,
)


# =========================
# ENGINES
# =========================

rule_engine = RuleEngine()

reaction_engine = ReactionEngine(
    mode=reaction_mode,
)


# =========================
# EVENT MODEL
# =========================

class Event:

    def __init__(
        self,
        event_type,
        severity,
        source,
        data,
        host,
        timestamp,
    ):
        self.type = event_type
        self.severity = severity
        self.source = source
        self.data = data
        self.host = host
        self.timestamp = timestamp

@app.get("/status")
def status():
    now = datetime.now(
        timezone.utc
    )

    agent = HEARTBEATS.get(
        "192.168.10.199"
    )

    agent_online = False
    privileged_online = False

    agent_last_seen = None

    if agent:
        agent_last_seen = agent.get(
            "last_seen"
        )

        try:
            last_seen = datetime.fromisoformat(
                agent_last_seen
            )

            age = (
                now - last_seen
            ).total_seconds()

            if age <= HEARTBEAT_TIMEOUT:
                agent_online = True

                privileged_online = bool(
                    agent.get(
                        "privileged",
                        False,
                    )
                )

        except Exception:
            agent_online = False
            privileged_online = False

    return {
        "ok": True,

        "api": {
            "status": "online",
        },

        "database": {
            "status": "online",
            "events": storage.count(),
            "incidents": storage.incident_count(),
            "commands": storage.command_count(),
        },

        "agent": {
            "host": "192.168.10.199",
            "status": (
                "online"
                if agent_online
                else "offline"
            ),
            "last_seen": agent_last_seen,
        },

        "privileged": {
            "status": (
                "online"
                if privileged_online
                else "offline"
            ),
            "last_seen": agent_last_seen,
        },
    }
# =========================
# HEALTH
# =========================
@app.post("/heartbeat")
def heartbeat(payload: dict[str, Any]):
    host = payload.get("host")

    if not isinstance(host, str) or not host:
        raise HTTPException(
            status_code=422,
            detail="host is required",
        )

    now = datetime.now(
        timezone.utc
    ).isoformat()

    HEARTBEATS[host] = {
        "last_seen": now,
        "privileged": bool(
            payload.get(
                "privileged",
                False,
            )
        ),
    }

    return {
        "ok": True,
        "host": host,
        "last_seen": now,
    }
@app.get("/commands")
def get_commands(
    limit: int = 50,
):
    if limit < 1 or limit > 500:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 500",
        )

    commands = storage.latest_commands(
        limit=limit
    )

    return {
        "ok": True,
        "count": len(commands),
        "commands": commands,
    }
@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "guardian-api",
        "events": storage.count(),
        "incidents": storage.incident_count(),
        "reaction_mode": reaction_engine.mode,
        "commands": storage.command_count(),

    }

@app.get("/")
def dashboard():
    return FileResponse(
        "web/panel.html"
    )

# =========================
# REACTION CONFIG
# =========================

@app.get("/config/reaction")
def get_reaction_config():
    return {
        "mode": reaction_engine.mode,
    }


# =========================
# EVENTS
# =========================

@app.get("/events")
def get_events(
    limit: int = 50,
    severity: str | None = None,
    event_type: str | None = None,
):
    if limit < 1 or limit > 500:
        raise HTTPException(
            status_code=400,
            detail=(
                "limit must be between "
                "1 and 500"
            ),
        )

    events = storage.latest(
        limit=limit
    )

    if severity is not None:
        events = [
            event
            for event in events
            if event["severity"] == severity
        ]

    if event_type is not None:
        events = [
            event
            for event in events
            if event["type"] == event_type
        ]

    return {
        "ok": True,
        "count": len(events),
        "events": events,
    }


# =========================
# INCIDENTS
# =========================

@app.get("/incidents")
def get_incidents(
    limit: int = 50,
):
    if limit < 1 or limit > 500:
        raise HTTPException(
            status_code=400,
            detail=(
                "limit must be between "
                "1 and 500"
            ),
        )

    incidents = storage.latest_incidents(
        limit=limit
    )

    return {
        "ok": True,
        "count": len(incidents),
        "incidents": incidents,
    }


# =========================
# RECEIVE EVENT
# =========================
@app.post("/commands/poll")
def poll_commands(
    payload: dict[str, Any],
):
    target_host = payload.get(
        "host"
    )

    if not target_host:
        raise HTTPException(
            status_code=422,
            detail="host is required",
        )

    commands = storage.claim_pending_commands(
        target_host=target_host,
        limit=10,
    )

    return {
        "ok": True,
        "commands": commands,
    }

@app.post("/commands/{command_id}/result")
def command_result(
    command_id: int,
    payload: dict[str, Any],
):
    status = payload.get(
        "status"
    )

    if status not in {
        "executed",
        "failed",
        "rejected",
    }:
        raise HTTPException(
            status_code=422,
            detail=(
                "status must be "
                "executed, failed or rejected"
            ),
        )

    result = payload.get(
        "result"
    )

    storage.update_command(
        command_id=command_id,
        status=status,
        result=result,
    )

    return {
        "ok": True,
        "command_id": command_id,
        "status": status,
    }

@app.post("/event")
def receive_event(
    payload: dict[str, Any],
):
    required = {
        "type",
        "severity",
        "source",
        "data",
        "host",
        "timestamp",
    }

    missing = required - payload.keys()

    if missing:
        raise HTTPException(
            status_code=422,
            detail=(
                "missing fields: "
                + ", ".join(
                    sorted(missing)
                )
            ),
        )

    if not isinstance(
        payload["data"],
        dict,
    ):
        raise HTTPException(
            status_code=422,
            detail="data must be an object",
        )

    event = Event(
        event_type=payload["type"],
        severity=payload["severity"],
        source=payload["source"],
        data=payload["data"],
        host=payload["host"],
        timestamp=payload["timestamp"],
    )

    # =========================
    # STORE EVENT
    # =========================

    event_id = storage.insert_event(
        event
    )

    # =========================
    # EVALUATE RULES
    # =========================

    matches = rule_engine.evaluate(
        payload
    )

    incidents_created = 0
    reactions_executed = 0

    # =========================
    # CREATE INCIDENTS
    # =========================

    for match in matches:

        incident_id = (
            storage.insert_incident(
                event_id=event_id,
                rule=match["rule"],
                action=match["action"],
                reason=match["reason"],
                status="open",
            )
        )

        incidents_created += 1

        incident = {
            "id": incident_id,
            "event_id": event_id,
            "rule": match["rule"],
            "action": match["action"],
            "reason": match["reason"],
            "status": "open",
        }

        # =========================
        # EXECUTE REACTION
        # =========================

        reaction_result = (
            reaction_engine.execute(
                incident
            )
        )

        reaction_status = (
            reaction_result.get(
                "status"
            )
            or "unknown"
        )

        reaction_message = (
            reaction_result.get(
                "message"
            )
            or reaction_result.get(
                "reason"
            )
            or ""
        )

        storage.update_reaction(
            incident_id=incident_id,
            reaction_status=reaction_status,
            reaction_result=reaction_message,
        )

        if reaction_result.get("ok"):
            reactions_executed += 1

        print(
            "[INCIDENT] "
            f"id={incident_id} "
            f"event_id={event_id} "
            f"rule={match['rule']} "
            f"action={match['action']} "
            f"status=open "
            f"reaction={reaction_status}",
            flush=True,
        )

    # =========================
    # EVENT LOG
    # =========================

    print(
        f"[EVENT] stored "
        f"id={event_id} "
        f"type={event.type} "
        f"severity={event.severity} "
        f"source={event.source} "
        f"host={event.host}",
        flush=True,
    )

    return {
        "ok": True,
        "message": "event stored",
        "event_id": event_id,
        "incidents_created": incidents_created,
        "reactions_executed": (
            reactions_executed
        ),
    }
