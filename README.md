# Guardian

> Linux security monitoring, incident detection and controlled response platform.

Guardian is a LAN-based security monitoring and response platform for Linux hosts.

The project combines:

- event collection
- security rule evaluation
- incident detection
- controlled automated reactions
- command queuing
- privileged system operations
- heartbeat monitoring
- SQLite-based audit history
- a read-only SOC-style web dashboard

## Architecture

Guardian consists of two main components:

```text
Orange Pi
192.168.10.200
│
├── Guardian API
├── SQLite
├── Command Queue
├── Incident Engine
└── Read-only Web Dashboard
        │
        │ HTTP
        ▼
Ubuntu
192.168.10.199
│
├── Guardian Agent
├── Collectors
├── Scanners
├── CommandPoller
├── Heartbeat
└── Guardian Privileged Server
        │
        ├── systemctl
        ├── nftables
        ├── Lynis
        └── smbstatus

Core features
Monitoring
SSH logs
Apache logs
filesystem changes
service state
Samba sessions
Debsecan
Lynis
Detection

Current rules include:

ssh_bruteforce_high
lynis_regression
Controlled reactions
notify
log
alert
restart_service
block_ip
unblock_ip
Security model

Privileged actions are isolated from the regular Agent process:

Agent
  ↓
PrivilegedClient
  ↓
UNIX socket
  ↓
Guardian Privileged Server
  ↓
root operation

The system uses:

allowlists
protected IPs
IP validation
cooldowns
rate limits
command audit history

Protected addresses:

192.168.10.199
192.168.10.254
Web dashboard

The project includes a read-only SOC-style dashboard:

http://192.168.10.200:8000/

Dashboard sections:

Dashboard
Events
Incidents
Commands
System
API

Important endpoints:

GET  /
GET  /health
GET  /status
GET  /events
GET  /incidents
GET  /commands

POST /event
POST /commands/poll
POST /commands/{id}/result
POST /heartbeat
Project structure
guardian/
├── agent/
├── web/
├── api.py
├── storage.py
├── rules.py
├── reactions.py
├── actions.py
├── config.example.yaml
├── README.md
└── .gitignore
Current status

The core monitoring, command queue, privileged execution, automated reactions, heartbeat and read-only dashboard are operational.

Verified functionality includes:

restart_service
block_ip
unblock_ip
protected IP validation
command queue
heartbeat
incident tracking
dashboard access over LAN
Roadmap
system metrics
advanced filtering
reaction history
automated tests
stronger API authentication
structured logging
backup / recovery tooling
IPv6 support
timed IP bans
live WebSocket events
multi-host support

