import time
import signal
from transport.local import LocalTransport
from transport.guardian import GuardianTransport
from core.config import load_config
from core.host import get_host_ip
from core.emitter import EventEmitter
from collectors.samba import SambaCollector
from transport.local import LocalTransport
from collectors.ssh import SSHCollector
from collectors.apache import ApacheCollector
from monitors.files import FileMonitor
from monitors.services import ServiceMonitor
from scanners.debsecan import DebsecanScanner
from scanners.lynis import LynisScanner
from commands import CommandHandler
from transport.commands import CommandClient
from transport.command_poller import CommandPoller
from transport.heartbeat import HeartbeatClient


shutdown_requested = False


def handle_shutdown(signum, frame):
    global shutdown_requested

    shutdown_requested = True

    print(
        f"[*] Guardian Agent shutdown requested "
        f"(signal={signum})",
        flush=True,
    )


def main():

    # =========================
    # CONFIG
    # =========================

    config = load_config()
    host = get_host_ip()
    heartbeat = HeartbeatClient(
        config=config,
        host=host,
        interval=10,
    )
    
    heartbeat.start()
    signal.signal(
        signal.SIGTERM,
        handle_shutdown,
    )
    
    signal.signal(
        signal.SIGINT,
        handle_shutdown,
    )

    print(
        f"[*] Guardian Agent starting on {host}",
        flush=True
    )

    # =========================
    # EVENT EMITTER
    # =========================

    emitter = EventEmitter(
        config,
        host
    )

    # =========================
    # LOCAL TRANSPORT
    # =========================

    emitter.add_transport(
        LocalTransport(config)
    )

    emitter.add_transport(
        GuardianTransport(config)
    )

    # =========================
    # COMMAND POLLER
    # =========================

    command_client = CommandClient(
        config=config,
        host=host,
    )

    command_handler = CommandHandler(
        config=config,
    )

    command_poller = CommandPoller(
        client=command_client,
        handler=command_handler,
        interval=config.get(
            "command_poller",
            {}
        ).get(
            "interval",
            10,
        ),
    )

    command_poller.start()
    # =========================
    # SSH
    # =========================

    ssh = SSHCollector(
        config,
        emitter
    )

    ssh.start()

    # =========================
    # APACHE
    # =========================

    apache = ApacheCollector(
        config,
        emitter
    )

    apache.start()

    # =========================
    # FILE MONITOR
    # =========================

    file_monitor = FileMonitor(
        emitter,
        config.get(
            "file_monitor_paths",
            []
        )
    )

    file_monitor.start()

    # =========================
    # SERVICE MONITOR
    # =========================

    service_config = config.get(
        "service_monitor",
        {}
    )

    service_monitor = ServiceMonitor(
        emitter=emitter,
        services=service_config.get(
            "services",
            []
        ),
        interval=service_config.get(
            "interval",
            30
        )
    )

    service_monitor.start()

    # =========================
    # DEBSECAN
    # =========================

    debsecan_config = config.get(
        "debsecan",
        {}
    )

    debsecan = DebsecanScanner(
        emitter=emitter,
        interval=debsecan_config.get(
            "interval",
            3600
        ),
        state_file=debsecan_config.get(
            "state_file",
            "/home/garygolden/agent/state/debsecan.json"
        )
    )

    debsecan.start()

    # =========================
    # LYNIS
    # =========================

    lynis_config = config.get(
        "lynis",
        {}
    )

    lynis = LynisScanner(
        emitter=emitter,
        interval=lynis_config.get(
            "interval",
            7200
        ),
        state_file=lynis_config.get(
            "state_file",
            "/home/garygolden/agent/state/lynis.json"
        ),
      socket_path=lynis_config.get(
         "socket_path",
         "/home/garygolden/agent/privileged/guardian.sock"
       )
    )

    lynis.start()


    # =========================
    # SAMBA
    # =========================

    samba_config = config.get(
        "samba",
        {}
    )

    samba = SambaCollector(
        emitter=emitter,
        interval=samba_config.get(
            "interval",
            10
        ),
        socket_path=samba_config.get(
            "socket_path",
            "/home/garygolden/agent/privileged/guardian.sock"
        )
    )

    samba.start()
    # =========================
    # AGENT RUNNING
    # =========================

    print(
        "[*] Guardian Agent initialized",
        flush=True
    )

    try:
        while not shutdown_requested:
            time.sleep(1)

    finally:
        print(
            "[*] Guardian Agent stopping",
            flush=True,
        )

        command_poller.stop()
        heartbeat.stop()

        print(
            "[*] Guardian Agent stopped",
            flush=True,
        )


if __name__ == "__main__":
    main()
