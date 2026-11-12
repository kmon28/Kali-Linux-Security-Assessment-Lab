#!/usr/bin/env python3
"""IR-014: point-in-time TCP/UDP connection detector for an authorized lab.

This is a documented reference implementation based on the IR-014 investigation.
It is not claimed to be a byte-for-byte copy of the original Kali script.
Requires: pip install psutil
"""
from datetime import datetime, timezone
import psutil

MONITORED_PORT = 9090


def endpoint_text(endpoint):
    if not endpoint:
        return "-"
    host = getattr(endpoint, "ip", endpoint[0])
    port = getattr(endpoint, "port", endpoint[1])
    return f"{host}:{port}"


def endpoint_port(endpoint):
    if not endpoint:
        return None
    return getattr(endpoint, "port", endpoint[1])


def process_details(pid):
    if pid is None:
        return "PID: None | process unavailable"
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            return (
                f"PID: {pid} | name: {proc.name()} | "
                f"executable: {proc.exe()} | parent PID: {proc.ppid()}"
            )
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
        return f"PID: {pid} | process details unavailable ({type(exc).__name__})"


def main():
    print(f"IR-014 scan UTC: {datetime.now(timezone.utc).isoformat()}")
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        print("Permission denied reading network connections; try sudo.")
        return 1

    print(f"Network connection records: {len(connections)}")
    alerts = 0
    for connection in connections:
        local = endpoint_text(connection.laddr)
        remote = endpoint_text(connection.raddr)
        print(f"Local: {local} | Remote: {remote} | State: {connection.status}")
        print(process_details(connection.pid))

        if MONITORED_PORT in (
            endpoint_port(connection.laddr),
            endpoint_port(connection.raddr),
        ):
            alerts += 1
            print(
                f"ALERT [{alerts}] Severity: MEDIUM (lab triage) | "
                f"Reason: Connection uses monitored port {MONITORED_PORT}"
            )
            if connection.status == psutil.CONN_TIME_WAIT:
                print("Note: TIME_WAIT can persist after process exit; not an active session.")

    print(f"Total alerts: {alerts}")
    print("Port-based alerts are not proof of malicious activity.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
