import subprocess
import threading
from typing import Dict, Optional

# Default block duration for demo/testing
DEFAULT_BLOCK_SECONDS = 15

# Keep track of auto-unblock timers so we can reset them cleanly
_unblock_timers: Dict[str, threading.Timer] = {}
_timer_lock = threading.Lock()


def _run_iptables(args: list[str]) -> subprocess.CompletedProcess:
    """
    Run an iptables command safely.
    """
    return subprocess.run(
        ["iptables", *args],
        capture_output=True,
        text=True
    )


def _is_root() -> bool:
    """
    Check whether the script is running with root privileges.
    """
    try:
        import os
        return os.geteuid() == 0
    except AttributeError:
        # Windows fallback, not expected for your Kali setup
        return True


def _cancel_timer(ip: str) -> None:
    """
    Cancel any pending auto-unblock timer for this IP.
    """
    with _timer_lock:
        timer = _unblock_timers.pop(ip, None)
        if timer and timer.is_alive():
            timer.cancel()


def _schedule_auto_unblock(ip: str, delay_seconds: int) -> None:
    """
    Schedule automatic unblock after delay_seconds.
    If a timer already exists for this IP, replace it.
    """
    if delay_seconds <= 0:
        return

    _cancel_timer(ip)

    timer = threading.Timer(delay_seconds, unblock_ip, args=(ip, False))
    timer.daemon = True

    with _timer_lock:
        _unblock_timers[ip] = timer

    timer.start()
    print(f"⏳ Auto-unblock scheduled in {delay_seconds} seconds.")


def block_ip(ip: str, duration: int = DEFAULT_BLOCK_SECONDS, auto_unblock: bool = True) -> None:
    """
    Block a given IP address using iptables.

    Parameters:
        ip: IP address to block
        duration: auto-unblock after this many seconds
        auto_unblock: if True, remove block automatically after duration
    """
    if not ip:
        print("No IP provided to block.")
        return

    if not _is_root():
        print("❌ Root privileges required to modify iptables.")
        return

    print(f"\n🔥 Blocking IP: {ip}")

    # Check whether rule already exists
    check_result = _run_iptables(["-C", "INPUT", "-s", ip, "-j", "DROP"])
    if check_result.returncode == 0:
        print("⚠️ IP is already blocked.")
        if auto_unblock:
            _schedule_auto_unblock(ip, duration)
        return

    # Add DROP rule
    block_result = _run_iptables(["-A", "INPUT", "-s", ip, "-j", "DROP"])
    if block_result.returncode == 0:
        print("✅ IP blocked successfully.")
        if auto_unblock:
            _schedule_auto_unblock(ip, duration)
    else:
        print("❌ Failed to block IP.")
        if block_result.stderr:
            print(block_result.stderr.strip())


def unblock_ip(ip: str, announce: bool = True) -> None:
    """
    Remove IP from iptables block list.

    Parameters:
        ip: IP address to unblock
        announce: print messages if True
    """
    if not ip:
        if announce:
            print("No IP provided to unblock.")
        return

    if not _is_root():
        if announce:
            print("❌ Root privileges required to modify iptables.")
        return

    # Stop any pending auto-unblock timer
    _cancel_timer(ip)

    if announce:
        print(f"\n🔓 Unblocking IP: {ip}")

    # Remove DROP rule
    unblock_result = _run_iptables(["-D", "INPUT", "-s", ip, "-j", "DROP"])
    if unblock_result.returncode == 0:
        if announce:
            print("✅ IP unblocked successfully.")
    else:
        if announce:
            print("⚠️ IP was not blocked or rule already removed.")
        if unblock_result.stderr and announce:
            print(unblock_result.stderr.strip())


def list_blocked_ips() -> None:
    """
    Show all blocked IP rules.
    """
    if not _is_root():
        print("❌ Root privileges required to view iptables rules.")
        return

    print("\n📜 Blocked IP Rules:")
    result = _run_iptables(["-L", "INPUT", "-v", "-n", "--line-numbers"])
    if result.returncode == 0:
        print(result.stdout)
    else:
        print("❌ Failed to list blocked IPs.")
        if result.stderr:
            print(result.stderr.strip())


if __name__ == "__main__":
    # Example test
    print("Firewall blocker module loaded.")
    print(f"Default auto-unblock time: {DEFAULT_BLOCK_SECONDS} seconds")
