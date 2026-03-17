import os

def block_ip(ip):
    if not ip:
        print("No IP provided to block.")
        return

    print(f"\n🔥 Blocking IP: {ip}")

    # Try to check if rule exists (suppress error output)
    check_command = f"iptables -C INPUT -s {ip} -j DROP 2>/dev/null"
    result = os.system(check_command)

    if result == 0:
        print("⚠️ IP is already blocked.")
        return

    # Add rule
    block_command = f"iptables -A INPUT -s {ip} -j DROP"
    result = os.system(block_command)

    if result == 0:
        print("✅ IP blocked successfully.")
    else:
        print("❌ Failed to block IP.")


def unblock_ip(ip):
    """
    Remove IP from iptables block list
    """

    if not ip:
        print("No IP provided to unblock.")
        return

    print(f"\n🔓 Unblocking IP: {ip}")

    unblock_command = f"iptables -D INPUT -s {ip} -j DROP"
    os.system(unblock_command)

    print("✅ IP unblocked successfully.")


def list_blocked_ips():
    """
    Show all blocked IP rules
    """

    print("\n📜 Blocked IP Rules:")
    os.system("iptables -L INPUT -v -n")
