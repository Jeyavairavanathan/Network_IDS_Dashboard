import sqlite3
import subprocess
import time
import ipaddress
import sys


DATABASE = "ids.db"


def get_authorized_network():

    conn = sqlite3.connect(DATABASE)

    row = conn.execute("""
        SELECT target_network
        FROM scan_audit
        WHERE authorization IN ('AUTHORIZED', 'TRUSTED')
        ORDER BY id DESC
        LIMIT 1
    """).fetchone()

    conn.close()

    if row:
        return row[0]

    return None


def is_private_network(network):

    try:
        net = ipaddress.ip_network(
            network,
            strict=False
        )

        return net.is_private

    except ValueError:

        return False


def scan_network(network):

    print("\n" + "=" * 60)
    print("NETWORK IDS - AUTOMATIC MONITOR")
    print("=" * 60)

    print(f"Authorized Network : {network}")
    print("Starting discovery scan...")

    try:

        result = subprocess.run(
            [
                "nmap",
                "-sn",
                "-T4",
                network
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:

            print("\n❌ Nmap scan failed.")
            print(result.stderr)

            return False

        print("\n✅ Scan completed.\n")
        print(result.stdout)

        return True

    except subprocess.TimeoutExpired:

        print(
            "\n⚠️ Scan timed out."
        )

        return False

    except FileNotFoundError:

        print(
            "\n❌ Nmap was not found."
        )

        return False

    except KeyboardInterrupt:

        print(
            "\n\n🛑 Scan interrupted by user."
        )

        return False


def monitor(interval=60):

    print("\n🛡️ Network IDS Monitor Started")

    print(
        f"Automatic scan interval: "
        f"{interval} seconds"
    )

    try:

        while True:

            network = get_authorized_network()

            if not network:

                print(
                    "\n❌ No authorized network found."
                )

                time.sleep(interval)

                continue

            if not is_private_network(network):

                print(
                    "\n❌ Blocked: "
                    "target is not a private network."
                )

                time.sleep(interval)

                continue

            scan_network(network)

            print(
                f"\n⏳ Next scan in "
                f"{interval} seconds..."
            )

            time.sleep(interval)

    except KeyboardInterrupt:

        print(
            "\n\n🛑 Network IDS Monitor stopped."
        )


if __name__ == "__main__":

    interval = 60

    if len(sys.argv) > 1:

        try:

            interval = int(sys.argv[1])

        except ValueError:

            print(
                "Invalid interval. "
                "Using 60 seconds."
            )

    monitor(interval)