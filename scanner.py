import sqlite3
import nmap
import sys
import ipaddress


DATABASE = "ids.db"


# --------------------------------------------------
# GET AUTHORIZED NETWORK FROM APP
# --------------------------------------------------

if len(sys.argv) != 2:

    print("No authorized network provided.")
    print("Scan blocked.")

    sys.exit(1)


NETWORK = sys.argv[1]


# --------------------------------------------------
# VALIDATE TARGET NETWORK
# --------------------------------------------------

try:

    network = ipaddress.ip_network(
        NETWORK,
        strict=False
    )

except ValueError:

    print("Invalid network.")
    print("Scan blocked.")

    sys.exit(1)


# Only private networks are allowed
if not network.is_private:

    print("Public network detected.")
    print("Scan blocked.")

    sys.exit(1)


print("=" * 55)
print("          NETWORK IDS - AUTHORIZED SCANNER")
print("=" * 55)

print(f"\nAuthorized Target : {NETWORK}")
print("Starting network discovery...\n")


# --------------------------------------------------
# CREATE NMAP SCANNER
# --------------------------------------------------

scanner = nmap.PortScanner()


# --------------------------------------------------
# START NETWORK DISCOVERY
# --------------------------------------------------

try:

    scanner.scan(
        hosts=NETWORK,
        arguments="-sn"
    )

except Exception as e:

    print(f"Nmap error: {e}")
    sys.exit(1)


# --------------------------------------------------
# CONNECT DATABASE
# --------------------------------------------------

conn = sqlite3.connect(DATABASE)

cursor = conn.cursor()


# --------------------------------------------------
# GET ONLINE HOSTS
# --------------------------------------------------

online_hosts = set(
    scanner.all_hosts()
)


print(
    f"Active devices detected: {len(online_hosts)}\n"
)


# --------------------------------------------------
# PROCESS EACH DEVICE
# --------------------------------------------------

for host in online_hosts:

    try:

        hostname = scanner[host].hostname()

    except Exception:

        hostname = ""


    if not hostname:

        hostname = "Unknown"


    # ----------------------------------------------
    # CHECK WHETHER DEVICE IS ALREADY KNOWN
    # ----------------------------------------------

    cursor.execute(
        """
        SELECT ip
        FROM known_devices
        WHERE ip = ?
        """,
        (host,)
    )

    known = cursor.fetchone()


    # ----------------------------------------------
    # NEW DEVICE DETECTED
    # ----------------------------------------------

    if known is None:

        print(
            f"[ALERT] New Device Detected: "
            f"{host}"
        )


        # Save as known device

        cursor.execute(
            """
            INSERT INTO known_devices
            (ip, hostname)
            VALUES (?, ?)
            """,
            (
                host,
                hostname
            )
        )


        # Create security alert

        cursor.execute(
            """
            INSERT INTO alerts
            (ip, message, level)
            VALUES (?, ?, ?)
            """,
            (
                host,
                "New Device Detected",
                "HIGH"
            )
        )


    else:

        print(
            f"[KNOWN] {host} "
            f"({hostname})"
        )


    # ----------------------------------------------
    # UPDATE DEVICE STATUS
    # ----------------------------------------------

    cursor.execute(
        """
        INSERT OR REPLACE INTO devices
        (ip, hostname, status)
        VALUES (?, ?, ?)
        """,
        (
            host,
            hostname,
            "Online"
        )
    )


# --------------------------------------------------
# MARK OLD DEVICES AS OFFLINE
# --------------------------------------------------

cursor.execute(
    """
    SELECT ip
    FROM devices
    """
)

all_devices = cursor.fetchall()


for row in all_devices:

    ip = row[0]


    if ip not in online_hosts:

        cursor.execute(
            """
            UPDATE devices
            SET status = 'Offline'
            WHERE ip = ?
            """,
            (ip,)
        )


# --------------------------------------------------
# SAVE DATABASE
# --------------------------------------------------

conn.commit()

conn.close()


# --------------------------------------------------
# SCAN COMPLETED
# --------------------------------------------------

print("\n" + "=" * 55)
print("SCAN COMPLETED SUCCESSFULLY")
print("=" * 55)

print(
    f"Target Network : {NETWORK}"
)

print(
    f"Active Devices : {len(online_hosts)}"
)

print(
    "Database       : Updated"
)

print("=" * 55)