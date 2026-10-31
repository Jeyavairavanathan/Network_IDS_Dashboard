from flask import Flask, render_template, request, redirect, session
import os
import smtplib

from email.message import EmailMessage
from dotenv import load_dotenv
import ipaddress
import sqlite3
import secrets
import subprocess
import sys
from werkzeug.security import generate_password_hash, check_password_hash
load_dotenv()

GMAIL_ADDRESS = os.getenv("GMAIL_ADDRESS")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

app = Flask(__name__)

app.secret_key = secrets.token_hex(32)

DATABASE = "ids.db"


# --------------------------------------------------
# TRUSTED NETWORKS
# --------------------------------------------------

TRUSTED_NETWORKS = [
    "192.168.1.0/24"
]


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def db():

    conn = sqlite3.connect(DATABASE)

    conn.row_factory = sqlite3.Row

    return conn


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()

        password = request.form.get("password", "")

        conn = db()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        conn.close()


        # Check user and password

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session["username"] = user["username"]

            session["user_id"] = user["id"]

            return redirect("/verify")


        return render_template(
            "login.html",
            error="Invalid username or password"
        )


    return render_template("login.html")
# --------------------------------------------------
# SIGN UP
# --------------------------------------------------

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if not username or not email or not password:
            return render_template(
                "signup.html",
                error="All fields are required."
            )

        if len(password) < 8:
            return render_template(
                "signup.html",
                error="Password must contain at least 8 characters."
            )

        if password != confirm_password:
            return render_template(
                "signup.html",
                error="Passwords do not match."
            )

        password_hash = generate_password_hash(password)

        conn = db()

        try:

            conn.execute(
                """
                INSERT INTO users
                (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    email,
                    password_hash
                )
            )

            conn.commit()

        except sqlite3.IntegrityError:

            conn.close()

            return render_template(
                "signup.html",
                error="Username or email already exists."
            )

        conn.close()

        return redirect("/")

    return render_template("signup.html")
# --------------------------------------------------
# FORGOT PASSWORD
# --------------------------------------------------

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form.get("email", "").strip()

        conn = db()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        conn.close()

        if not user:

            return render_template(
                "forgot_password.html",
                error="No account found with this email."
            )

        reset_code = secrets.token_hex(3).upper()
                # Send verification code through Gmail

        message = EmailMessage()

        message["Subject"] = "Network IDS - Password Reset Code"
        message["From"] = GMAIL_ADDRESS
        message["To"] = email

        message.set_content(
            f"""
Hello,

Your Network IDS password reset verification code is:

{reset_code}

Use this code to reset your password.

If you did not request this password reset,
please ignore this email.

Network IDS Security Team
"""
        )

        try:

            with smtplib.SMTP(
                "smtp.gmail.com",
                587
            ) as server:

                server.starttls()

                server.login(
                    GMAIL_ADDRESS,
                    GMAIL_APP_PASSWORD
                )

                server.send_message(message)

        except Exception as e:

            print("Email sending error:", e)

            return render_template(
                "forgot_password.html",
                error="Unable to send verification email."
            )

        conn = db()

        conn.execute(
            """
            UPDATE users
            SET reset_code = ?
            WHERE email = ?
            """,
            (reset_code, email)
        )

        conn.commit()
        conn.close()

        print(
            f"\nPASSWORD RESET CODE: {reset_code}\n"
        )

        session["reset_email"] = email

        return redirect("/verify-reset-code")

    return render_template("forgot_password.html")
# --------------------------------------------------
# VERIFY RESET CODE
# --------------------------------------------------

@app.route("/verify-reset-code", methods=["GET", "POST"])
def verify_reset_code():

    email = session.get("reset_email")

    if not email:
        return redirect("/forgot-password")

    if request.method == "POST":

        code = request.form.get("code", "").strip().upper()

        conn = db()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        conn.close()

        if not user or user["reset_code"] != code:

            return render_template(
                "verify_reset_code.html",
                error="Invalid verification code."
            )

        # Code verified
        session["reset_verified"] = True

        return redirect("/reset-password")

    return render_template("verify_reset_code.html")


# --------------------------------------------------
# RESET PASSWORD
# --------------------------------------------------

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():

    email = session.get("reset_email")

    if not email:
        return redirect("/forgot-password")

    if not session.get("reset_verified"):
        return redirect("/forgot-password")

    if request.method == "POST":

        password = request.form.get("password", "")

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if len(password) < 8:

            return render_template(
                "reset_password.html",
                error="Password must contain at least 8 characters."
            )

        if password != confirm_password:

            return render_template(
                "reset_password.html",
                error="Passwords do not match."
            )

        password_hash = generate_password_hash(password)

        conn = db()

        conn.execute(
            """
            UPDATE users
            SET password_hash = ?,
                reset_code = NULL,
                reset_expires = NULL
            WHERE email = ?
            """,
            (
                password_hash,
                email
            )
        )

        conn.commit()
        conn.close()

        # Clear reset session
        session.pop("reset_email", None)
        session.pop("reset_verified", None)

        return redirect("/")

    return render_template("reset_password.html")
# --------------------------------------------------
# NETWORK SECURITY VERIFICATION
# --------------------------------------------------

@app.route("/verify", methods=["GET", "POST"])
def verify():

    if "username" not in session:

        return redirect("/")


    if request.method == "POST":

        network = request.form.get("network", "").strip()

        purpose = request.form.get("purpose", "").strip()

        authorized = request.form.get("authorized")


        # Validate network

        try:

            net = ipaddress.ip_network(
                network,
                strict=False
            )

        except ValueError:

            return render_template(
                "verify.html",
                error="Invalid network format."
            )


        # Only private networks

        if not net.is_private:

            return render_template(
                "verify.html",
                error="Only private networks are allowed."
            )


        # Check trusted network

        is_trusted = False

        for trusted in TRUSTED_NETWORKS:

            trusted_net = ipaddress.ip_network(
                trusted,
                strict=False
            )

            if net.subnet_of(trusted_net):

                is_trusted = True

                break


        # Authorization required for
        # non-trusted networks

        if not is_trusted:

            if authorized != "yes":

                return render_template(
                    "verify.html",
                    error=(
                        "Administrator permission is "
                        "required for this network."
                    )
                )


        # Purpose required

        if not purpose:

            return render_template(
                "verify.html",
                error="Please enter the scan purpose."
            )


        if is_trusted:

            authorization_status = "TRUSTED"

        else:

            authorization_status = "AUTHORIZED"


        # Save audit record

        conn = db()

        conn.execute(
            """
            INSERT INTO scan_audit
            (
                username,
                target_network,
                purpose,
                authorization
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                session["username"],
                network,
                purpose,
                authorization_status
            )
        )

        conn.commit()

        conn.close()


        # Store authorized network

        session["authorized_network"] = network

        session["scan_authorized"] = True


        return redirect("/scanner")


    return render_template("verify.html")


# --------------------------------------------------
# SCANNER PAGE
# --------------------------------------------------

@app.route("/scanner")
def scanner_page():

    if "username" not in session:

        return redirect("/")


    if not session.get("scan_authorized"):

        return redirect("/verify")


    network = session.get(
        "authorized_network"
    )


    return render_template(
        "scanner.html",
        network=network
    )


# --------------------------------------------------
# START SCAN
# --------------------------------------------------

@app.route("/scan", methods=["POST"])
def scan():

    if "username" not in session:

        return redirect("/")


    if not session.get("scan_authorized"):

        return redirect("/verify")


    network = session.get(
        "authorized_network"
    )


    if not network:

        return redirect("/verify")


    # Validate again before scan

    try:

        net = ipaddress.ip_network(
            network,
            strict=False
        )

    except ValueError:

        session.pop(
            "authorized_network",
            None
        )

        session.pop(
            "scan_authorized",
            None
        )

        return redirect("/verify")


    if not net.is_private:

        session.pop(
            "authorized_network",
            None
        )

        session.pop(
            "scan_authorized",
            None
        )

        return redirect("/verify")


    # Start scanner

    try:

        subprocess.Popen(
            [
                sys.executable,
                "scanner.py",
                network
            ]
        )

    except Exception as e:

        return render_template(
            "scanner.html",
            network=network,
            error=f"Scanner error: {e}"
        )


    return redirect("/dashboard")


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
def dashboard():

    if "username" not in session:

        return redirect("/")


    conn = db()


    devices = conn.execute(
        """
        SELECT *
        FROM devices
        ORDER BY ip
        """
    ).fetchall()


    alerts = conn.execute(
        """
        SELECT *
        FROM alerts
        ORDER BY id DESC
        """
    ).fetchall()


    total_devices = conn.execute(
        """
        SELECT COUNT(*)
        FROM devices
        """
    ).fetchone()[0]


    online_devices = conn.execute(
        """
        SELECT COUNT(*)
        FROM devices
        WHERE status = 'Online'
        """
    ).fetchone()[0]


    total_alerts = conn.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        """
    ).fetchone()[0]


    conn.close()


    return render_template(
        "index.html",
        devices=devices,
        alerts=alerts,
        total_devices=total_devices,
        online_devices=online_devices,
        total_alerts=total_alerts
    )


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5001,
        debug=True
    )