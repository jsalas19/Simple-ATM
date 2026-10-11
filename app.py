import hmac
import os
import secrets
import sqlite3
import time
from contextlib import closing
from decimal import Decimal, InvalidOperation
from functools import wraps
from pathlib import Path
from typing import Callable, TypeVar

from flask import (
    Flask,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

LOGIN_ATTEMPT_LIMIT = 3
LOCKOUT_SECONDS = 300
MAX_SQLITE_INTEGER = 9_223_372_036_854_775_807
F = TypeVar("F", bound=Callable[..., object])


def create_app(test_config: dict[str, object] | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("ATM_SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.path.join(app.instance_path, "atm.sqlite3"),
        ATM_PIN=os.environ.get("ATM_PIN", "1234"),
        INITIAL_BALANCE_CENTS=100_000,
        LOGIN_ATTEMPT_LIMIT=LOGIN_ATTEMPT_LIMIT,
        LOCKOUT_SECONDS=LOCKOUT_SECONDS,
    )
    if test_config:
        app.config.update(test_config)

    pin = str(app.config["ATM_PIN"])
    if not pin.isascii() or not pin.isdigit() or not 4 <= len(pin) <= 12:
        raise ValueError("ATM_PIN must contain four to twelve digits.")
    app.config["ATM_PIN"] = pin
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    initialize_database(app)

    @app.teardown_appcontext
    def close_database(_error: BaseException | None = None) -> None:
        connection = g.pop("database", None)
        if connection is not None:
            connection.close()

    @app.get("/")
    def index():
        balance_cents = None
        if session.get("authenticated"):
            balance_cents = get_database().execute(
                "SELECT balance_cents FROM account WHERE id = 1"
            ).fetchone()["balance_cents"]
        return render_template(
            "index.html",
            balance_display=format_money(balance_cents) if balance_cents is not None else None,
            show_demo_pin=app.config["ATM_PIN"] == "1234",
        )

    @app.post("/login")
    def login():
        validate_csrf()
        connection = get_database()
        connection.execute("BEGIN IMMEDIATE")
        state = connection.execute(
            "SELECT failed_attempts, locked_until FROM login_state WHERE id = 1"
        ).fetchone()
        now = time.time()

        if state["locked_until"] > now:
            seconds_left = int(state["locked_until"] - now + 0.999)
            connection.commit()
            flash(f"Access is locked. Try again in {seconds_left} seconds.", "error")
            return redirect(url_for("index"))

        attempts = state["failed_attempts"] if state["locked_until"] == 0 else 0
        submitted_pin = request.form.get("pin", "")
        if (
            submitted_pin.isascii()
            and submitted_pin.isdigit()
            and hmac.compare_digest(submitted_pin, app.config["ATM_PIN"])
        ):
            connection.execute(
                "UPDATE login_state SET failed_attempts = 0, locked_until = 0 WHERE id = 1"
            )
            connection.commit()
            session.clear()
            session["authenticated"] = True
            session["csrf_token"] = secrets.token_urlsafe(32)
            flash("Welcome. You are signed in.", "success")
            return redirect(url_for("index"))

        attempts += 1
        locked_until = (
            now + app.config["LOCKOUT_SECONDS"]
            if attempts >= app.config["LOGIN_ATTEMPT_LIMIT"]
            else 0
        )
        connection.execute(
            "UPDATE login_state SET failed_attempts = ?, locked_until = ? WHERE id = 1",
            (attempts, locked_until),
        )
        connection.commit()

        if locked_until:
            flash(
                "Too many incorrect PINs. Access is temporarily locked.",
                "error",
            )
        else:
            remaining = app.config["LOGIN_ATTEMPT_LIMIT"] - attempts
            flash(f"Incorrect PIN. {remaining} attempt(s) remaining.", "error")
        return redirect(url_for("index"))

    @app.post("/transaction")
    @login_required
    def transaction():
        validate_csrf()
        amount_cents = parse_amount(request.form.get("amount", ""))
        if amount_cents is None:
            flash("Enter an amount greater than $0.00 with at most two decimal places.", "error")
            return redirect(url_for("index"))

        operation = request.form.get("operation")
        if operation not in {"deposit", "withdraw"}:
            abort(400, description="Unsupported transaction.")

        connection = get_database()
        connection.execute("BEGIN IMMEDIATE")
        balance_cents = connection.execute(
            "SELECT balance_cents FROM account WHERE id = 1"
        ).fetchone()["balance_cents"]

        if operation == "withdraw" and amount_cents > balance_cents:
            connection.rollback()
            flash("Insufficient funds for that withdrawal.", "error")
            return redirect(url_for("index"))
        if operation == "deposit" and amount_cents > MAX_SQLITE_INTEGER - balance_cents:
            connection.rollback()
            flash("That deposit exceeds the supported account balance.", "error")
            return redirect(url_for("index"))

        adjustment = amount_cents if operation == "deposit" else -amount_cents
        connection.execute(
            "UPDATE account SET balance_cents = balance_cents + ? WHERE id = 1",
            (adjustment,),
        )
        connection.commit()
        formatted_amount = format_money(amount_cents)
        verb = "Deposited" if operation == "deposit" else "Withdrew"
        flash(f"{verb} {formatted_amount}.", "success")
        return redirect(url_for("index"))

    @app.post("/logout")
    @login_required
    def logout():
        validate_csrf()
        session.clear()
        flash("You have been signed out.", "success")
        return redirect(url_for("index"))

    @app.context_processor
    def inject_csrf_token() -> dict[str, Callable[[], str]]:
        return {"csrf_token": get_csrf_token}

    return app


def login_required(view: F) -> F:
    @wraps(view)
    def wrapped(*args: object, **kwargs: object):
        if not session.get("authenticated"):
            flash("Please sign in to continue.", "error")
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    return wrapped  # type: ignore[return-value]


def get_database() -> sqlite3.Connection:
    if "database" not in g:
        connection = sqlite3.connect(current_app.config["DATABASE"])
        connection.row_factory = sqlite3.Row
        g.database = connection
    return g.database


def initialize_database(app: Flask) -> None:
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        with connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS account (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    balance_cents INTEGER NOT NULL CHECK (balance_cents >= 0)
                );
                CREATE TABLE IF NOT EXISTS login_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until REAL NOT NULL DEFAULT 0
                );
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO account (id, balance_cents) VALUES (1, ?)",
                (app.config["INITIAL_BALANCE_CENTS"],),
            )
            connection.execute("INSERT OR IGNORE INTO login_state (id) VALUES (1)")


def get_csrf_token() -> str:
    token = session.get("csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf() -> None:
    expected = session.get("csrf_token")
    submitted = request.form.get("csrf_token", "")
    if (
        not isinstance(expected, str)
        or not submitted.isascii()
        or not hmac.compare_digest(expected, submitted)
    ):
        abort(400, description="Invalid or missing CSRF token.")


def parse_amount(raw_amount: str) -> int | None:
    try:
        amount = Decimal(raw_amount)
        if not amount.is_finite() or amount <= 0 or amount * 100 != (amount * 100).to_integral_value():
            return None
        cents = int(amount * 100)
    except (InvalidOperation, ValueError, OverflowError):
        return None
    if cents > MAX_SQLITE_INTEGER:
        return None
    return cents


def format_money(cents: int) -> str:
    return f"${cents // 100:,}.{cents % 100:02d}"


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
