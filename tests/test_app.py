import re
import tempfile
import unittest
from pathlib import Path

from app import create_app


class ATMAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        database_path = Path(self.temporary_directory.name) / "test.sqlite3"
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE": str(database_path),
                "ATM_PIN": "2468",
                "SECRET_KEY": "test-secret",
                "INITIAL_BALANCE_CENTS": 25_000,
                "LOCKOUT_SECONDS": 60,
            }
        )
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def csrf_token(self) -> str:
        response = self.client.get("/")
        match = re.search(
            rb'name="csrf_token" value="([^"]+)"',
            response.data,
        )
        self.assertIsNotNone(match)
        return match.group(1).decode()

    def login(self) -> None:
        response = self.client.post(
            "/login", data={"pin": "2468", "csrf_token": self.csrf_token()}
        )
        self.assertEqual(response.status_code, 302)

    def balance(self) -> str:
        return self.client.get("/").get_data(as_text=True)

    def test_login_and_balance(self) -> None:
        response = self.client.post(
            "/login", data={"pin": "2468", "csrf_token": self.csrf_token()}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("$250.00", self.balance())

    def test_wrong_pin_locks_account_after_three_attempts(self) -> None:
        for _ in range(3):
            response = self.client.post(
                "/login", data={"pin": "0000", "csrf_token": self.csrf_token()}
            )
            self.assertEqual(response.status_code, 302)

        response = self.client.post(
            "/login", data={"pin": "2468", "csrf_token": self.csrf_token()}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("locked", self.balance().lower())
        self.assertNotIn("$250.00", self.balance())

    def test_non_ascii_pin_is_rejected(self) -> None:
        response = self.client.post(
            "/login",
            data={"pin": "１２３４", "csrf_token": self.csrf_token()},
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("Incorrect PIN", self.balance())

    def test_deposit_and_withdrawal_update_balance(self) -> None:
        self.login()
        response = self.client.post(
            "/transaction",
            data={
                "operation": "deposit",
                "amount": "12.34",
                "csrf_token": self.csrf_token(),
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("$262.34", self.balance())

        response = self.client.post(
            "/transaction",
            data={
                "operation": "withdraw",
                "amount": "2.34",
                "csrf_token": self.csrf_token(),
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("$260.00", self.balance())

    def test_balance_persists_between_app_instances(self) -> None:
        self.login()
        self.client.post(
            "/transaction",
            data={
                "operation": "deposit",
                "amount": "5.00",
                "csrf_token": self.csrf_token(),
            },
        )
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE": str(Path(self.temporary_directory.name) / "test.sqlite3"),
                "ATM_PIN": "2468",
                "SECRET_KEY": "test-secret",
            }
        )
        self.client = self.app.test_client()
        self.login()
        self.assertIn("$255.00", self.balance())

    def test_withdrawal_cannot_overdraw_and_amount_must_be_valid(self) -> None:
        self.login()
        token = self.csrf_token()
        response = self.client.post(
            "/transaction",
            data={"operation": "withdraw", "amount": "250.01", "csrf_token": token},
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("$250.00", self.balance())

        response = self.client.post(
            "/transaction",
            data={"operation": "deposit", "amount": "1.001", "csrf_token": token},
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("$250.00", self.balance())

    def test_transaction_requires_login_and_csrf(self) -> None:
        response = self.client.post("/transaction")
        self.assertEqual(response.status_code, 302)

        self.login()
        response = self.client.post(
            "/transaction", data={"operation": "deposit", "amount": "1.00"}
        )
        self.assertEqual(response.status_code, 400)
        response = self.client.post(
            "/transaction",
            data={
                "operation": "deposit",
                "amount": "1.00",
                "csrf_token": "１２３４",
            },
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
