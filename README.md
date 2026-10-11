# Simple ATM

A small, single-account ATM web app built with Python and Flask. It supports PIN
authentication, balance checks, deposits, withdrawals, and a five-minute lockout
after three failed login attempts. The account balance and lockout state are
stored in SQLite.

## Run locally

1. Install Python 3.10 or newer.
2. (Optional) Create and activate a virtual environment.
3. Install the dependency:

   ```powershell
   py -m pip install -r requirements.txt
   ```

4. Start the app:

   ```powershell
   py app.py
   ```

5. Open <http://127.0.0.1:5000>.

The local demo PIN is `1234`. You can change it with the `ATM_PIN` environment
variable (four to twelve digits). Set `ATM_SECRET_KEY` to a stable, private
random value if you want browser sessions to survive server restarts. The
default account starts with a balance of `$1,000.00`; its balance and login
lockout are saved in `instance/atm.sqlite3`.

This is an educational, single-account demo, not a production banking system.
Do not expose the development server to the public internet or use real account
credentials or funds.

## Tests

Run the tests with:

```powershell
py -m unittest discover -s tests -v
```
