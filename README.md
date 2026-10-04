# License Desk

Customer and license panel with a view-only login. Data is fake. No live keys, no IP addresses, no payments.

Demo: https://license-desk.onrender.com

Log in with this user and password to access demo
User: DemoMode Password: D!D!D!

Admin: `admin` / `YardAdmin!42`

DemoMode can open customers, licenses, a license page, and the audit log. It cannot add customers, issue licenses, revoke licenses, change passwords, or generate keys. Those posts return 403. Issue and revoke write an audit row.

## Run

```bash
cd license-desk
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
