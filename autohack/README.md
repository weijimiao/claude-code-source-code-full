# AutoHack (Authorized-Only)

Standalone folder you can copy and run independently.

- Run safe web hardening checks (`web-security-check`) for security headers.
## Quick start

```bash
cd autohack
python3 main.py init-policy --policy policy.json
python3 main.py plan --policy policy.json --target example.com --mode dns
python3 main.py run --policy policy.json --target example.com --mode dns --log run.log.jsonl
python3 main.py web-security-check --policy policy.json --url https://example.com
```

py main.py web-security-check --policy policy.json --url https://example.com
## Notes

# or install from requirements file:
. .venv/bin/activate
pip install -r requirements.txt
# or install from requirements file:
.venv\Scripts\activate
pip install -r requirements.txt
- This tool is for **authorized defensive testing** only.
- It enforces target scope checks and blocks prohibited actions from policy.
- It writes JSONL audit logs for each run step.
- JavaScript injection/exploitation is intentionally not implemented; use `web-security-check` for defensive validation.
