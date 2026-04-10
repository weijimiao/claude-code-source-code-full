# AutoHack (Authorized-Only)

Standalone folder you can copy and run independently.

## Quick start

```bash
cd autohack
python3 main.py init-policy --policy policy.json
python3 main.py plan --policy policy.json --target example.com --mode dns
python3 main.py run --policy policy.json --target example.com --mode dns --log run.log.jsonl
```

## Notes

- This tool is for **authorized defensive testing** only.
- It enforces target scope checks and blocks prohibited actions from policy.
- It writes JSONL audit logs for each run step.
