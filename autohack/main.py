#!/usr/bin/env python3
"""
AutoHack (authorized-only): a standalone defensive security automation starter.

This program is intentionally constrained for legal/authorized use:
- Requires explicit in-scope targets.
- Blocks prohibited actions.
- Generates auditable JSONL logs for every step.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now_iso() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class Policy:
    engagement_id: str = "ENG-2026-001"
    authorized_by: str = "Security Director"
    valid_from: str = field(default_factory=now_iso)
    valid_to: str = "2026-12-31T23:59:59Z"
    in_scope_targets: list[str] = field(default_factory=lambda: ["example.com", "127.0.0.1"])
    max_commands: int = 10
    active_testing_requires_approval: bool = True
    prohibited_actions: list[str] = field(
        default_factory=lambda: ["dos", "social_engineering", "persistence", "credential_stuffing"]
    )

    @staticmethod
    def from_file(path: Path) -> "Policy":
        raw = json.loads(path.read_text(encoding="utf-8"))
        return Policy(**raw)

    def to_file(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), indent=2) + "\n", encoding="utf-8")


def append_log(log_path: Path, event: dict[str, Any]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"ts": now_iso(), **event}
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")


def check_scope(policy: Policy, target: str) -> bool:
    return target in policy.in_scope_targets


def build_recon_command(target: str, mode: str) -> list[str]:
    if mode == "dns":
        return ["nslookup", target]
    if mode == "tcp":
        return ["nmap", "-sT", "-Pn", "--top-ports", "100", target]
    if mode == "http":
        return ["curl", "-I", f"https://{target}"]
    raise ValueError(f"Unsupported recon mode: {mode}")


def run_command(cmd: list[str], timeout_seconds: int = 60) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def cmd_init(args: argparse.Namespace) -> int:
    policy_path = Path(args.policy)
    if policy_path.exists() and not args.force:
        print(f"Policy already exists: {policy_path} (use --force to overwrite)")
        return 1
    Policy().to_file(policy_path)
    print(f"Wrote policy: {policy_path}")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    policy = Policy.from_file(Path(args.policy))
    if not check_scope(policy, args.target):
        print(f"Blocked: target '{args.target}' is out of scope.")
        return 2

    risk = "low" if args.mode in {"dns", "http"} else "medium"
    approval_needed = policy.active_testing_requires_approval and args.mode == "tcp"
    plan = {
        "objective": f"Run authorized {args.mode} recon on {args.target}",
        "steps": [
            "Validate policy scope",
            f"Execute recon mode '{args.mode}'",
            "Capture evidence to JSONL log",
            "Summarize findings and remediation",
        ],
        "risk": risk,
        "approval_required": approval_needed,
    }
    print(json.dumps(plan, indent=2))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    policy = Policy.from_file(Path(args.policy))
    log_path = Path(args.log)

    if not check_scope(policy, args.target):
        append_log(log_path, {"event": "blocked", "reason": "out_of_scope", "target": args.target})
        print(f"Blocked: target '{args.target}' is out of scope.")
        return 2

    if args.action in policy.prohibited_actions:
        append_log(log_path, {"event": "blocked", "reason": "prohibited_action", "action": args.action})
        print(f"Blocked: prohibited action '{args.action}'.")
        return 3

    if args.mode == "tcp" and policy.active_testing_requires_approval and not args.approved:
        append_log(log_path, {"event": "blocked", "reason": "approval_required", "mode": args.mode})
        print("Blocked: --approved is required for tcp mode under current policy.")
        return 4

    cmd = build_recon_command(args.target, args.mode)
    append_log(
        log_path,
        {
            "event": "command_start",
            "engagement_id": policy.engagement_id,
            "target": args.target,
            "mode": args.mode,
            "command": shlex.join(cmd),
        },
    )

    try:
        code, stdout, stderr = run_command(cmd, timeout_seconds=args.timeout)
    except FileNotFoundError as err:
        append_log(log_path, {"event": "command_error", "error": str(err), "command": shlex.join(cmd)})
        print(f"Tool missing: {err}")
        return 5
    except subprocess.TimeoutExpired:
        append_log(log_path, {"event": "command_timeout", "command": shlex.join(cmd)})
        print("Command timed out.")
        return 6

    append_log(
        log_path,
        {
            "event": "command_finish",
            "exit_code": code,
            "stdout_preview": stdout[:1000],
            "stderr_preview": stderr[:1000],
        },
    )

    print(f"Exit code: {code}")
    if stdout.strip():
        print("--- stdout ---")
        print(stdout[:1000])
    if stderr.strip():
        print("--- stderr ---")
        print(stderr[:1000])
    print(f"Audit log: {log_path}")
    return 0 if code == 0 else code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Standalone authorized security automation starter.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    init_p = sub.add_parser("init-policy", help="Create a starter policy JSON.")
    init_p.add_argument("--policy", default="policy.json")
    init_p.add_argument("--force", action="store_true")
    init_p.set_defaults(func=cmd_init)

    plan_p = sub.add_parser("plan", help="Create a constrained run plan.")
    plan_p.add_argument("--policy", default="policy.json")
    plan_p.add_argument("--target", required=True)
    plan_p.add_argument("--mode", choices=["dns", "tcp", "http"], default="dns")
    plan_p.set_defaults(func=cmd_plan)

    run_p = sub.add_parser("run", help="Execute approved recon with audit logging.")
    run_p.add_argument("--policy", default="policy.json")
    run_p.add_argument("--log", default="autohack.log.jsonl")
    run_p.add_argument("--target", required=True)
    run_p.add_argument("--mode", choices=["dns", "tcp", "http"], default="dns")
    run_p.add_argument("--action", default="recon")
    run_p.add_argument("--approved", action="store_true")
    run_p.add_argument("--timeout", type=int, default=60)
    run_p.set_defaults(func=cmd_run)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
def cmd_web_security(args: argparse.Namespace) -> int:
    policy = Policy.from_file(Path(args.policy))
    parsed = urlparse(args.url)
    domain = parsed.hostname or ""
    if domain not in policy.allowed_web_domains:
        print(f"Blocked: domain '{domain}' is not in policy allowed_web_domains.")
        return 2

    request = Request(args.url, headers={"User-Agent": "autohack/1.0"})
    try:
        with urlopen(request, timeout=args.timeout) as response:  # noqa: S310
            headers = {k.lower(): v for k, v in response.headers.items()}
    except Exception as err:  # noqa: BLE001
        print(f"Security check failed: {err}")
        return 1

    required = [
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
    ]
    missing = [h for h in required if h not in headers]
    print(f"URL: {args.url}")
    print("Missing recommended headers:")
    if missing:
        for h in missing:
            print(f"- {h}")
    else:
        print("- none")
    return 0


    websec_p = sub.add_parser(
        "web-security-check",
        help="Check common browser security headers (safe alternative to JS injection testing).",
    )
    websec_p.add_argument("--policy", default="policy.json")
    websec_p.add_argument("--url", required=True)
    websec_p.add_argument("--timeout", type=int, default=10)
    websec_p.set_defaults(func=cmd_web_security)

def extract_target(text: str, default_target: str) -> str:
    domain_match = re.search(r"\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    if domain_match:
        return domain_match.group(0)
    if ip_match:
        return ip_match.group(0)
    return default_target


def cmd_agent(args: argparse.Namespace) -> int:
    prompt = args.task.lower()
    target = extract_target(args.task, args.default_target)

    if any(word in prompt for word in ["tool", "kali", "installed"]):
        return cmd_check_tools(argparse.Namespace(json=args.json))

    if "plan" in prompt:
        mode = "tcp" if any(w in prompt for w in ["port", "tcp", "scan"]) else "dns"
        return cmd_plan(argparse.Namespace(policy=args.policy, target=target, mode=mode))

    if any(word in prompt for word in ["header", "csp", "security check"]):
        return cmd_web_security(argparse.Namespace(policy=args.policy, url=f"https://{target}", timeout=args.timeout))

    if any(word in prompt for word in ["website", "web", "fetch"]):
        return cmd_web(
            argparse.Namespace(
                policy=args.policy,
                url=f"https://{target}",
                timeout=args.timeout,
                max_bytes=args.max_bytes,
            )
        )

    if any(word in prompt for word in ["terminal", "command", "run shell"]):
        shell_cmd = args.fallback_command
        return cmd_terminal(argparse.Namespace(policy=args.policy, command=shell_cmd, timeout=args.timeout))

    mode = "tcp" if any(w in prompt for w in ["port", "tcp", "scan"]) else "dns"
    return cmd_run(
        argparse.Namespace(
            policy=args.policy,
            log=args.log,
            target=target,
            mode=mode,
            engine=args.engine,
            action="recon",
            approved=args.approved,
            timeout=args.timeout,
        )
    )


    agent_p = sub.add_parser("agent", help="Natural-language autopilot wrapper so you don't memorize commands.")
    agent_p.add_argument("--policy", default="policy.json")
    agent_p.add_argument("--task", required=True, help="Natural language task, e.g. 'plan scan for example.com'")
    agent_p.add_argument("--default-target", default="example.com")
    agent_p.add_argument("--engine", choices=["stdlib", "external"], default="stdlib")
    agent_p.add_argument("--approved", action="store_true")
    agent_p.add_argument("--timeout", type=int, default=10)
    agent_p.add_argument("--max-bytes", type=int, default=2000)
    agent_p.add_argument("--log", default="autohack.log.jsonl")
    agent_p.add_argument("--json", action="store_true", help="Used for tool inventory tasks.")
    agent_p.add_argument("--fallback-command", default="echo agent-ready")
    agent_p.set_defaults(func=cmd_agent)

