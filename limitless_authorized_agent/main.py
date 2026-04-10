#!/usr/bin/env python3
"""
Limitless Authorized Security Agent (single-folder starter).

This is a safe, defensive starter that helps operators generate:
1) A constrained system prompt.
2) A runtime engagement policy block.
3) Reusable task templates.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from textwrap import dedent


SYSTEM_PROMPT_TEMPLATE = dedent(
    """\
    You are Aegis, an elite coding and authorized security testing agent.

    Mission:
    - Deliver high-quality engineering and defensive security outcomes quickly.
    - Combine software development, threat modeling, code review, and authorized pentesting support.

    Non-negotiable constraints:
    1) Operate only on approved assets in the current engagement scope.
    2) Refuse any action that is illegal, unethical, out of scope, or lacks explicit authorization.
    3) Prefer low-impact verification first; require human approval before active or potentially disruptive tests.
    4) Produce complete audit trails: intent, commands, outputs, findings, and remediation.
    5) Never fabricate results—if uncertain, say so and request the next best verification step.

    Behavior standards:
    - Think in phases: Discover → Plan → Validate Policy → Execute → Verify → Report.
    - Be concise in chat, exhaustive in logs/artifacts.
    - Default to reproducible workflows (scripts, Make targets, CI jobs, typed contracts).
    - Convert every finding into actionable remediation with severity, confidence, evidence, and owner-ready fix steps.
    - When coding, prioritize secure defaults, test coverage, and least privilege.
    """
)


CAPABILITY_PROFILE = dedent(
    """\
    Capability profile:
    - Senior full-stack engineer (TypeScript, Python, Go)
    - AppSec specialist (OWASP ASVS, CWE/CVE mapping, secure code review)
    - Cloud security practitioner (AWS/Azure/GCP hardening guidance)
    - Detection engineer (log correlation, triage playbooks, alert tuning)
    - Documentation expert (runbooks, executive summaries, remediation plans)
    """
)


TASK_TEMPLATES = dedent(
    """\
    Secure coding task:
    - Implement <feature> with secure defaults.
    - Add threat model assumptions.
    - Add input validation and authorization checks.
    - Add unit/integration tests, including abuse cases.

    Authorized pentest task:
    - Evaluate <target> for <risk category> within approved scope.
    - Confirm scope and approval ID.
    - Run passive/low-impact recon first.
    - Request approval before active validation.
    - Capture evidence and map findings to CWE/OWASP.

    Incident triage task:
    - Investigate <alert/event>.
    - Build timeline from telemetry.
    - Identify root cause and blast radius.
    - Propose containment, eradication, and recovery actions.
    """
)


@dataclass(frozen=True)
class EngagementPolicy:
    engagement_id: str
    authorized_by: str
    valid_from_iso: str
    valid_to_iso: str
    in_scope_domain: str
    in_scope_cidr: str
    approval_contact: str

    def to_yaml(self) -> str:
        return dedent(
            f"""\
            engagement:
              id: "{self.engagement_id}"
              authorized_by: "{self.authorized_by}"
              valid_from: "{self.valid_from_iso}"
              valid_to: "{self.valid_to_iso}"
            scope:
              in_scope_domains:
                - "{self.in_scope_domain}"
              in_scope_ips:
                - "{self.in_scope_cidr}"
              out_of_scope:
                - "production-payment-systems"
            rules:
              max_request_rate_per_target: 2
              active_testing_requires_approval: true
              prohibited_actions:
                - "DoS/stress testing"
                - "social engineering"
                - "persistence/backdoors"
            approval_contacts:
              primary: "{self.approval_contact}"
            """
        )


def utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a constrained prompt pack for an authorized security agent."
    )
    parser.add_argument("--engagement-id", default="ENG-2026-001")
    parser.add_argument("--authorized-by", default="Security Director")
    parser.add_argument("--valid-from", default=utc_now_iso())
    parser.add_argument("--valid-to", default="2026-12-31T23:59:59Z")
    parser.add_argument("--domain", default="example.com")
    parser.add_argument("--cidr", default="203.0.113.0/24")
    parser.add_argument("--approval-contact", default="oncall-security@example.com")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    policy = EngagementPolicy(
        engagement_id=args.engagement_id,
        authorized_by=args.authorized_by,
        valid_from_iso=args.valid_from,
        valid_to_iso=args.valid_to,
        in_scope_domain=args.domain,
        in_scope_cidr=args.cidr,
        approval_contact=args.approval_contact,
    )

    print("# LIMITLESS AUTHORIZED SECURITY AGENT PACK\n")
    print("## SYSTEM PROMPT\n")
    print(SYSTEM_PROMPT_TEMPLATE)
    print("## CAPABILITY PROFILE\n")
    print(CAPABILITY_PROFILE)
    print("## ENGAGEMENT POLICY (YAML)\n")
    print(policy.to_yaml())
    print("## TASK TEMPLATES\n")
    print(TASK_TEMPLATES)


if __name__ == "__main__":
    main()
