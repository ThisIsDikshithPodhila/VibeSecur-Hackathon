"""Plain-language presenter copy derived from saved business records.

This module never authorizes a payment or repair. Only exact, human-submitted
requests are routed to existing controller commands by the presenter API.
"""

from __future__ import annotations

import re


def message_intent(value: str) -> str:
    normalized = re.sub(r"\s+", " ", value.strip().lower()).rstrip(".!?")
    if normalized in {
        "process today's supplier invoice and prepare the payment",
        "process todays supplier invoice and prepare the payment",
        "pay the approved supplier invoice",
        "process the approved supplier invoice",
        "process the supplier invoice",
    }:
        return "start_work"
    if normalized == "fix it":
        return "fix"
    if normalized in {"investigate", "investigate incident", "investigate this", "what happened"}:
        return "investigate"
    if normalized in {"continue work with the approved invoice", "continue with the approved invoice", "continue supplier payment"}:
        return "continue"
    if normalized in {"resume payment", "resume approved payment", "continue approved payment"}:
        return "resume"
    if normalized in {"change the plan", "edit the plan"}:
        return "edit_plan"
    if normalized.startswith(("also ", "add ", "include ", "require ", "remove ")):
        return "plan_note"
    if any(phrase in normalized for phrase in ("summarize the invoice", "invoice details", "read the invoice")):
        return "invoice"
    if any(phrase in normalized for phrase in ("supplier status", "supplier record", "check supplier")):
        return "supplier"
    if any(phrase in normalized for phrase in ("prepare payment", "payment for approval")):
        return "prepare"
    if any(phrase in normalized for phrase in ("pending approvals", "show approvals")):
        return "approvals"
    return "unsupported"


def plan_from_investigation(report: dict | None) -> str:
    """Build an editable proposal from the actual investigation fields."""
    if not isinstance(report, dict) or not report.get("evidenceRefs"):
        return ""
    if report.get('disposition') not in (None, 'recovery_required'):
        return ""
    correction = report.get("correction")
    acceptance = report.get("acceptanceCriteria")
    rollback = report.get("rollback")
    steps: list[str] = []
    if isinstance(correction, str) and correction.strip():
        steps.append(correction.strip().rstrip("."))
    if isinstance(acceptance, list):
        steps.extend(item.strip().rstrip(".") for item in acceptance
                     if isinstance(item, str) and item.strip())
    if isinstance(rollback, str) and rollback.strip():
        steps.append("Prepare rollback: " + rollback.strip().rstrip("."))
    return "\n\n".join(f"{number}. {item}." for number, item in enumerate(steps, 1))


def _money(amount_minor: int, currency: str) -> str:
    major = amount_minor / 100
    return f"{currency} {major:,.0f}" if amount_minor % 100 == 0 else f"{currency} {major:,.2f}"


def business_reply(run: dict, intent: str) -> str:
    protected = run["protected"]
    invoice = protected["invoice"]
    supplier = protected["supplier"]
    amount = _money(invoice["amountMinor"], invoice["currency"])
    if intent == "invoice":
        source_read = any(event["kind"] == "source.document_http" and event.get("data", {}).get("httpStatus") == 200
                          for event in run.get("events", []))
        source = "The supplier document was read in this run." if source_read else "This comes from the saved invoice record; the supplier document has not been read in this run."
        return f"Invoice {invoice['invoiceId']} is for {amount}. {source}"
    if intent == "supplier":
        return (f"The saved supplier record is {supplier['supplierId']}. "
                "This run has no separate supplier-active status field, so I cannot claim an active-status check passed.")
    if intent == "prepare":
        return (f"The current payment details are invoice {invoice['invoiceId']} for {amount}. "
                "Review the exact beneficiary in the payment approval control before authorizing it.")
    if intent == "approvals":
        active = [approval for approval in protected.get("approvals", [])
                  if not approval.get("consumed") and not approval.get("revoked")]
        return (f"The protected payment record has {len(active)} unconsumed, unrevoked approval(s). "
                "The server checks expiry and exact transaction details when payment is executed.")
    if intent == "edit_plan":
        return "Open the plan editor to review and save changes. Saved notes do not change the configured repair mission yet."
    return ("I can show the saved invoice and supplier records, approvals, incident, investigation and repair state. "
            "I could not match that message to a supported work action; no action was taken.")
