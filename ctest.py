#!/usr/bin/env python3
"""C-Test — lean AWS Config post-deployment / black-box compliance validation.

C-Test is intended to validate the observable behavior of AWS Config after deployment
without requiring knowledge of, or access to, the target department's underlying cloud
architecture. It can analyze an entire conformance pack or one standalone AWS-managed
Config rule, trigger a fresh on-demand evaluation, wait for that evaluation using bounded
polling rather than a fixed sleep, distinguish confirmed non-compliance from operational
errors and insufficient data, and return the most useful AWS-provided forensic detail
available. Output is obfuscated by default so account, resource, network, and other
potentially identifying values are replaced with stable-within-run correlation tokens;
full diagnostic output requires an explicit command-line override.

Output marker: C-Test Tango
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import re
import secrets
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError


APP_NAME = "C-Test"
OUTPUT_MARKER = "C-Test Tango"
MAX_RULES_PER_API_CALL = 25
DEFAULT_POLL_INTERVAL = 5.0
DEFAULT_TIMEOUT = 300.0

EXIT_PASS = 0
EXIT_FAIL = 2
EXIT_INDETERMINATE = 3
EXIT_ERROR = 4


@dataclass
class RuleOutcome:
    name: str
    source_identifier: str
    compliance: str
    operational_error: Optional[str] = None


class Obfuscator:
    """Preserve diagnostic meaning while replacing identifying values with tokens."""

    _ARN_RE = re.compile(r"arn:(?:aws|aws-us-gov|aws-cn):[^\s,;\]\[()]+", re.IGNORECASE)
    _ACCOUNT_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
    _EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
    _AWS_ID_RE = re.compile(
    r"\b(?:i|vpc|subnet|sg|eni|eipalloc|vol|snap|ami|rtb|acl|nat|igw|vpce|fs|fsap)-[0-9a-zA-Z]+\b"
    )
    _IP_CANDIDATE_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f:.]{3,})(?![\w:])")

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self._key = secrets.token_bytes(32)
        self._cache: Dict[Tuple[str, str], str] = {}

    def token(self, kind: str, value: Any) -> str:
        text = "N/A" if value is None else str(value)
        if not self.enabled or text in {"", "N/A", "None"}:
            return text

        cache_key = (kind, text)
        if cache_key not in self._cache:
            digest = hmac.new(self._key, text.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
            self._cache[cache_key] = f"<{kind}:{digest}>"
        return self._cache[cache_key]

    def sanitize_text(self, value: Any) -> str:
        text = "" if value is None else str(value)
        if not self.enabled or not text:
            return text

        text = self._ARN_RE.sub(lambda m: self.token("arn", m.group(0)), text)
        text = self._EMAIL_RE.sub(lambda m: self.token("email", m.group(0)), text)
        text = self._AWS_ID_RE.sub(lambda m: self.token("resource", m.group(0)), text)
        text = self._ACCOUNT_RE.sub(lambda m: self.token("account", m.group(0)), text)

        def replace_ip(candidate: re.Match[str]) -> str:
            raw = candidate.group(0)
            try:
                ipaddress.ip_address(raw)
                return self.token("ip", raw)
            except ValueError:
                return raw

        return self._IP_CANDIDATE_RE.sub(replace_ip, text)


# ------------------------------------------------------------------------------
# Utility helpers
# ------------------------------------------------------------------------------

def chunks(values: Sequence[str], size: int = MAX_RULES_PER_API_CALL) -> Iterable[List[str]]:
    for index in range(0, len(values), size):
        yield list(values[index : index + size])


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def latest_timestamp(status: Mapping[str, Any]) -> Optional[datetime]:
    candidates = [
    status.get("LastSuccessfulEvaluationTime"),
    status.get("LastFailedEvaluationTime"),
    ]
    valid = [value for value in candidates if isinstance(value, datetime)]
    return max(valid) if valid else None


def aws_error_text(exc: BaseException, obfuscator: Obfuscator) -> str:
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        code = error.get("Code", "ClientError")
        message = obfuscator.sanitize_text(error.get("Message", str(exc)))
        return f"{code}: {message}"
    return obfuscator.sanitize_text(str(exc))


def make_config_client(args: argparse.Namespace):
    session_kwargs: Dict[str, str] = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    if args.region:
        session_kwargs["region_name"] = args.region
    session = boto3.Session(**session_kwargs)
    return session.client("config"), session.region_name or "unknown"


def print_header(mode: str, target: str, region: str, obfuscator: Obfuscator) -> None:
    print("=" * 100)
    print(OUTPUT_MARKER)
    print(f"APPLICATION : {APP_NAME}")
    print(f"UTC RUN TIME : {utc_now_iso()}")
    print(f"MODE : {mode.upper()}")
    print(f"TARGET : {obfuscator.token('target', target)}")
    print(f"AWS REGION : {obfuscator.token('region', region)}")
    print(f"OBFUSCATION : {'ENABLED (default)' if obfuscator.enabled else 'DISABLED (explicit override)'}")
    print("VERDICT POLICY : PASS only on confirmed compliance; FAIL on confirmed non-compliance;")
    print(" INDETERMINATE for insufficient evidence; ERROR for operational failure.")
    print("=" * 100)


# ------------------------------------------------------------------------------
# AWS Config discovery
# ------------------------------------------------------------------------------

def get_pack_rule_summaries(config_client, pack_name: str) -> List[Dict[str, Any]]:
    paginator = config_client.get_paginator("describe_conformance_pack_compliance")
    summaries: List[Dict[str, Any]] = []
    for page in paginator.paginate(ConformancePackName=pack_name):
        summaries.extend(page.get("ConformancePackRuleComplianceList", []))
    return summaries


def describe_rules(config_client, rule_names: Sequence[str]) -> Dict[str, Dict[str, Any]]:
    described: Dict[str, Dict[str, Any]] = {}
    for batch in chunks(list(rule_names)):
        response = config_client.describe_config_rules(ConfigRuleNames=batch)
        for rule in response.get("ConfigRules", []):
            described[rule["ConfigRuleName"]] = rule
    return described


def get_rule_evaluation_statuses(config_client, rule_names: Sequence[str]) -> Dict[str, Dict[str, Any]]:
    statuses: Dict[str, Dict[str, Any]] = {}
    for batch in chunks(list(rule_names)):
        response = config_client.describe_config_rule_evaluation_status(ConfigRuleNames=batch)
        for status in response.get("ConfigRulesEvaluationStatus", []):
            statuses[status["ConfigRuleName"]] = status
    return statuses


# ------------------------------------------------------------------------------
# Evaluation + bounded polling
# ------------------------------------------------------------------------------

def evaluate_batch_and_poll(
    config_client,
    rule_names: Sequence[str],
    timeout: float,
    poll_interval: float,
    obfuscator: Obfuscator,
) -> Tuple[bool, Dict[str, Dict[str, Any]], List[str]]:
    """Start one <=25-rule batch and wait for a new terminal evaluation for each rule."""

    baseline_status = get_rule_evaluation_statuses(config_client, rule_names)
    baseline_time = {name: latest_timestamp(baseline_status.get(name, {})) for name in rule_names}

    try:
        config_client.start_config_rules_evaluation(ConfigRuleNames=list(rule_names))
    except (ClientError, BotoCoreError) as exc:
        return False, baseline_status, [f"Unable to start evaluation: {aws_error_text(exc, obfuscator)}"]

    deadline = time.monotonic() + timeout
    delay = max(1.0, poll_interval)
    last_status: Dict[str, Dict[str, Any]] = baseline_status
    pending = set(rule_names)
    diagnostics: List[str] = []

    while pending and time.monotonic() < deadline:
        try:
            # ConfigRuleState exposes EVALUATING/ACTIVE; evaluation status carries timestamps/errors.
            described = describe_rules(config_client, list(pending))
            fresh_status = get_rule_evaluation_statuses(config_client, list(pending))
            last_status.update(fresh_status)

            completed_now: List[str] = []
            for name in list(pending):
                rule_state = described.get(name, {}).get("ConfigRuleState", "UNKNOWN")
                status = fresh_status.get(name, {})
                current_time = latest_timestamp(status)
                before_time = baseline_time.get(name)
                advanced = current_time is not None and (before_time is None or current_time > before_time)

                if rule_state == "ACTIVE" and advanced:
                    completed_now.append(name)

            for name in completed_now:
                pending.discard(name)

        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"ThrottlingException", "Throttling", "RequestLimitExceeded"}:
                diagnostics.append(f"Polling throttled; retrying: {aws_error_text(exc, obfuscator)}")
            else:
                return False, last_status, [f"Polling failed: {aws_error_text(exc, obfuscator)}"]
        except BotoCoreError as exc:
            return False, last_status, [f"Polling failed: {aws_error_text(exc, obfuscator)}"]

        if pending:
            time.sleep(delay)
            delay = min(delay * 1.35, 20.0)

    if pending:
        unresolved = ", ".join(obfuscator.token("rule", name) for name in sorted(pending))
        diagnostics.append(
            f"Timed out after {timeout:.0f}s waiting for fresh evaluation evidence for: {unresolved}"
        )
        return False, last_status, diagnostics

    return True, last_status, diagnostics


def evaluate_rules(
    config_client,
    rule_names: Sequence[str],
    timeout: float,
    poll_interval: float,
    obfuscator: Obfuscator,
) -> Tuple[bool, Dict[str, Dict[str, Any]], List[str]]:
    """Evaluate all rules safely in AWS's <=25-name API batches."""

    all_statuses: Dict[str, Dict[str, Any]] = {}
    diagnostics: List[str] = []

    batches = list(chunks(list(rule_names)))
    for number, batch in enumerate(batches, start=1):
        print(f"[+] Starting evaluation batch {number}/{len(batches)} ({len(batch)} rule(s)).")
        ok, statuses, batch_diagnostics = evaluate_batch_and_poll(
            config_client, batch, timeout, poll_interval, obfuscator
        )
        all_statuses.update(statuses)
        diagnostics.extend(batch_diagnostics)
        if not ok:
            return False, all_statuses, diagnostics
        print(f"[+] Evaluation batch {number}/{len(batches)} completed.")

    return True, all_statuses, diagnostics


# ------------------------------------------------------------------------------
# Diagnostics and compliance collection
# ------------------------------------------------------------------------------

def platform_diagnostics(
    described_rules: Mapping[str, Mapping[str, Any]],
    statuses: Mapping[str, Mapping[str, Any]],
    obfuscator: Obfuscator,
) -> List[str]:
    findings: List[str] = []

    for name, rule in described_rules.items():
        source_identifier = rule.get("Source", {}).get("SourceIdentifier", "UNKNOWN")
        visible_name = obfuscator.token("rule", name)
        state = rule.get("ConfigRuleState", "UNKNOWN")
        status = statuses.get(name, {})
        error_code = status.get("LastErrorCode")
        error_message = status.get("LastErrorMessage")
        failed_eval = status.get("LastFailedEvaluationTime")
        successful_eval = status.get("LastSuccessfulEvaluationTime")

        if state != "ACTIVE":
            findings.append(
            f"Rule {visible_name} ({source_identifier}) state is {state}, not ACTIVE."
            )

        # Report a failure as current only when it is at least as recent as the last success.
        failure_is_current = bool(
            error_code
            and isinstance(failed_eval, datetime)
            and (not isinstance(successful_eval, datetime) or failed_eval >= successful_eval)
            )
        if failure_is_current:
            findings.append(
            "Rule "
            f"{visible_name} ({source_identifier}) execution failure: "
            f"{error_code}: {obfuscator.sanitize_text(error_message)}"
            )

    return findings


def get_pack_resource_results(config_client, pack_name: str) -> List[Dict[str, Any]]:
    paginator = config_client.get_paginator("get_conformance_pack_compliance_details")
    results: List[Dict[str, Any]] = []
    for page in paginator.paginate(ConformancePackName=pack_name):
        results.extend(page.get("ConformancePackRuleEvaluationResults", []))
    return results


def get_rule_resource_results(config_client, rule_name: str) -> List[Dict[str, Any]]:
    paginator = config_client.get_paginator("get_compliance_details_by_config_rule")
    results: List[Dict[str, Any]] = []
    for page in paginator.paginate(ConfigRuleName=rule_name):
        results.extend(page.get("EvaluationResults", []))
    return results


def print_resource_results(
    results: Sequence[Mapping[str, Any]],
    described_rules: Mapping[str, Mapping[str, Any]],
    obfuscator: Obfuscator,
) -> None:
    print("\n" + "=" * 100)
    print("RESOURCE-LEVEL COMPLIANCE & FORENSIC DETAIL")
    print("=" * 100)

    if not results:
        print("[!] AWS Config returned no resource-level evaluation results.")
        print(" This can be consistent with INSUFFICIENT_DATA or with a rule having no applicable recorded resources.")
        return

    for index, result in enumerate(results, start=1):
        identifier = result.get("EvaluationResultIdentifier", {})
        qualifier = identifier.get("EvaluationResultQualifier", {})
        rule_name = qualifier.get("ConfigRuleName", "UNKNOWN")
        rule = described_rules.get(rule_name, {})
        source_identifier = rule.get("Source", {}).get("SourceIdentifier", "UNKNOWN")
        resource_type = qualifier.get("ResourceType", "N/A")
        resource_id = qualifier.get("ResourceId", "N/A")
        compliance = result.get("ComplianceType", "UNKNOWN")
        annotation = result.get("Annotation") or "No annotation supplied by AWS Config."
        invoked = result.get("ConfigRuleInvokedTime")
        recorded = result.get("ResultRecordedTime")

        print(f"[{index}] Rule source : {source_identifier}")
        print(f" Rule correlation : {obfuscator.token('rule', rule_name)}")
        print(f" Resource type : {resource_type}")
        print(f" Resource : {obfuscator.token('resource', resource_id)}")
        print(f" Compliance : {compliance}")
        print(f" Annotation/reason : {obfuscator.sanitize_text(annotation)}")
        if invoked:
            print(f" Rule invoked : {invoked}")
        if recorded:
            print(f" Result recorded : {recorded}")


def strict_verdict(outcomes: Sequence[RuleOutcome], operational_errors: Sequence[str]) -> str:
    if operational_errors or any(outcome.operational_error for outcome in outcomes):
        return "ERROR"
    if any(outcome.compliance == "NON_COMPLIANT" for outcome in outcomes):
        return "FAIL"
    if not outcomes or any(outcome.compliance not in {"COMPLIANT", "NON_COMPLIANT"} for outcome in outcomes):
        return "INDETERMINATE"
    return "PASS"


def exit_code_for(verdict: str) -> int:
    return {
        "PASS": EXIT_PASS,
        "FAIL": EXIT_FAIL,
        "INDETERMINATE": EXIT_INDETERMINATE,
        "ERROR": EXIT_ERROR,
    }[verdict]


def print_final_verdict(verdict: str, outcomes: Sequence[RuleOutcome], diagnostics: Sequence[str]) -> None:
    print("\n" + "=" * 100)
    print(f"{OUTPUT_MARKER} — FINAL VERDICT: {verdict}")
    print("=" * 100)

    counts: Dict[str, int] = {}
    for outcome in outcomes:
        counts[outcome.compliance] = counts.get(outcome.compliance, 0) + 1

    if counts:
        print("Rule status counts : " + ", ".join(f"{key}={value}" for key, value in sorted(counts.items())))

    if verdict == "PASS":
        print("Reason : Every evaluated target rule is confirmed COMPLIANT and no operational error was detected.")
    elif verdict == "FAIL":
        print("Reason : At least one target rule is confirmed NON_COMPLIANT.")
    elif verdict == "INDETERMINATE":
        print("Reason : AWS Config did not provide sufficient evidence to confirm all target rules as compliant or non-compliant.")
    else:
        print("Reason : An AWS/API/rule-execution condition prevented C-Test from obtaining a reliable compliance determination.")

    if diagnostics:
        print("Forensic diagnostics:")
        for item in diagnostics:
            print(f" - {item}")

    print(f"Process exit code : {exit_code_for(verdict)}")


# ------------------------------------------------------------------------------
# Mode implementations
# ------------------------------------------------------------------------------

def run_pack(config_client, pack_name: str, args: argparse.Namespace, obfuscator: Obfuscator) -> int:
    print("\n[STEP 1] Discovering conformance-pack constituents from AWS Config...")
    try:
        summaries = get_pack_rule_summaries(config_client, pack_name)
    except (ClientError, BotoCoreError) as exc:
        diagnostic = f"Pack discovery failed: {aws_error_text(exc, obfuscator)}"
        print_final_verdict("ERROR", [], [diagnostic])
        return EXIT_ERROR

    if not summaries:
        diagnostic = "AWS Config returned no constituent rule compliance records for the requested conformance pack."
        print_final_verdict("INDETERMINATE", [], [diagnostic])
        return EXIT_INDETERMINATE

    rule_names = [item["ConfigRuleName"] for item in summaries if item.get("ConfigRuleName")]
    print(f"[+] AWS reports {len(rule_names)} constituent rule(s). No caller-supplied rule list is required.")

    try:
        described = describe_rules(config_client, rule_names)
    except (ClientError, BotoCoreError) as exc:
        diagnostic = f"Unable to describe constituent rules: {aws_error_text(exc, obfuscator)}"
        print_final_verdict("ERROR", [], [diagnostic])
        return EXIT_ERROR

    missing = sorted(set(rule_names) - set(described))
    if missing:
        diagnostics = [
            "AWS listed constituent rule(s) that could not be resolved by DescribeConfigRules: "
            + ", ".join(obfuscator.token("rule", name) for name in missing)
            ]
        print_final_verdict("ERROR", [], diagnostics)
        return EXIT_ERROR

    non_aws_managed = [
    name for name, rule in described.items() if rule.get("Source", {}).get("Owner") != "AWS"
    ]
    if non_aws_managed:
        diagnostics = [
            "C-Test's current validation contract is AWS-managed Config rules; this pack contains unsupported non-AWS-managed rule(s): "
            + ", ".join(obfuscator.token("rule", name) for name in non_aws_managed)
            ]
        print_final_verdict("ERROR", [], diagnostics)
        return EXIT_ERROR

    print("\n[STEP 2] Triggering on-demand evaluation and polling for fresh completion evidence...")
    ok, statuses, polling_diagnostics = evaluate_rules(
        config_client, rule_names, args.timeout, args.poll_interval, obfuscator
    )

    diagnostics = list(polling_diagnostics)
    diagnostics.extend(platform_diagnostics(described, statuses, obfuscator))
    if not ok or diagnostics:
        # We still retrieve compliance evidence where possible, but do not claim a reliable PASS/FAIL.
        operational_failure = True
    else:
        operational_failure = False

    print("\n[STEP 3] Retrieving fresh rule-level and resource-level compliance evidence...")
    try:
        fresh_summaries = get_pack_rule_summaries(config_client, pack_name)
        resource_results = get_pack_resource_results(config_client, pack_name)
    except (ClientError, BotoCoreError) as exc:
        diagnostics.append(f"Compliance retrieval failed: {aws_error_text(exc, obfuscator)}")
        print_final_verdict("ERROR", [], diagnostics)
        return EXIT_ERROR

    summary_by_name = {item.get("ConfigRuleName"): item for item in fresh_summaries}
    outcomes: List[RuleOutcome] = []

    print("\n" + "=" * 100)
    print("RULE-LEVEL COMPLIANCE SUMMARY")
    print("=" * 100)
    for name in rule_names:
        rule = described[name]
        source_identifier = rule.get("Source", {}).get("SourceIdentifier", "UNKNOWN")
        compliance = summary_by_name.get(name, {}).get("ComplianceType", "INSUFFICIENT_DATA")
        outcomes.append(RuleOutcome(name, source_identifier, compliance))
        print(
            f"{source_identifier:<48} | "
            f"{obfuscator.token('rule', name):<22} | {compliance}"
            )

    print_resource_results(resource_results, described, obfuscator)

    verdict = strict_verdict(outcomes, diagnostics if operational_failure else [])
    print_final_verdict(verdict, outcomes, diagnostics)
    return exit_code_for(verdict)


def run_rule(config_client, rule_name: str, args: argparse.Namespace, obfuscator: Obfuscator) -> int:
    print("\n[STEP 1] Resolving standalone AWS-managed Config rule...")
    try:
        described = describe_rules(config_client, [rule_name])
    except (ClientError, BotoCoreError) as exc:
        diagnostic = f"Rule discovery failed: {aws_error_text(exc, obfuscator)}"
        print_final_verdict("ERROR", [], [diagnostic])
        return EXIT_ERROR

    rule = described.get(rule_name)
    if not rule:
        diagnostic = "The requested Config rule was not found in this account/region."
        print_final_verdict("ERROR", [], [diagnostic])
        return EXIT_ERROR

    source = rule.get("Source", {})
    source_identifier = source.get("SourceIdentifier", "UNKNOWN")
    if source.get("Owner") != "AWS":
        diagnostic = (
            "The requested standalone rule is not AWS-managed. "
            "C-Test standalone mode intentionally accepts AWS-managed Config rules only."
            )
        print_final_verdict("ERROR", [], [diagnostic])
        return EXIT_ERROR

    print(f"[+] Resolved AWS-managed rule source: {source_identifier}")

    print("\n[STEP 2] Triggering on-demand evaluation and polling for fresh completion evidence...")
    ok, statuses, polling_diagnostics = evaluate_rules(
        config_client, [rule_name], args.timeout, args.poll_interval, obfuscator
    )
    diagnostics = list(polling_diagnostics)
    diagnostics.extend(platform_diagnostics(described, statuses, obfuscator))

    print("\n[STEP 3] Retrieving fresh rule and resource compliance evidence...")
    try:
        compliance_response = config_client.describe_compliance_by_config_rule(
            ConfigRuleNames=[rule_name]
        )
        resource_results = get_rule_resource_results(config_client, rule_name)
    except (ClientError, BotoCoreError) as exc:
        diagnostics.append(f"Compliance retrieval failed: {aws_error_text(exc, obfuscator)}")
        print_final_verdict("ERROR", [], diagnostics)
        return EXIT_ERROR

    compliance_items = compliance_response.get("ComplianceByConfigRules", [])
    compliance = "INSUFFICIENT_DATA"
    if compliance_items:
        compliance = compliance_items[0].get("Compliance", {}).get("ComplianceType", "INSUFFICIENT_DATA")

    outcome = RuleOutcome(rule_name, source_identifier, compliance)
    print("\n" + "=" * 100)
    print("RULE-LEVEL COMPLIANCE SUMMARY")
    print("=" * 100)
    print(f"Rule source : {source_identifier}")
    print(f"Rule correlation : {obfuscator.token('rule', rule_name)}")
    print(f"Compliance : {compliance}")

    print_resource_results(resource_results, described, obfuscator)

    if not ok or diagnostics:
        verdict = "ERROR"
    elif compliance == "NON_COMPLIANT":
        verdict = "FAIL"
    elif compliance == "COMPLIANT":
        verdict = "PASS"
    else:
        verdict = "INDETERMINATE"

    print_final_verdict(verdict, [outcome], diagnostics)
    return exit_code_for(verdict)


# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctest.py",
        description=(
        "C-Test: lean AWS Config black-box validation for a conformance pack "
        "or a standalone AWS-managed Config rule."
        ),
        )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    pack_parser = subparsers.add_parser("pack", help="Validate an entire conformance pack.")
    pack_parser.add_argument("target", metavar="PACK_NAME", help="Exact AWS Config conformance pack name.")

    rule_parser = subparsers.add_parser("rule", help="Validate one standalone AWS-managed Config rule.")
    rule_parser.add_argument("target", metavar="RULE_NAME", help="Exact deployed AWS Config rule name.")

    for subparser in (pack_parser, rule_parser):
        subparser.add_argument(
            "--unobfuscated",
            action="store_true",
            help="Explicitly disable secure-by-default output obfuscation and print AWS-returned identifiers/details.",
            )
        subparser.add_argument(
            "--timeout",
            type=float,
            default=DEFAULT_TIMEOUT,
            help=f"Polling timeout in seconds per <=25-rule batch (default: {DEFAULT_TIMEOUT:.0f}).",
            )
        subparser.add_argument(
            "--poll-interval",
            type=float,
            default=DEFAULT_POLL_INTERVAL,
            help=f"Initial polling interval in seconds (default: {DEFAULT_POLL_INTERVAL:.0f}; increases with backoff).",
            )
        subparser.add_argument("--region", help="AWS region override. Otherwise use normal boto3 resolution.")
        subparser.add_argument("--profile", help="AWS shared-config profile name.")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.timeout <= 0 or args.poll_interval <= 0:
        parser.error("--timeout and --poll-interval must both be greater than zero")

    obfuscator = Obfuscator(enabled=not args.unobfuscated)

    try:
        config_client, region = make_config_client(args)
    except (BotoCoreError, ClientError) as exc:
        print(f"{OUTPUT_MARKER} — ERROR creating AWS session: {aws_error_text(exc, obfuscator)}")
        return EXIT_ERROR

    print_header(args.mode, args.target, region, obfuscator)

    try:
        if args.mode == "pack":
            return run_pack(config_client, args.target, args, obfuscator)
        return run_rule(config_client, args.target, args, obfuscator)
    except KeyboardInterrupt:
        print(f"\n{OUTPUT_MARKER} — ERROR: interrupted by operator.")
        return EXIT_ERROR
    except (ClientError, BotoCoreError) as exc:
        print(f"\n{OUTPUT_MARKER} — ERROR: {aws_error_text(exc, obfuscator)}")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
