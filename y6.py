import json
import sys
import time
import boto3
from botocore.exceptions import ClientError

# ==============================================================================
# CONFIGURATION
# ==============================================================================
CONFORMANCE_PACK_NAME = "efs-security-conformance-pack"

# Example Input: The exact list of constituent rules you want to validate
CONSTITUENT_RULES_JSON = """
[
    "efs-in-backup-plan",
    "efs-filesystem-ct-encrypted",
    "efs-access-point-enforce-root-directory",
    "efs-mount-target-public-accessible",
    "efs-resources-protected-by-backup-plan",
    "efs-automatic-backups-enabled",
    "efs-access-point-enforce-user-identity",
    "efs-encrypted-check"
]
"""

def validate_conformance_pack(pack_name, short_rules_list):
    config_client = boto3.client("config")
    
    print("=" * 80)
    print(f"STEP 1: RESOLVING & REFRESHING RULES FOR PACK: {pack_name}")
    print("=" * 80)
    
    try:
        # Fetch all live rules from AWS Config to map system-generated names
        paginator = config_client.get_paginator("describe_config_rules")
        all_live_rules = []
        for page in paginator.paginate():
            all_live_rules.extend(page.get("ConfigRules", []))
    except ClientError as e:
        print(f"API Error fetching system rules: {e}")
        sys.exit(1)

    # Filter rules that match BOTH the pack name prefix and your input JSON array
    target_resolved_names = []
    for rule in all_live_rules:
        rule_name = rule["ConfigRuleName"]
        # Conformance pack rules contain the pack name as a prefix
        if pack_name in rule_name:
            for short_name in short_rules_list:
                if short_name in rule_name:
                    target_resolved_names.append(rule_name)
                    break

    if not target_resolved_names:
        print(f"[-] No matching rules found for Pack: '{pack_name}' based on the input array.")
        return

    print(f"[+] Found {len(target_resolved_names)} active system rules to re-evaluate.")
    
    # Trigger asynchronous compliance evaluations
    try:
        config_client.start_config_rules_evaluation(
            ConfigRuleNames=target_resolved_names
        )
        print("[+] Refresh signal transmitted successfully.")
    except ClientError as e:
        print(f"[-] Failed to trigger refresh: {e}")

    print("\n--> Pausing 10 seconds for compliance calculation pipeline...")
    time.sleep(10)

    print("=" * 80)
    print("STEP 2: RUNTIME DIAGNOSTICS & SYSTEM FAILURES")
    print("=" * 80)
    
    # Check for platform-level execution errors
    has_errors = False
    for rule in all_live_rules:
        if rule["ConfigRuleName"] in target_resolved_names:
            error_msg = rule.get("LastErrorMessage")
            state = rule.get("ConfigRuleState")
            if error_msg or state != "ACTIVE":
                has_errors = True
                print(f" CRITICAL: Rule [{rule['ConfigRuleName']}] is in state [{state}].")
                print(f" Reason: {error_msg}\n")
    
    if not has_errors:
        print("[+] Diagnostics Clear: All constituent rules executed without platform errors.")

    print("\n" + "=" * 80)
    print("STEP 3: SANITIZED RESOURCE COMPLIANCE SUMMARY")
    print("=" * 80)
    print(f"{'RESOURCE TYPE':<30} | {'RESOURCE ID':<30} | {'COMPLIANCE STATUS'}")
    print("-" * 80)

    # Collect compliance results specifically for this Conformance Pack
    try:
        pack_paginator = config_client.get_paginator("describe_conformance_pack_compliance_details")
        for page in pack_paginator.paginate(ConformancePackName=pack_name):
            results = page.get("ConformancePackRuleEvaluationResults", [])
            for result in results:
                qualifier = result["EvaluationResultIdentifier"]["EvaluationResultQualifier"]
                
                # Sanitize and extract structural elements
                res_type = qualifier.get("ResourceType", "N/A")
                res_id = qualifier.get("ResourceId", "N/A")
                compliance = result.get("ComplianceType", "N/A")
                
                print(f"{res_type:<30} | {res_id:<30} | {compliance}")
    except ClientError as e:
        print(f"[-] Error retrieving pack details: {e}")

if __name__ == "__main__":
    # Parse the incoming constituent rule array
    try:
        constituent_rules = json.loads(CONSTITUENT_RULES_JSON)
    except json.JSONDecodeError:
        print("Error: Input rule string is not a valid JSON array.")
        sys.exit(1)

    validate_conformance_pack(CONFORMANCE_PACK_NAME, constituent_rules)
