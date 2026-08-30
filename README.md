# AWS Compliance Collector

Utilities for validating AWS Config conformance-pack and managed-rule compliance behavior.

## Python File Summary

### `python/`

#### `python/ctest.py`

C-Test is a command-line, black-box validation utility for AWS Config conformance packs and standalone AWS-managed Config rules. It discovers deployed rules, triggers new evaluations in AWS-supported batches, polls for fresh completion evidence, collects rule-level and resource-level compliance results, distinguishes PASS, FAIL, INDETERMINATE, and ERROR outcomes, and provides operational diagnostics. Sensitive AWS identifiers are obfuscated by default, with an explicit command-line option for unobfuscated diagnostic output.

#### `python/sleeper.py`

This earlier conformance-pack validation utility targets a configured EFS security conformance pack and a hard-coded list of constituent rules. It discovers matching deployed AWS Config rules, starts their reevaluation, waits a fixed 10 seconds, reports rule execution errors, and prints resource-level compliance results. Unlike `ctest.py`, it is pack-specific, uses fixed configuration values and a fixed sleep interval, and does not provide bounded polling, formal verdicts, standalone-rule operation, or default output obfuscation.

## Usage

### Prerequisites

- Python 3
- `boto3` and `botocore`
- AWS credentials with permission to read AWS Config information and start Config-rule evaluations
- An AWS region supplied through the normal AWS configuration, an environment variable, or the `--region` option

Install the required AWS SDK:

```bash
python3 -m pip install boto3
```

### C-Test: conformance-pack mode

Validate every AWS-managed Config rule belonging to a deployed conformance pack:

```bash
python3 python/ctest.py pack PACK_NAME
```

Example:

```bash
python3 python/ctest.py pack efs-security-conformance-pack
```

### C-Test: standalone-rule mode

Validate one deployed standalone AWS-managed Config rule:

```bash
python3 python/ctest.py rule RULE_NAME
```

Example:

```bash
python3 python/ctest.py rule efs-encrypted-check
```

### C-Test options

The following options can be placed after the pack or rule name:

```text
--region REGION
--profile PROFILE
--timeout SECONDS
--poll-interval SECONDS
--unobfuscated
```

Example using an AWS profile and region:

```bash
python3 python/ctest.py pack efs-security-conformance-pack \
  --profile my-aws-profile \
  --region us-east-1
```

Example with custom polling settings:

```bash
python3 python/ctest.py pack efs-security-conformance-pack \
  --timeout 600 \
  --poll-interval 10
```

Output obfuscation is enabled by default. Disable it only when full AWS identifiers and diagnostic details are appropriate:

```bash
python3 python/ctest.py rule efs-encrypted-check --unobfuscated
```

Display command-line help:

```bash
python3 python/ctest.py --help
python3 python/ctest.py pack --help
python3 python/ctest.py rule --help
```

### C-Test exit codes

| Exit code | Verdict | Meaning |
|---:|---|---|
| `0` | PASS | All evaluated target rules are confirmed compliant. |
| `2` | FAIL | At least one target rule is confirmed non-compliant. |
| `3` | INDETERMINATE | AWS Config did not provide enough evidence for a final determination. |
| `4` | ERROR | An AWS, API, evaluation, or operational error prevented a reliable result. |

### Sleeper

Before running `sleeper.py`, edit these constants inside the file:

- `CONFORMANCE_PACK_NAME`
- `CONSTITUENT_RULES_JSON`

Then run:

```bash
python3 python/sleeper.py
```

The script uses the normal Boto3 credential and region resolution process. It has no command-line arguments and waits a fixed 10 seconds after requesting reevaluation.
