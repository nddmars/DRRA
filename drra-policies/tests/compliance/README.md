# Compliance Testing

Automated validation that policies work as intended and don't introduce regressions.

## Test Categories

### 1. Sigma Rule Testing
Validates detection rules against real and simulated ransomware behavior.

**Tests** (`test_sigma_rules.py`):
- ✅ Rule triggers on mass file modification payload
- ✅ Rule triggers on entropy spike (>0.85)
- ✅ Rule triggers on VSS abuse command
- ✅ Rule does NOT trigger on normal file operations
- ✅ Detection latency < 60 seconds
- ✅ False positive rate < 2%

### 2. OPA Policy Testing
Validates that policies correctly allow/deny decisions.

**Tests** (`test_opa_policies.py`):
- ✅ Isolation allowed for user process, denied for system process
- ✅ Recovery allowed from pre-incident snapshot, denied from post-incident
- ✅ Denial reasons logged for audit trail
- ✅ Object Lock enabled before deletion attempts
- ✅ High-risk operations require approval flag

### 3. Semgrep Rule Testing
Validates that secure coding rules catch violations without false positives.

**Tests** (`test_semgrep_rules.py`):
- ✅ Detects unlogged file operations
- ✅ Detects hardcoded credentials
- ✅ Detects weak cryptography
- ✅ Detects unsafe path manipulation
- ✅ Allows legitimate code patterns

### 4. Integration Testing
End-to-end validation of policies in context.

**Tests** (`test_integration.py`):
- ✅ Sigma rule fires → OPA isolation decision → Semgrep logs operation
- ✅ Recovery snapshot validated by OPA → Semgrep enforces integrity checks
- ✅ Immutability policies prevent log tampering

## Running Tests

### Run All Compliance Tests
```bash
pytest tests/compliance/ -v
```

### Run Specific Test Suite
```bash
# Sigma rule testing
pytest tests/compliance/test_sigma_rules.py -v

# OPA policy testing  
pytest tests/compliance/test_opa_policies.py -v

# Semgrep rule testing
pytest tests/compliance/test_semgrep_rules.py -v

# Integration tests
pytest tests/compliance/test_integration.py -v
```

### Generate Coverage Report
```bash
pytest tests/compliance/ --cov=drra_policies --cov-report=html
```

## CI/CD Integration

Automatic execution on:
- ✅ Pull requests (policies must pass before merge)
- ✅ Commits to main (ensure no regressions)
- ✅ Policy updates (validate new rules)
- ✅ Monthly (regression test against latest Forge payloads)

**Build Failure Triggers**:
```
IF sigma_false_positive_rate > 2% THEN FAIL
IF opa_policy_denial_reason_missing THEN FAIL
IF semgrep_rule_matches_zero THEN FAIL
IF integration_test_latency > 60s THEN FAIL
```

## Test Data

### Sample Incident Files
Located in `tests/fixtures/`:
- `mass_modification_payload.json` – 10K file modification events
- `entropy_spike_payload.json` – Encrypted file signatures
- `vss_abuse_commands.json` – Shadow copy deletion attempts
- `lateral_movement_logs.json` – Kerberos abuse patterns

### Mock Objects
- `MockMinIO` – Simulates immutable object storage
- `MockSHIELD` – Simulates isolation requests
- `MockSentinel` – Simulates detection events

## Contributing Tests

1. Create test case in appropriate `test_*.py` file
2. Use fixtures for test data
3. Document expected behavior
4. Ensure test is repeatable
5. Get code review before merge

---

**Next**: Run baseline compliance tests
