# Semgrep Rules - Secure Coding & Resilience Patterns

Catch security issues and enforce resilience patterns in Forge, Vigil, and Shield code during development.

## Rule Categories

### 1. Logging Enforcement
Ensure all security-critical operations are logged to immutable storage.

**Rules**:
- `logging_no_unlogged_file_operations.py` – Detects file modifications without logging
- `logging_no_unlogged_encryption.py` – Catches encryption without audit trail
- `logging_no_unlogged_isolation.py` – VLAN/process kill without log entry
- `logging_no_unlogged_recovery.py` – Data restoration without forensic record

**Enforcement**: All operations in Shield must log to MinIO before execution.

### 2. Cryptography Security
Prevent weak cipher usage, random number generation issues, key management failures.

**Rules**:
- `crypto_no_weak_ciphers.py` – Detects DES, MD5, SHA1 usage
- `crypto_no_insecure_randomness.py` – Catches `random.randint()` for security contexts
- `crypto_fixed_seeds.py` – Prevents seed-based PRNG compromise
- `crypto_key_in_code.py` – Detects hardcoded API keys, credentials

**Enforcement**: Vigil ML models must use strong hashing for entropy calculations.

### 3. Input Validation
Prevent injection attacks and path traversal in Forge/Vigil.

**Rules**:
- `validation_sql_injection.py` – Detects unsafe SQL concatenation
- `validation_path_traversal.py` – Catches unsafe file path manipulation
- `validation_command_injection.py` – Prevents shell command interpolation
- `validation_regex_dos.py` – Detects potential ReDoS vulnerabilities

**Enforcement**: All user inputs to honeypot generation must be validated.

### 4. Resilience Patterns
Enforce defensive coding to prevent system compromise during incident response.

**Rules**:
- `resilience_error_handling.py` – Recovery must catch exceptions gracefully
- `resilience_timeout_enforcement.py` – Isolation must have timeouts (prevent hanging)
- `resilience_resource_limits.py` – Recovery threads must be bounded (prevent DoS)
- `resilience_immutability_checks.py` – Before deletion, verify Object Lock is active

**Enforcement**: Shield operations cannot silently fail.

## Usage

### Scan Repository
```bash
semgrep --config=drra-policies/semgrep/ backend/ vigil/ shield/
```

### Add to Pre-commit
```yaml
# .pre-commit-config.yaml
- repo: https://github.com/returntocorp/semgrep
  rev: v1.45.0
  hooks:
    - id: semgrep
      args: ['--config=drra-policies/semgrep/', '--error']
```

### Integrate with CI/CD
```bash
# In GitHub Actions
- uses: returntocorp/semgrep-action@v1
  with:
    config: drra-policies/semgrep/
    generateSarif: true
```

## Testing Rules

```bash
pytest tests/compliance/test_semgrep_rules.py
```

Each rule must:
- ✅ Detect real violations in test code
- ✅ Not over-match on false positives
- ✅ Have clear remediation guidance
- ✅ Reference OWASP/CWE standards

## Contributing New Rules

1. Create `.yml` rule file with pattern
2. Write test cases (positive and negative)
3. Document rationale and false positive mitigation
4. Get security team review
5. Merge to main branch

---

**Example Rule Structure** (see `logging_no_unlogged_file_operations.py` for template)
