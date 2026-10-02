# Drex Agent Firewall: Adversarial Red-Team Benchmark Report

## 1. Overview

The **Firewall Red-Team Benchmark** is an adversarial evaluation suite containing **220 distinct scenarios** across 10 security-critical categories.

Unlike baseline validation suites that test expected positive paths or mirror existing deterministic rules, this benchmark evaluates adversarial attempts designed specifically to bypass security filters through obfuscation, encoding, symlink tricks, parser ambiguities, and multi-step composition.

---

## 2. Benchmark Summary Metrics

| Metric | Target | Measured Result | Status |
| :--- | :--- | :--- | :--- |
| **Total Scenarios** | $\ge 200$ | **220** | **PASSED** |
| **Benchmark Accuracy** | $\ge 90.0\%$ | **99.55%** (219 / 220) | **PASSED** |
| **High-Impact Scenarios** | N/A | **136** | **CONFIRMED** |
| **High-Impact False Allows** | $\le 0.0\%$ | **0 (0.0%)** | **PASSED (ZERO LEAKS)** |
| **High-Impact False Allow Rate** | $\le 0.0\%$ | **0.0%** | **PASSED** |
| **False Blocks on Safe Actions** | $\le 2.0\%$ | **0 (0.0%)** | **PASSED** |
| **Escalation Rate** | N/A | **11.82%** (26 / 220) | **RECORDED** |
| **Abstention Rate** | N/A | **0.0%** (0 / 220) | **CONFIRMED** |
| **Average Decision Latency** | $\le 50\text{ ms}$ | **31.97 ms** | **PASSED** |

> [!IMPORTANT]
> **Zero High-Impact False Allows**: Across all 136 high-impact adversarial attacks (destructive wipes, secret exfiltrations, SSRF metadata probes, remote force pushes, and filesystem escapes), the firewall permitted **zero** unauthorized actions.

---

## 3. Results by Category

| Category | Scenarios | Accuracy | High-Impact Count | False Allows | False Blocks |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **A. Shell Obfuscation** | 25 | 100.0% | 20 | 0 | 0 |
| **B. Filesystem Escape** | 25 | 100.0% | 18 | 0 | 0 |
| **C. Secret Exfiltration** | 25 | 100.0% | 18 | 0 | 0 |
| **D. SSRF / Network Bypass** | 25 | 100.0% | 20 | 0 | 0 |
| **E. Git Bypass** | 20 | 100.0% | 11 | 0 | 0 |
| **F. GitHub External Effects** | 20 | 95.0% | 10 | 0 | 0 |
| **G. MCP Protocol Attacks** | 20 | 100.0% | 9 | 0 | 0 |
| **H. Ambiguous High-Impact** | 20 | 100.0% | 11 | 0 | 0 |
| **I. Prompt Injection Payloads** | 20 | 100.0% | 12 | 0 | 0 |
| **J. Multi-Step Composite** | 20 | 100.0% | 7 | 0 | 0 |
| **TOTAL / OVERALL** | **220** | **99.55%** | **136** | **0** | **0** |

---

## 4. Honest Analysis of Imperfect Cases

The current run recorded one exact-label mismatch in the GitHub external-effects category. It recorded zero false blocks and zero high-impact false allows. The report does not treat an exact-label mismatch as proof that an external effect was executed.

---

## 5. Reproducing Red-Team Benchmark

Run the suite directly from the command line:

```bash
# Run standalone benchmark CLI
drex-firewall benchmark --redteam

# Run via Pytest
pytest tests/test_redteam.py -v
```
