"""Example demonstrating DrexFirewall Python SDK usage."""

from drex_agent_firewall import DrexFirewall, OutcomeType

# 1. Initialize firewall (runs in replay mode without credentials)
fw = DrexFirewall()

# 2. Evaluate proposed action
decision = fw.evaluate(
    tool="shell",
    operation="execute",
    arguments={"command": "git status"},
    context={"cwd": "/workspace"},
)

print(f"Action: git status")
print(f"Decision: {decision.decision.value} (Allowed: {decision.allowed})")
print(f"Reason: {decision.reason}")
if decision.drex_evaluation:
    print(f"Confidence: {decision.drex_evaluation.confidence * 100:.1f}%")
    print(f"Risk Class: {decision.drex_evaluation.risk.value}")

# 3. Guarded shell execution
if decision.allowed:
    result = fw.execute_shell("git status")
    print("\nCommand Output:")
    print(result.stdout)

# 4. Attempting a dangerous action
blocked_decision = fw.evaluate(
    tool="shell",
    operation="execute",
    arguments={"command": "rm -rf /"},
)

print(f"\nAction: rm -rf /")
print(f"Decision: {blocked_decision.decision.value} (Allowed: {blocked_decision.allowed})")
print(f"Reason: {blocked_decision.reason}")
print(f"Hard Rule Triggered: {blocked_decision.hard_policy_triggered}")

# 5. Attaching calibration outcome feedback
fw.record_outcome(
    action_id=blocked_decision.action_id,
    outcome=OutcomeType.EXECUTED_SUCCESSFULLY,
    notes="Demonstrated hard rule block on rm -rf /",
)
