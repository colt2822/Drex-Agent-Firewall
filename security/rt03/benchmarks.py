"""Run each deterministic replay benchmark once, sequentially, without a DB."""
import json
from pathlib import Path
from drex_agent_firewall import DrexFirewall
from drex_agent_firewall.schemas.config import FirewallConfig
from drex_agent_firewall.benchmark.runner import BenchmarkRunner
from drex_agent_firewall.benchmark.redteam.runner import RedTeamRunner
from drex_agent_firewall.benchmark.firewall_bypass.runner import BypassBenchmarkRunner
from drex_agent_firewall.benchmark.isolation.runner import IsolationBenchmarkRunner


if __name__ == "__main__":
    config = FirewallConfig.load_default()
    config.provider.type = "replay"
    for name, runner in (("standard", BenchmarkRunner), ("redteam", RedTeamRunner), ("hostile-bypass", BypassBenchmarkRunner), ("isolation", IsolationBenchmarkRunner)):
        fw = DrexFirewall(config=config, enable_audit_db=False)
        report = runner(firewall=fw).run()
        Path(__file__).with_name(f"{name}-benchmark.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
        print(name, {key: value for key, value in report.items() if not isinstance(value, (dict, list))}, flush=True)
