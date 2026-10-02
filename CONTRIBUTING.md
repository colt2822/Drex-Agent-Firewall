# Contributing to Drex Agent Firewall

Thank you for your interest in contributing to Drex Agent Firewall!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/colt2822/Drex-Agent-Firewall.git
   cd Drex-Agent-Firewall
   ```

2. Create a virtual environment and install in editable mode with development dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

3. Run the test suite:
   ```bash
   pytest
   ```

4. Run the benchmark suite:
   ```bash
   drex-firewall benchmark
   ```

## Code Guidelines

- **Typed Everything**: Use Python type annotations throughout. Pydantic models are used for boundary schemas.
- **Fail-Safe Security**: Hard deterministic policies must never be bypassed by probabilistic model outputs.
- **Zero Secret Leakage**: All payloads and arguments must pass through the secret redaction engine before persistence, logging, or transmission.
- **Hermetic Tests**: All filesystem and destructive tests must execute in isolated temporary directories (`tmp_path`). Never mutate the host filesystem.

## Submitting Pull Requests

1. Fork the repo and create your feature branch: `git checkout -b feature/my-feature`
2. Ensure all tests pass: `pytest`
3. Run the benchmark and ensure `FALSE_ALLOW_RATE_FOR_HIGH_IMPACT_ACTIONS` remains `0.0%`: `drex-firewall benchmark`
4. Commit your changes with clear, descriptive commit messages.
5. Push your branch and open a Pull Request.
