FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git nodejs npm gcc bubblewrap && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY pyproject.toml README.md LICENSE requirements.lock ./
COPY src ./src
RUN python -m pip install --no-cache-dir -r requirements.lock && python -m pip install --no-cache-dir --no-deps . && mkdir -p /home/agent /workspace && rm -rf /build
WORKDIR /workspace
CMD ["drex-firewall", "--help"]
