FROM python:3.11-slim-bookworm

# Install base OS tools for execution
RUN apt-get update && apt-get install -y \
    git \
    ripgrep \
    tree \
    jq \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install static analysis tools
RUN pip install --no-cache-dir \
    semgrep \
    bandit \
    detect-secrets

WORKDIR /workspace
CMD ["tail", "-f", "/dev/null"]
