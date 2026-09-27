FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then GITLEAKS_ARCH="x64"; \
    elif [ "$ARCH" = "arm64" ]; then GITLEAKS_ARCH="arm64"; \
    else GITLEAKS_ARCH="x64"; fi && \
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v8.24.0/gitleaks_8.24.0_linux_${GITLEAKS_ARCH}.tar.gz" -o /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks && \
    rm -f /tmp/gitleaks.tar.gz

COPY pyproject.toml /app/
COPY repoguard /app/repoguard
COPY reports /app/reports
COPY testbeds /app/testbeds

RUN pip install --no-cache-dir -e ".[dev]"

WORKDIR /workspace

ENTRYPOINT ["python", "-m", "repoguard"]
CMD ["scan", "."]
