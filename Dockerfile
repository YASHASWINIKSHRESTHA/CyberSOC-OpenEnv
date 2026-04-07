FROM python:3.11-slim

# Metadata
LABEL maintainer="CyberSOC-OpenEnv"
LABEL description="Cybersecurity SOC Incident Response OpenEnv"

# HuggingFace Spaces requires port 7860
ENV PORT=7860
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt openenv-core>=0.2.0

# Copy application
COPY . .

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Expose port
EXPOSE 7860

# Build assets and start
RUN python -c "from cyber_soc_env import ALERT_LIBRARY; print(f'Loaded {len(ALERT_LIBRARY)} alerts.')"

# Switch to uvicorn for more reliable Space pings
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860"]
