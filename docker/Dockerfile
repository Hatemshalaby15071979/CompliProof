FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project metadata and source (before pip install so the wheel build
# can read pyproject.toml, README.md, and the src/ package).
COPY pyproject.toml .
COPY README.md .
COPY requirements.lock.txt .
COPY src/ ./src/
COPY dashboard/ ./dashboard/

# Build and install the wheel rather than using an editable source-tree install.
RUN pip install --no-cache-dir setuptools==78.1.1 wheel==0.46.3 -r requirements.lock.txt \
    && pip install --no-cache-dir --no-build-isolation --no-deps .

# Create workspace directories and give the non-root user ownership
RUN mkdir -p /app/workspace /app/workspace/reconciliations /app/workspace/reports /app/workspace/kb \
    && groupadd -r compliproof && useradd -r -g compliproof compliproof \
    && chown -R compliproof:compliproof /app/workspace

# Create a non-root user and switch to it
USER compliproof

# Set environment
ENV PYTHONUNBUFFERED=1
ENV COMPLIPROOF_WORKSPACE=/app/workspace
ENV COMPLIPROOF_SECURE_COOKIES=1

# Expose port
EXPOSE 8200

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8200/api/healthz', timeout=5)" || exit 1

# Listen on the container interface; publish only to host loopback.
CMD ["python", "-m", "compliproof.server", "--host", "0.0.0.0", "--port", "8200"]
