FROM python:3.12-slim

LABEL maintainer="CyberDudeBivash <bivash@cyberdudebivash.com>"
LABEL description="CDB-SENTINEL Threat Intelligence Platform v11.0 APEX ULTRA"
LABEL version="11.0"

WORKDIR /app

# Install dependencies first (Docker cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create required directories
RUN mkdir -p data/stix data/whitepapers exports

# Run the sentinel pipeline
CMD ["python", "-m", "agent.sentinel_blogger"]
