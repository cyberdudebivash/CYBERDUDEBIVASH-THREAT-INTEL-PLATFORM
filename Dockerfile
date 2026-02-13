FROM python:3.12-slim

LABEL maintainer="CyberDudeBivash <iambivash@cyberdudebivash.com>"
LABEL description="CDB-SENTINEL Threat Intelligence Platform"

WORKDIR /app

# Install dependencies first (Docker cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create required directories
RUN mkdir -p data exports

# Run the daily sentinel pipeline
CMD ["python", "-m", "agent.sentinel_blogger"]
