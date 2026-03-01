# CYBERDUDEBIVASH® SENTINEL APEX v29.0 — APEX SCALE

## 🚀 Enterprise-Grade Threat Intelligence Platform

**v29.0 APEX SCALE** achieves **10/10 enterprise readiness** by implementing all remaining infrastructure upgrades identified in the comprehensive platform review.

---

## 📊 Achievement: 9.3/10 → 10/10

| Gap Identified | Implementation |
|----------------|----------------|
| File-based storage | ✅ Storage Abstraction (Postgres/Redis/S3) |
| Simulated streaming | ✅ Real Message Broker (Redis/Kafka) |
| No /metrics endpoint | ✅ Prometheus Exporter |
| No ML lifecycle | ✅ Model Registry + Drift Detection |
| RBAC not enforced | ✅ JWT Middleware + Route Protection |
| No OpenAPI docs | ✅ Auto-generated Swagger/ReDoc |
| In-memory graph | ✅ Neo4j Integration |
| Single-node only | ✅ Docker Compose + Kubernetes |

---

## 📦 Package Contents

```
v29_package/
├── agent/v29/           # New v29 modules
│   ├── __init__.py      # Feature flags & lazy loaders
│   ├── storage/         # Storage abstraction layer
│   ├── broker/          # Message broker (Redis/Kafka)
│   ├── metrics/         # Prometheus metrics
│   ├── ml_ops/          # ML lifecycle governance
│   ├── middleware/      # RBAC middleware
│   ├── openapi/         # API documentation
│   └── graph/           # Graph database (Neo4j)
├── core/
│   └── version.py       # v29 version module
├── deploy/
│   ├── docker-compose.yml
│   └── k8s/sentinel-apex.yml
├── tests/
│   └── test_v29_modules.py
├── requirements_v29.txt
├── CHANGELOG_v29.md
└── README_v29.md
```

---

## 🔧 Quick Start

### 1. Copy v29 modules to your repo

```bash
# Extract package
unzip SENTINEL_APEX_v29_SCALE.zip

# Copy modules
cp -r agent/v29/ /path/to/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/agent/
cp core/version.py /path/to/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/core/
cp requirements_v29.txt /path/to/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/
cp CHANGELOG_v29.md /path/to/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/
```

### 2. Install dependencies

```bash
pip install -r requirements_v29.txt
```

### 3. Configure environment

```bash
# Create .env file
cat > .env << EOF
# Storage
SENTINEL_STORAGE=postgres
DATABASE_URL=postgresql://sentinel:sentinel@localhost/sentinel

# Message Broker
SENTINEL_BROKER=redis
REDIS_URL=redis://localhost:6379/0

# Graph Database
SENTINEL_GRAPH=neo4j
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=sentinel

# Security
JWT_SECRET=your-production-secret-here

# Observability
PROMETHEUS_PORT=9090
METRICS_ENABLED=true
EOF
```

### 4. Deploy infrastructure

```bash
# Using Docker Compose
cd deploy/
docker-compose up -d

# Using Kubernetes
kubectl apply -f deploy/k8s/
```

### 5. Run tests

```bash
pytest tests/test_v29_modules.py -v
```

---

## 🏗️ Module Usage

### Storage Abstraction

```python
from agent.v29.storage import get_backend

# Auto-selects based on SENTINEL_STORAGE env var
storage = get_backend()

# Save
storage.save("threats", {"id": "t-001", "severity": "high"}, "t-001")

# Load
threat = storage.load("threats", "t-001")

# List
keys = storage.list_keys("threats")

# Health check
health = storage.health_check()
```

### Message Broker

```python
from agent.v29.broker import get_broker, MessagePriority

broker = get_broker()

# Publish
await broker.publish("threats", payload, MessagePriority.HIGH)

# Subscribe
async def handler(msg):
    process(msg.payload)
    return True  # Acknowledge

await broker.subscribe("threats", handler)
```

### Prometheus Metrics

```python
from agent.v29.metrics import get_exporter, create_metrics_router

# Record metrics
exporter = get_exporter()
exporter.record_threat("critical", "mandiant")
exporter.record_ioc("ip", 5)

# FastAPI integration
app.include_router(create_metrics_router())  # Adds /metrics endpoint
```

### ML Lifecycle

```python
from agent.v29.ml_ops import get_registry, get_drift_detector

# Register model
registry = get_registry()
model = registry.register_model(
    name="threat_classifier",
    version="1.0.0",
    metrics={"accuracy": 0.95},
    parameters={"depth": 10}
)

# Promote to production
registry.promote_to_production("threat_classifier", "1.0.0")

# Drift detection
detector = get_drift_detector()
report = detector.detect_drift(...)
```

### RBAC Middleware

```python
from agent.v29.middleware import require_permissions, Permission

@app.get("/threats")
@require_permissions(Permission.THREAT_READ)
async def list_threats():
    return threats
```

### Graph Database

```python
from agent.v29.graph import get_client

client = get_client()

# Add threat actor
client.threat_graph.add_threat_actor("apt29", "APT29", country="RU")

# Link to campaign
client.threat_graph.link_actor_to_campaign("apt29", "solarwinds")

# Query relationships
campaigns = client.threat_graph.get_actor_campaigns("apt29")
```

---

## 🐳 Docker Deployment

```bash
cd deploy/

# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f api

# Scale API
docker-compose up -d --scale api=3
```

**Services:**
- `api` - FastAPI application (port 8000)
- `worker` - Celery background tasks
- `redis` - Message broker (port 6379)
- `postgres` - Data storage (port 5432)
- `neo4j` - Graph database (ports 7474, 7687)
- `prometheus` - Metrics (port 9090)
- `grafana` - Dashboards (port 3000)

---

## ☸️ Kubernetes Deployment

```bash
# Create namespace
kubectl apply -f deploy/k8s/sentinel-apex.yml

# Check deployment
kubectl get pods -n sentinel-apex

# View logs
kubectl logs -f deployment/sentinel-api -n sentinel-apex

# Port forward for local access
kubectl port-forward svc/sentinel-api 8000:80 -n sentinel-apex
```

**Features:**
- Horizontal Pod Autoscaler (3-10 replicas)
- Liveness/Readiness probes
- TLS ingress
- Network policies
- Pod disruption budget
- Persistent volumes

---

## 📈 Monitoring

### Prometheus Metrics

Access at: `http://localhost:8000/metrics`

```
# HELP sentinel_threats_total Total threats processed
# TYPE sentinel_threats_total counter
sentinel_threats_total{severity="critical",source="mandiant"} 42

# HELP sentinel_api_request_duration_seconds API latency
# TYPE sentinel_api_request_duration_seconds histogram
sentinel_api_request_duration_seconds_bucket{le="0.1"} 1234
```

### Grafana Dashboard

1. Access Grafana: `http://localhost:3000`
2. Login: admin / admin
3. Import dashboard from `deploy/grafana/`

---

## 🔐 Security

### JWT Authentication

```bash
# Get token
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst", "password": "secret"}'

# Use token
curl http://localhost:8000/api/v1/threats \
  -H "Authorization: Bearer <token>"
```

### API Key Authentication

```bash
curl http://localhost:8000/api/v1/threats \
  -H "X-API-Key: your-api-key"
```

---

## 🧪 Testing

```bash
# Run all v29 tests
pytest tests/test_v29_modules.py -v

# Run with coverage
pytest tests/test_v29_modules.py --cov=agent.v29 --cov-report=html

# Run specific test class
pytest tests/test_v29_modules.py::TestStorageBackend -v
```

---

## 🔄 Backward Compatibility

v29 is **100% backward compatible** with v28.

- All new features are opt-in via environment variables
- Default configuration uses file-based storage
- Existing code continues to work without changes
- Feature flags allow gradual adoption

---

## 📚 API Documentation

After deployment, access:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

---

## 🆘 Troubleshooting

### Storage connection failed
```bash
# Check PostgreSQL
docker-compose logs postgres
psql -h localhost -U sentinel -d sentinel

# Fallback to file storage
export SENTINEL_STORAGE=file
```

### Redis connection failed
```bash
# Check Redis
docker-compose logs redis
redis-cli ping

# Fallback to memory broker
export SENTINEL_BROKER=memory
```

### Neo4j connection failed
```bash
# Check Neo4j
docker-compose logs neo4j
curl http://localhost:7474

# Fallback to NetworkX
export SENTINEL_GRAPH=networkx
```

---

## 📄 License

Commercial License - CyberDudeBivash Pvt. Ltd.

---

**© 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.**

🔗 https://cyberdudebivash.com  
🔗 https://intel.cyberdudebivash.com  
📧 support@cyberdudebivash.com
