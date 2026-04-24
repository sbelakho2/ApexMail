# Helm Chart Deployment

Deploy ApexMail to any Kubernetes cluster using the official Helm chart.

## Prerequisites

- Kubernetes 1.26+
- Helm 3.12+
- A container registry with ApexMail images
- PostgreSQL 15+ (included as subchart or external)
- Redis 7+ (included as subchart or external)

## Quick Install

```bash
# Add any required Bitnami repo (for PostgreSQL/Redis subcharts)
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Install with default values
helm install apexmail ./deploy/helm/apexmail \
  --namespace apexmail --create-namespace \
  --set global.imageRegistry=your-registry.example.com/apexmail
```

## Configuration

All configuration lives in `values.yaml`. Override per environment:

```bash
helm install apexmail ./deploy/helm/apexmail \
  -f values-production.yaml \
  --set ingress.hosts[0].host=mail.yourcompany.com
```

### Required Secrets

Create a Kubernetes Secret before installing:

```bash
kubectl create secret generic apexmail-secrets \
  --from-literal=database-url='postgresql://apexmail:PASSWORD@host:5432/apexmail' \
  --from-literal=redis-password='REDIS_PASSWORD' \
  --from-literal=redis-url='redis://:REDIS_PASSWORD@host:6379/0' \
  --from-literal=tracking-secret-key='YOUR_32_CHAR_SECRET_HERE' \
  -n apexmail
```

For HIPAA deployments, also create the KEK secret:

```bash
kubectl create secret generic apexmail-kek \
  --from-literal=kek_id='kek-1' \
  --from-literal=kek_material='HEX_ENCODED_32_BYTE_KEY' \
  -n apexmail
```

### Key Values

| Value                              | Default        | Description                             |
|------------------------------------|----------------|-----------------------------------------|
| `global.imageRegistry`             | `""`           | Container registry prefix               |
| `global.imagePullPolicy`           | `IfNotPresent` | Image pull policy                       |
| `apiServer.replicaCount`           | 2              | API server replicas                     |
| `trackingService.replicaCount`     | 2              | Tracking service replicas               |
| `mta.replicaCount`                 | 2              | MTA replicas                            |
| `ingress.hosts[0].host`            | `mail.example.com` | Your domain                         |
| `postgresql.enabled`               | `true`         | Deploy PostgreSQL subchart              |
| `redis.enabled`                    | `true`         | Deploy Redis subchart                   |
| `hipaa.enabled`                    | `false`        | Enable HIPAA encryption features        |
| `monitoring.prometheus.enabled`    | `true`         | Enable Prometheus ServiceMonitors       |
| `networkPolicies.enabled`          | `true`         | Deploy network policies                 |

### Using External Databases

For production, use a managed database service:

```yaml
# values-production.yaml
postgresql:
  enabled: false

externalDatabase:
  host: your-rds-instance.amazonaws.com
  port: 5432
  database: apexmail
  user: apexmail
  existingSecret: apexmail-db-credentials
  sslMode: require

redis:
  enabled: false

externalRedis:
  host: your-elasticache.amazonaws.com
  port: 6379
  existingSecret: apexmail-redis-credentials
```

## Architecture

The chart deploys these services:

| Service            | Port  | Purpose                                 |
|--------------------|-------|-----------------------------------------|
| API Server         | 3000  | REST API + web/control-plane SSR        |
| Tracking Service   | 3001  | Open/click tracking, SSE streaming      |
| MTA                | 25/587/465 | SMTP mail transfer                 |
| Worker             | —     | Background job processing               |
| Enterprise         | 3002  | Compliance, encryption, audit           |

## HIPAA Deployment

Enable HIPAA features for healthcare compliance:

```yaml
hipaa:
  enabled: true
  encryption:
    kekSecret: apexmail-kek
    kekSecretIdKey: kek_id
    kekSecretKeyKey: kek_material

enterprise:
  enabled: true
```

This activates:
- AES-256-GCM field-level encryption for PHI columns
- 7-year audit log retention
- Verbose access logging
- KEK/DEK envelope encryption with key rotation support

## Monitoring

With `monitoring.prometheus.enabled: true`, the chart creates ServiceMonitor
resources for Prometheus Operator:

- **API Server** — scraped on the HTTP port at `/metrics`
- **Tracking Service** — scraped on port 9092 at `/metrics`

### Prometheus Metrics

| Metric                                    | Type      | Description                    |
|-------------------------------------------|-----------|--------------------------------|
| `apexmail_http_request_duration_seconds`  | Histogram | API request latency            |
| `apexmail_http_requests_total`            | Counter   | Total API requests             |
| `apexmail_http_requests_in_flight`        | Gauge     | Concurrent requests            |

## Upgrading

```bash
helm upgrade apexmail ./deploy/helm/apexmail \
  -f values-production.yaml \
  --namespace apexmail
```

The chart uses config checksum annotations to trigger rolling updates when
ConfigMaps change, ensuring zero-downtime deployments.

## Uninstalling

```bash
helm uninstall apexmail --namespace apexmail
```

> **Note:** Persistent volumes for PostgreSQL and Redis are NOT deleted
> automatically. Delete the PVCs manually if you want to remove all data.
