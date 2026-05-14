# Service Mesh & mTLS Architecture

**INF-23/INF-24:** Service mesh documentation and production-ready mTLS configuration.

## Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [mTLS Configuration](#mtls-configuration)
- [Service Mesh Components](#service-mesh-components)
- [Traffic Flow](#traffic-flow)
- [Security Policies](#security-policies)
- [Monitoring](#monitoring)
- [Operational Procedures](#operational-procedures)
- [Helm Configuration](#helm-configuration)
- [Troubleshooting](#troubleshooting)

---

## Overview

ApexMail uses a **service mesh** architecture to secure, observe, and manage inter-service communication. The mesh provides:

- **mTLS (mutual TLS):** Encrypts and authenticates all inter-service traffic
- **Traffic management:** Fine-grained routing, retries, timeouts, circuit breaking
- **Observability:** Distributed tracing, metrics collection, access logs
- **Security:** Authorization policies, rate limiting at mesh level

The mesh is implemented using **Linkerd** (or Istio, depending on deployment) with a **SPIRE**-based identity system for certificate issuance and rotation.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Service Mesh                            │
│                                                              │
│  ┌──────────┐   mTLS   ┌──────────┐   mTLS   ┌──────────┐  │
│  │ API      │◄────────►│  MTA     │◄────────►│  Worker   │  │
│  │ Server   │          │  Service │          │  Service  │  │
│  └────┬─────┘          └──────────┘          └──────────┘  │
│       │                                                     │
│       │ mTLS             ┌──────────┐                       │
│       └─────────────────►│ Tracking │                       │
│                          │ Service  │                       │
│                          └──────────┘                       │
│                                                              │
│  ┌──────────┐   mTLS   ┌──────────┐                         │
│  │ Postgres │◄────────►│  Redis   │                         │
│  │ (sidecar)│          │ (sidecar)│                         │
│  └──────────┘          └──────────┘                         │
└─────────────────────────────────────────────────────────────┘
```

### Identity Model

Each service pod receives a **SPIRE-issued SPIFFE ID**:
- `spiffe://apexmail.ee/ns/apexmail/sa/api-server`
- `spiffe://apexmail.ee/ns/apexmail/sa/mta-service`
- `spiffe://apexmail.ee/ns/apexmail/sa/worker-service`
- `spiffe://apexmail.ee/ns/apexmail/sa/tracking-service`
- `spiffe://apexmail.ee/ns/apexmail/sa/enterprise-service`

These identities are used for:
- mTLS certificate issuance
- Authorization policy enforcement
- Audit logging of inter-service calls

---

## mTLS Configuration

### Certificate Rotation

mTLS certificates are short-lived (24 hours) and automatically rotated by SPIRE:

```yaml
# SPIRE Agent configuration (sidecar container)
spire-agent:
  trust_domain: apexmail.ee
  certificate_ttl: 24h
  renewal_window: 6h
```

### Enforcement Mode

| Mode | Description | Recommendation |
|------|-------------|----------------|
| `permissive` | mTLS attempted but not required | Migration phase only |
| `permissive-mutual` | mTLS accepted but not enforced | Staging/testing |
| **`strict`** | **mTLS required and verified** | **Production (default)** |
| `disable` | No mTLS | Development only |

### Cipher Suites

```yaml
mtls:
  cipher_suites:
    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  min_tls_version: "1.3"
```

---

## Service Mesh Components

### Sidecar Proxy

Every pod in the mesh runs a sidecar proxy (Linkerd2-proxy or Envoy):

| Resource | Request | Limit |
|----------|---------|-------|
| CPU | 50m | 200m |
| Memory | 64Mi | 256Mi |

### Control Plane

| Component | Replicas | Description |
|-----------|----------|-------------|
| `spire-server` | 2 | SPIFFE identity management, CA |
| `spire-agent` | Per-node | Workload attestation, SVID delivery |
| `linkerd-controller` | 2 | Service mesh control plane |
| `linkerd-identity` | 2 | mTLS identity controller |
| `linkerd-proxy-injector` | 2 | Automatic sidecar injection |
| `linkerd-tap` | 1 | Traffic inspection (debugging) |

---

## Traffic Flow

### Ingress to Service

```
Internet → nginx Ingress (TLS termination) → API Server (mTLS)
```

- External TLS terminates at nginx ingress
- Traffic from ingress to service uses mTLS
- nginx has a service mesh sidecar

### Service to Service

```
API Server (mTLS) → MTA Service (mTLS)
API Server (mTLS) → Worker Service (mTLS)
API Server (mTLS) → Tracking Service (mTLS)
API Server (mTLS) → Enterprise Service (mTLS)
```

All inter-service traffic:
- Encrypted with TLS 1.3
- Authenticated via SPIFFE identities
- Routed through local sidecar proxies
- Metrics exported to Prometheus

### Service to Data Store

```
API Server (mTLS) → PostgreSQL
API Server (mTLS) → Redis
```

- Data store connections use sidecar TCP proxy with mTLS
- PostgreSQL: mTLS-authenticated via `sslmode=verify-full`
- Redis: mTLS-authenticated with Redis ACLs

---

## Security Policies

### Authorization Policy (Strict)

```yaml
apiVersion: v1
kind: NetworkPolicy
metadata:
  name: apexmail-mtls-strict
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: apexmail
      ports:
        - protocol: TCP
          port: 443  # mTLS port
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: apexmail
```

### Service-Level Authorization

| Source | Target | Permitted Operations |
|--------|--------|---------------------|
| api-server | mta-service | Send email, check status |
| api-server | worker-service | Queue jobs, check status |
| api-server | tracking-service | Create events, read analytics |
| api-server | postgres | All CRUD |
| api-server | redis | Cache operations, rate limiting |
| mta-service | postgres | Read queue, write delivery log |
| worker-service | postgres | Read/write jobs |
| enterprise-service | postgres | Enterprise tenant CRUD |

---

## Monitoring

### Metrics

The mesh exports the following metrics for each service:

| Metric | Description | Labels |
|--------|-------------|--------|
| `apexmail_mesh_request_total` | Request count | source, target, route, status_code |
| `apexmail_mesh_request_duration_ms` | Request latency | source, target, percentile |
| `apexmail_mesh_tls_handshake_errors` | mTLS errors | source, target |
| `apexmail_mesh_certificate_expiry_seconds` | Cert TTL remaining | identity, service |
| `apexmail_mesh_circuit_breaker_state` | Circuit breaker state | service, destination |

### Grafana Dashboard

Import [`grafana-dashboards/service-mesh.json`](../../deploy/grafana/dashboards/service-mesh.json) for a pre-built service mesh dashboard showing:
- Request volume by service pair
- Latency heatmap
- TLS handshake error rate
- Certificate expiry timeline
- Circuit breaker status

### Alerting Rules

```yaml
# Prometheus alert rule for mTLS failures
- alert: MeshTlsHandshakeFailure
  expr: rate(apexmail_mesh_tls_handshake_errors_total[5m]) > 0
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "mTLS handshake failures between {{ $labels.source }} and {{ $labels.target }}"
```

---

## Operational Procedures

### Adding a New Service to the Mesh

1. **Label the namespace** for automatic sidecar injection:
   ```bash
   kubectl label namespace apexmail linkerd.io/inject=enabled
   ```

2. **Annotate the deployment** with SPIFFE identity:
   ```bash
   kubectl annotate deployment/<service> -n apexmail \
     spire-managed-identity=true
   ```

3. **Define authorization policy** for the new service:
   ```yaml
   apiVersion: policy.linkerd.io/v1beta1
   kind: AuthorizationPolicy
   metadata:
     name: <service>-authz
     namespace: apexmail
   spec:
     target:
       group: core
       kind: Service
       name: <service>
     requiredAuthentication:
       mTLS: {}
   ```

4. **Verify** that traffic flows correctly with mTLS:
   ```bash
   linkerd viz tap deployment/<service> -n apexmail | grep tls
   ```

### Debugging mTLS Issues

1. **Check certificate status:**
   ```bash
   kubectl exec -n apexmail deploy/api-server -c linkerd-proxy -- \
     curl -s http://localhost:4191/metrics | grep tls
   ```

2. **Inspect SPIRE agent registration entries:**
   ```bash
   kubectl exec -n spire deploy/spire-server -- \
     ./bin/spire-server entry show
   ```

3. **Verify mTLS between two pods:**
   ```bash
   linkerd viz edges deployment -n apexmail
   # Shows which services communicate with mTLS
   ```

4. **Bypass sidecar for debugging** (temporary):
   ```bash
   kubectl annotate deployment/api-server -n apexmail \
     linkerd.io/inject=disabled
   kubectl rollout restart deployment/api-server -n apexmail
   ```

### Rotating SPIRE CA Certificate

1. **Generate new CA:**
   ```bash
   kubectl exec -n spire deploy/spire-server -- \
     ./bin/spire-server bundle set --format=spiffe \
     --id spiffe://apexmail.ee
   ```

2. **Verify new certificates are issued:**
   ```bash
   kubectl exec -n spire deploy/spire-server -- \
     ./bin/spire-server token generate -spiffeID spiffe://apexmail.ee/ns/apexmail/sa/api-server
   ```

3. **Monitor for certificate renewal** across all pods (expected within 24 hours).

---

## Helm Configuration

The service mesh is configured in [`values.yaml`](../../deploy/helm/apexmail/values.yaml) under the `serviceMesh` section:

```yaml
serviceMesh:
  enabled: true
  provider: linkerd
  mtls: strict
  spire:
    enabled: true
    trustDomain: apexmail.ee
  sidecar:
    resources:
      requests:
        cpu: 50m
        memory: 64Mi
      limits:
        cpu: 200m
        memory: 256Mi
  authorization:
    defaultAction: deny
  monitoring:
    metrics: true
    tracing: true
    accessLogs: true
```

---

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| `connection refused` on service port | Sidecar not injected | Check annotation: `kubectl describe pod <pod> \| grep linkerd` |
| `tls: bad certificate` | Expired or mismatched identity | Check SPIRE agent logs: `kubectl logs <pod> -c spire-agent` |
| High latency on service calls | Sidecar resource contention | Increase sidecar resource limits |
| `403 Forbidden` on service calls | Authorization policy | Check AuthorizationPolicy resources |
| Certificate renewal failures | SPIRE server unavailable | Check: `kubectl get pods -n spire` |

## Related

- [Helm chart values (serviceMesh)](../../deploy/helm/apexmail/values.yaml)
- [Certificate expiry alerting](../../deploy/monitoring/alerts/certificate-expiry.yml)
- [Secret Rotation Runbook](../secret-rotation.md)
- [Network Partition Runbook](./network-partition.md)
- [Linkerd documentation](https://linkerd.io/docs/)
- [SPIRE documentation](https://spiffe.io/docs/)
