# Network Partition Runbook

**Severity:** SEV1–SEV2 (host cut off from the internet, or internal Docker
network segmentation between services)

> **Reality note (2026-09-05):** earlier versions of this runbook described
> cross-region partitions between Finland and Germany over WireGuard with
> Kubernetes tooling. None of that exists — production is a **single Hetzner
> host (Finland)** running Docker Compose, so a "network partition" here means
> either (a) the host lost internet connectivity, (b) an internal Docker
> network between compose services broke, or (c) DNS resolution failed. There
> is no region to fail over to; see
> [disaster-recovery.md](../disaster-recovery.md).

## Symptoms

- External probes fail (`make verify` red) while the host itself is up
- Service logs show `connection timeout`, `connection reset by peer`, `i/o timeout` against postgres/redis/clickhouse
- Healthchecks flip unhealthy (`docker compose ps` shows unhealthy while the process runs)
- Mail flow stalls: MTA cannot reach the internet (no MX delivery), or api-server cannot reach postgres

## Initial Diagnosis

All commands run on the deploy host (`/opt/apexmail/src`).

1. **Check host internet connectivity:**
   ```bash
   curl -sf --connect-timeout 5 https://1.1.1.1 > /dev/null && echo egress-ok || echo egress-down
   ping -c 3 1.1.1.1
   ```

2. **Check internal Docker networks:**
   ```bash
   docker network ls
   docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env ps
   # The stack spans dedicated networks (apexmail_backend, apexmail_data_internal,
   # apexmail_backup_egress, monitoring); a service attached to the wrong
   # network after a partial recreate is a classic self-inflicted partition.
   docker inspect <container> --format '{{json .NetworkSettings.Networks}}' | jq 'keys'
   ```

3. **Check service-to-dependency connectivity:**
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env \
     exec api-server sh -c 'wget -q -T 5 -O /dev/null http://postgres:5432 && echo pg-ok'
   docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env \
     exec api-server sh -c 'redis-cli -h redis ping'
   ```

4. **Check DNS resolution** (both external and Docker's internal DNS):
   ```bash
   docker compose ... exec api-server sh -c 'nslookup postgres; nslookup api.apexmail.ee'
   ```

5. **Check the host firewall** (UFW is configured by the bootstrap script):
   ```bash
   ufw status verbose
   iptables -L DOCKER-USER -n -v | head -20
   ```

## Recovery Procedures

### Procedure 1: Internal Partition (service cannot reach a dependency)

1. Identify the partitioned service from healthchecks/logs.
2. Restart it (re-establishes DNS + network attachment):
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env \
     up -d --force-recreate <service>
   ```
3. If a whole internal network vanished or a manual `docker run` interfered,
   recreate the stack (`docker compose ... up -d`); the deploy script aborts
   on conflicting non-compose containers for exactly this reason.
4. Verify with `/health/ready` on the affected service.

### Procedure 2: Host Egress Loss (host online internally, internet down)

1. Confirm the scope: Hetzner status page, `ufw status`, uplink errors
   (`ip -s link show`).
2. If UFW/iptables rules were changed (e.g. a blocked OUTPUT chain), restore
   the bootstrap-script baseline (`deploy/scripts/hetzner-bootstrap.sh`).
3. If it is a Hetzner-side outage: nothing to do but wait; in-host services
   keep running, outbound mail retries on the queue's retry schedule, and
   Let's Encrypt renewal retries later.
4. If egress is down for longer than the mail queue's retry window, expect
   deferred/bounced mail once TTLs expire; watch the queue depth metrics.

### Procedure 3: Host Unreachable Externally (nothing responds)

This is a host outage, not a partition — follow the DR procedure:
[disaster-recovery.md](../disaster-recovery.md) (host rebuild + backup
restore). There is no standby host to fail over to.

## Post-Recovery Verification

```bash
# 1. All services healthy
docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env ps

# 2. Public endpoints
make verify

# 3. Deep dependency health (unversioned path)
curl -sf https://api.apexmail.ee/health/deep | jq '.'

# 4. Mail path: send a test message through the API and confirm it leaves the queue
```

## Prevention

- External probes (the pipeline's verify stage / `make verify`) catch egress loss quickly.
- Keep the compose networks declarative — never attach containers to internal networks by hand.
- Test the host-rebuild drill quarterly
  ([disaster-recovery-testing.md](../disaster-recovery-testing.md)).

## Related

- [Disaster Recovery & Backup Procedures](../disaster-recovery.md)
- [Infrastructure alerting rules](../../../deploy/alerting-rules.yml)
- [Deployment model](../../../deploy/DEPLOYMENT.md)
