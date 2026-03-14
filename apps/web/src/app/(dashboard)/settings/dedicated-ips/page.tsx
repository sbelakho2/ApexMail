'use client';

import * as React from 'react';
import {
  Server,
  Plus,
  X,
  CheckCircle,
} from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogFooter,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import { Alert, AlertTitle, AlertDescription as AlertDesc } from '@/components/ui/alert';
import { cn } from '@/lib/utils';
import { useAPI, useAPIMutation, getCsrfToken, globalMutate, APIError } from '@/hooks/use-api';
import { useUserStore } from '@/stores';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { canManageDedicatedIps, type DedicatedIpPlanLike } from '@/lib/dedicated-ip-access';

// ---------- Constants ----------

const WARMUP_DAYS = 45;
const WARMUP_POLL_INTERVAL_MS = 30_000;

// ---------- Types ----------

interface DedicatedIpResponse {
  id: string;
  ipAddress: string;
  ptrRecord: string | null;
  status: 'pending' | 'provisioning' | 'warming' | 'active' | 'degraded' | 'cooldown' | 'releasing' | 'suspended' | 'disabled' | 'released' | 'retired';
  warmup: {
    startedAt: string | null;
    completedAt: string | null;
    estimatedCompletion: string | null;
    progressPercent: number;
    currentDailyLimit: number | null;
  };
  reputation: {
    score: number;
    blocklisted: boolean;
  };
  stats: {
    emailsSentTotal: number;
    bouncesTotal: number;
    complaintsTotal: number;
  };
  createdAt: string;
  updatedAt: string;
}

interface AllocationResponse {
  included: number;
  active: number;
  addOnAvailable: boolean;
  addOnPriceMonthly: number;
}

interface ListResponse {
  dedicatedIps: DedicatedIpResponse[];
  allocation: AllocationResponse | null;
  pagination: {
    total: number;
    limit: number;
    offset: number;
    hasMore: boolean;
  };
}

// ---------- Status helpers ----------

const RETIRED_STATUSES = new Set(['retired', 'released']);

const statusConfig: Record<string, { label: string; variant: 'default' | 'secondary' | 'destructive' | 'outline' }> = {
  pending:      { label: 'Pending',      variant: 'outline' },
  provisioning: { label: 'Provisioning', variant: 'outline' },
  warming:      { label: 'Warming Up',   variant: 'secondary' },
  active:       { label: 'Active',       variant: 'default' },
  degraded:     { label: 'Degraded',     variant: 'destructive' },
  cooldown:     { label: 'Cooling Down', variant: 'secondary' },
  releasing:    { label: 'Releasing',    variant: 'outline' },
  suspended:    { label: 'Suspended',    variant: 'destructive' },
  disabled:     { label: 'Disabled',     variant: 'destructive' },
  released:     { label: 'Released',     variant: 'outline' },
  retired:      { label: 'Released',     variant: 'outline' },
};

function StatusBadge({ status }: { status: string }) {
  const config = statusConfig[status] ?? statusConfig['pending'];
  return <Badge variant={config.variant}>{config.label}</Badge>;
}

// ---------- Component ----------

export default function DedicatedIpsPage() {
  const router = useRouter();
  const canAccess = useUserStore((s) => s.canAccess);
  const userRole = useUserStore((s) => s.user?.role);
  const [error, setError] = React.useState<string | null>(null);
  const [provisioning, setProvisioning] = React.useState(false);
  const [showProvisionDialog, setShowProvisionDialog] = React.useState(false);
  const [showReleaseDialog, setShowReleaseDialog] = React.useState<string | null>(null);
  const [releasing, setReleasing] = React.useState(false);
  const [successMessage, setSuccessMessage] = React.useState<string | null>(null);
  const [offset, setOffset] = React.useState(0);
  const { data: billing } = useAPI<{ plan?: DedicatedIpPlanLike }>('/api/billing');
  const hasDedicatedIpsAccess = canManageDedicatedIps(userRole, billing?.plan ?? null);

  // Fetch IPs via useAPI (includes credentials + deduping)
  const { data, isLoading: loading, error: fetchError, mutate: revalidate } = useAPI<ListResponse>(
    `/v1/dedicated-ips?limit=20&offset=${offset}`,
  );

  const ips = data?.dedicatedIps ?? [];
  const allocation = data?.allocation ?? null;
  const pagination = data?.pagination ?? null;

  // Map 403 to upgrade prompt
  React.useEffect(() => {
    if (fetchError instanceof APIError && fetchError.status === 403) {
      setError('upgrade');
    } else if (fetchError) {
      setError(fetchError.message);
    }
  }, [fetchError]);

  // Auto-refresh while any IP is warming
  const hasWarmingIp = ips.some((ip) => ip.status === 'warming' || ip.status === 'provisioning');
  React.useEffect(() => {
    if (!hasWarmingIp) return;
    const interval = setInterval(() => {
      void revalidate();
    }, WARMUP_POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [hasWarmingIp, revalidate]);

  // Clear success message after 5s
  React.useEffect(() => {
    if (!successMessage) return;
    const t = setTimeout(() => setSuccessMessage(null), 5000);
    return () => clearTimeout(t);
  }, [successMessage]);

  React.useEffect(() => {
    if (billing && !hasDedicatedIpsAccess) {
      router.replace('/settings/billing?reason=dedicated_ip_unavailable');
    }
  }, [billing, hasDedicatedIpsAccess, router]);

  if (billing && !hasDedicatedIpsAccess) {
    return null;
  }

  // Provision new IP (POST with CSRF)
  async function handleProvision() {
    setProvisioning(true);
    setError(null);
    try {
      const csrfToken = await getCsrfToken();
      if (!csrfToken) throw new Error('Unable to initialize CSRF token');
      const res = await fetch('/v1/dedicated-ips', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
      });
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        throw new Error(body?.error?.message ?? 'Failed to provision IP');
      }
      setShowProvisionDialog(false);
      setSuccessMessage('Dedicated IP provisioned! Warmup will begin automatically.');
      setError(null);
      void revalidate();
      void globalMutate((key) => typeof key === 'string' && key.startsWith('/v1/dedicated-ips'));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Provisioning failed');
    } finally {
      setProvisioning(false);
    }
  }

  // Release IP (DELETE with CSRF)
  async function handleRelease(id: string) {
    setReleasing(true);
    setError(null);
    try {
      const csrfToken = await getCsrfToken();
      if (!csrfToken) throw new Error('Unable to initialize CSRF token');
      const res = await fetch(`/v1/dedicated-ips/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
      });
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        throw new Error(body?.error?.message ?? 'Failed to release IP');
      }
      setShowReleaseDialog(null);
      setSuccessMessage('Dedicated IP released. Billing will be prorated.');
      setError(null);
      void revalidate();
      void globalMutate((key) => typeof key === 'string' && key.startsWith('/v1/dedicated-ips'));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Release failed');
    } finally {
      setReleasing(false);
    }
  }

  // RBAC gate — dedicated-ips requires admin
  if (!canAccess('dedicated-ips')) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Dedicated IPs"
          description="Improve deliverability with your own dedicated sending IPs."
          breadcrumbs={[{ label: 'Settings', href: '/settings' }, { label: 'Dedicated IPs' }]}
        />
        <Card>
          <CardContent className="py-12 text-center">
            <p className="text-muted-foreground">
              You do not have permission to manage dedicated IPs. Contact an admin.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Plan upgrade needed
  if (error === 'upgrade') {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Dedicated IPs"
          description="Improve deliverability with your own dedicated sending IPs."
          breadcrumbs={[{ label: 'Settings', href: '/settings' }, { label: 'Dedicated IPs' }]}
        />
        <Card className="max-w-lg mx-auto text-center">
          <CardContent className="pt-8 pb-8 space-y-4">
            <Server className="h-12 w-12 mx-auto text-surface-400" />
            <CardTitle>Upgrade Required</CardTitle>
            <p className="text-sm text-muted-foreground">
              Dedicated IPs are available on Pro plans and above.
              Upgrade your plan to get dedicated sending IPs with automatic warmup.
            </p>
            <Button asChild>
              <a href="/billing">View Plans</a>
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const activeIps = ips.filter(ip => !RETIRED_STATUSES.has(ip.status));
  const retiredIps = ips.filter(ip => RETIRED_STATUSES.has(ip.status));
  const includedCount = allocation?.included ?? 0;
  const addOnCount = Math.max(0, (allocation?.active ?? 0) - includedCount);
  const addOnPrice = ((allocation?.addOnPriceMonthly ?? 3000) / 100);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dedicated IPs"
        description={`Manage your dedicated sending IP addresses. Each IP goes through a ${WARMUP_DAYS}-day warmup period.`}
        breadcrumbs={[{ label: 'Settings', href: '/settings' }, { label: 'Dedicated IPs' }]}
        actions={
          allocation?.addOnAvailable ? (
            <Button onClick={() => setShowProvisionDialog(true)} disabled={provisioning}>
              <Plus className="h-4 w-4 mr-2" />
              Add Dedicated IP
            </Button>
          ) : null
        }
      />

      <div className="rounded-md border border-border bg-muted/20 px-3 py-2 text-xs text-muted-foreground flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <span>Dedicated IP setup runs over multiple days; return to nearby workflows and come back anytime.</span>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" asChild>
            <Link href="/settings/billing">Back to Billing</Link>
          </Button>
          <Button variant="ghost" size="sm" asChild>
            <Link href="/domains">Back to Domains</Link>
          </Button>
        </div>
      </div>

      {/* Success message */}
      {successMessage && (
        <Alert>
          <CheckCircle className="h-4 w-4" />
          <AlertTitle>Success</AlertTitle>
          <AlertDesc>{successMessage}</AlertDesc>
        </Alert>
      )}

      {/* Error message */}
      {error && error !== 'upgrade' && (
        <Alert variant="destructive">
          <AlertTitle>Error</AlertTitle>
          <AlertDesc>{error}</AlertDesc>
        </Alert>
      )}

      {/* Allocation Summary */}
      {allocation && (
        <div className="grid gap-4 sm:grid-cols-3">
          <Card>
            <CardContent className="pt-6">
              <div className="text-sm text-muted-foreground">Active IPs</div>
              <div className="text-2xl font-bold mt-1">{allocation.active}</div>
              {includedCount > 0 && (
                <div className="text-xs text-muted-foreground mt-1">
                  {includedCount} included in plan
                </div>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-sm text-muted-foreground">Add-on IPs</div>
              <div className="text-2xl font-bold mt-1">{addOnCount}</div>
              {addOnCount > 0 && (
                <div className="text-xs text-muted-foreground mt-1">
                  ${(addOnCount * addOnPrice).toFixed(0)}/mo additional
                </div>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-sm text-muted-foreground">Add-on Price</div>
              <div className="text-2xl font-bold mt-1">${addOnPrice}/mo</div>
              <div className="text-xs text-muted-foreground mt-1">
                per additional IP
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <Card>
          <CardContent className="py-12 text-center">
            <div className="animate-pulse space-y-3">
              <div className="h-4 w-48 bg-surface-200 rounded mx-auto" />
              <div className="h-4 w-32 bg-surface-200 rounded mx-auto" />
            </div>
          </CardContent>
        </Card>
      )}

      {/* Empty state */}
      {!loading && activeIps.length === 0 && (
        <Card className="text-center">
          <CardContent className="pt-8 pb-8 space-y-4">
            <Server className="h-12 w-12 mx-auto text-surface-400" />
            <CardTitle>No Dedicated IPs</CardTitle>
            <p className="text-sm text-muted-foreground max-w-md mx-auto">
              Dedicated IPs give you full control over your sending reputation.
              Each IP goes through an automatic {WARMUP_DAYS}-day warmup period to build deliverability.
            </p>
            {allocation?.addOnAvailable && (
              <Button onClick={() => setShowProvisionDialog(true)}>
                <Plus className="h-4 w-4 mr-2" />
                Add Your First Dedicated IP
              </Button>
            )}
          </CardContent>
        </Card>
      )}

      {/* Active IPs */}
      {activeIps.length > 0 && (
        <div className="space-y-4">
          <h3 className="text-lg font-semibold">Active IPs</h3>
          <div className="grid gap-4">
            {activeIps.map((ip) => (
              <IpCard
                key={ip.id}
                ip={ip}
                onRelease={() => setShowReleaseDialog(ip.id)}
              />
            ))}
          </div>
        </div>
      )}

      {/* Retired IPs */}
      {retiredIps.length > 0 && (
        <div className="space-y-4">
          <h3 className="text-lg font-semibold text-muted-foreground">Released IPs</h3>
          <div className="grid gap-4">
            {retiredIps.map((ip) => (
              <IpCard key={ip.id} ip={ip} />
            ))}
          </div>
        </div>
      )}

      {/* Pagination */}
      {pagination && pagination.hasMore && (
        <div className="flex justify-center pt-2">
          <Button
            variant="outline"
            onClick={() => setOffset((prev) => prev + (pagination.limit ?? 20))}
          >
            Load More
          </Button>
        </div>
      )}

      {/* Provision Confirmation Dialog */}
      <Dialog open={showProvisionDialog} onOpenChange={setShowProvisionDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Dedicated IP</DialogTitle>
            <DialogDescription>
              A new dedicated IP will be provisioned and enter a {WARMUP_DAYS}-day automatic warmup period.
              During warmup, sending limits gradually increase to build reputation.
              {addOnCount >= 0 && includedCount > 0 && (allocation?.active ?? 0) >= includedCount && (
                <span className="block mt-2 font-medium text-foreground">
                  This IP will be billed as an add-on at ${addOnPrice}/mo.
                </span>
              )}
              {includedCount > 0 && (allocation?.active ?? 0) < includedCount && (
                <span className="block mt-2 font-medium text-emerald-600">
                  This IP is included in your plan at no extra cost.
                </span>
              )}
              {includedCount === 0 && (
                <span className="block mt-2 font-medium text-foreground">
                  This IP will be billed at ${addOnPrice}/mo as an add-on.
                </span>
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowProvisionDialog(false)} disabled={provisioning}>
              Cancel
            </Button>
            <Button onClick={handleProvision} disabled={provisioning}>
              {provisioning ? 'Provisioning…' : 'Add Dedicated IP'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Release Confirmation Dialog */}
      <Dialog open={!!showReleaseDialog} onOpenChange={() => setShowReleaseDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Release Dedicated IP</DialogTitle>
            <DialogDescription>
              Are you sure you want to release this dedicated IP? This action cannot be undone.
              The IP reputation and warmup progress will be lost. Billing will be prorated.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowReleaseDialog(null)} disabled={releasing}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => showReleaseDialog && handleRelease(showReleaseDialog)}
              disabled={releasing}
            >
              {releasing ? 'Releasing…' : 'Release IP'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ---------- IP Card Component ----------

function IpCard({
  ip,
  onRelease,
}: {
  ip: DedicatedIpResponse;
  onRelease?: () => void;
}) {
  const isRetired = RETIRED_STATUSES.has(ip.status);
  const isWarming = ip.status === 'warming';
  const bounceRate = ip.stats.emailsSentTotal > 0
    ? ((ip.stats.bouncesTotal / ip.stats.emailsSentTotal) * 100).toFixed(2)
    : '0.00';
  const complaintRate = ip.stats.emailsSentTotal > 0
    ? ((ip.stats.complaintsTotal / ip.stats.emailsSentTotal) * 100).toFixed(3)
    : '0.000';

  const estimatedCompletion = ip.warmup.estimatedCompletion
    ? new Date(ip.warmup.estimatedCompletion).toLocaleDateString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric',
      })
    : null;

  return (
    <Card className={cn(isRetired && 'opacity-60')}>
      <CardContent className="pt-6">
        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
          {/* Left: IP info */}
          <div className="space-y-3 flex-1">
            <div className="flex items-center gap-3">
              <code className="text-lg font-mono font-semibold">{ip.ipAddress}</code>
              <StatusBadge status={ip.status} />
              {ip.reputation.blocklisted && (
                <Badge variant="destructive">Blocklisted</Badge>
              )}
            </div>

            {/* Warmup progress */}
            {isWarming && (
              <div className="space-y-1">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Warmup Progress</span>
                  <span className="font-medium">{ip.warmup.progressPercent}%</span>
                </div>
                <div
                  className="h-2 rounded-full bg-surface-200 overflow-hidden"
                  role="progressbar"
                  aria-valuenow={ip.warmup.progressPercent}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-label="Warmup progress"
                >
                  <div
                    className="h-full rounded-full transition-all duration-500 bg-primary"
                    style={{
                      width: `${Math.max(0, Math.min(100, ip.warmup.progressPercent))}%`,
                    }}
                  />
                </div>
                {ip.warmup.currentDailyLimit && (
                  <div className="text-xs text-muted-foreground">
                    Current daily limit: {ip.warmup.currentDailyLimit.toLocaleString()} emails
                  </div>
                )}
                {estimatedCompletion && (
                  <div className="text-xs text-muted-foreground">
                    Estimated completion: {estimatedCompletion}
                  </div>
                )}
              </div>
            )}

            {/* Stats row */}
            <div className="flex flex-wrap gap-x-6 gap-y-2 text-sm">
              <div>
                <span className="text-muted-foreground">Reputation: </span>
                <span className={cn(
                  'font-medium',
                  ip.reputation.score >= 90 ? 'text-emerald-600' :
                  ip.reputation.score >= 70 ? 'text-amber-600' : 'text-red-600',
                )}>
                  {ip.reputation.score.toFixed(1)}
                </span>
              </div>
              <div>
                <span className="text-muted-foreground">Sent: </span>
                <span className="font-medium">{ip.stats.emailsSentTotal.toLocaleString()}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Bounce Rate: </span>
                <span className="font-medium">{bounceRate}%</span>
              </div>
              <div>
                <span className="text-muted-foreground">Complaint Rate: </span>
                <span className="font-medium">{complaintRate}%</span>
              </div>
            </div>

            {ip.ptrRecord && (
              <div className="text-xs text-muted-foreground">
                PTR: {ip.ptrRecord}
              </div>
            )}
          </div>

          {/* Right: Actions */}
          {onRelease && !isRetired && (
            <div className="flex-shrink-0">
              <Button variant="outline" size="sm" onClick={onRelease}>
                <X className="h-3 w-3 mr-1.5" />
                Release
              </Button>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
