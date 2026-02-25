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

// ---------- Types ----------

interface DedicatedIpResponse {
  id: string;
  ipAddress: string;
  ptrRecord: string | null;
  status: 'pending' | 'warming' | 'active' | 'suspended' | 'retired';
  warmup: {
    startedAt: string | null;
    completedAt: string | null;
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

const statusConfig: Record<string, { label: string; variant: 'default' | 'secondary' | 'destructive' | 'outline'; color: string }> = {
  pending: { label: 'Pending', variant: 'outline', color: 'text-amber-600' },
  warming: { label: 'Warming Up', variant: 'secondary', color: 'text-blue-600' },
  active: { label: 'Active', variant: 'default', color: 'text-emerald-600' },
  suspended: { label: 'Suspended', variant: 'destructive', color: 'text-red-600' },
  retired: { label: 'Retired', variant: 'outline', color: 'text-surface-400' },
};

function StatusBadge({ status }: { status: string }) {
  const config = statusConfig[status] ?? statusConfig['pending'];
  return <Badge variant={config.variant}>{config.label}</Badge>;
}

// ---------- Component ----------

export default function DedicatedIpsPage() {
  const [ips, setIps] = React.useState<DedicatedIpResponse[]>([]);
  const [allocation, setAllocation] = React.useState<AllocationResponse | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [provisioning, setProvisioning] = React.useState(false);
  const [showProvisionDialog, setShowProvisionDialog] = React.useState(false);
  const [showReleaseDialog, setShowReleaseDialog] = React.useState<string | null>(null);
  const [releasing, setReleasing] = React.useState(false);
  const [successMessage, setSuccessMessage] = React.useState<string | null>(null);

  // Fetch IPs
  const fetchIps = React.useCallback(async () => {
    try {
      const res = await fetch('/v1/dedicated-ips');
      if (!res.ok) {
        if (res.status === 403) {
          setError('upgrade');
          return;
        }
        throw new Error('Failed to load dedicated IPs');
      }
      const data: ListResponse = await res.json();
      setIps(data.dedicatedIps);
      setAllocation(data.allocation);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void fetchIps();
  }, [fetchIps]);

  // Clear success message after 5s
  React.useEffect(() => {
    if (!successMessage) return;
    const t = setTimeout(() => setSuccessMessage(null), 5000);
    return () => clearTimeout(t);
  }, [successMessage]);

  // Provision new IP
  async function handleProvision() {
    setProvisioning(true);
    try {
      const res = await fetch('/v1/dedicated-ips', { method: 'POST' });
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        throw new Error(body?.error?.message ?? 'Failed to provision IP');
      }
      setShowProvisionDialog(false);
      setSuccessMessage('Dedicated IP provisioned! Warmup will begin automatically.');
      await fetchIps();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Provisioning failed');
    } finally {
      setProvisioning(false);
    }
  }

  // Release IP
  async function handleRelease(id: string) {
    setReleasing(true);
    try {
      const res = await fetch(`/v1/dedicated-ips/${id}`, { method: 'DELETE' });
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        throw new Error(body?.error?.message ?? 'Failed to release IP');
      }
      setShowReleaseDialog(null);
      setSuccessMessage('Dedicated IP released. Billing will be prorated.');
      await fetchIps();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Release failed');
    } finally {
      setReleasing(false);
    }
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

  const activeIps = ips.filter(ip => ip.status !== 'retired');
  const retiredIps = ips.filter(ip => ip.status === 'retired');
  const includedCount = allocation?.included ?? 0;
  const addOnCount = Math.max(0, (allocation?.active ?? 0) - includedCount);
  const addOnPrice = ((allocation?.addOnPriceMonthly ?? 3000) / 100);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dedicated IPs"
        description="Manage your dedicated sending IP addresses. Each IP goes through a 14-day warmup period."
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
              Each IP goes through an automatic 14-day warmup period to build deliverability.
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

      {/* Provision Confirmation Dialog */}
      <Dialog open={showProvisionDialog} onOpenChange={setShowProvisionDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Dedicated IP</DialogTitle>
            <DialogDescription>
              A new dedicated IP will be provisioned and enter a 14-day automatic warmup period.
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
  const isRetired = ip.status === 'retired';
  const isWarming = ip.status === 'warming';
  const bounceRate = ip.stats.emailsSentTotal > 0
    ? ((ip.stats.bouncesTotal / ip.stats.emailsSentTotal) * 100).toFixed(2)
    : '0.00';
  const complaintRate = ip.stats.emailsSentTotal > 0
    ? ((ip.stats.complaintsTotal / ip.stats.emailsSentTotal) * 100).toFixed(3)
    : '0.000';

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
                <div className="h-2 rounded-full bg-surface-200 overflow-hidden" aria-hidden="true">
                  <svg width="100%" height="100%" viewBox="0 0 100 8" preserveAspectRatio="none">
                    <rect x="0" y="0" width="100" height="8" fill="rgb(var(--surface-200))" rx="999" ry="999" />
                    <rect
                      x="0"
                      y="0"
                      width={Math.max(0, Math.min(100, ip.warmup.progressPercent))}
                      height="8"
                      fill="rgb(var(--brand-500))"
                      rx="999"
                      ry="999"
                    />
                  </svg>
                </div>
                {ip.warmup.currentDailyLimit && (
                  <div className="text-xs text-muted-foreground">
                    Current daily limit: {ip.warmup.currentDailyLimit.toLocaleString()} emails
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
