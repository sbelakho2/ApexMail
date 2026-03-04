'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Mail, Code } from '@/components/ui/icons';
import { formatShortDate, getLocalTimeZone } from '@/lib/utils';

interface PaygUsage {
  period: {
    start: string;
    end: string;
  };
  usage: {
    emailsSent: number;
    apiCalls: number;
  };
  cost: {
    emailCost: number;
    apiCost: number;
    totalCost: number;
  };
}

interface PaygUsageDashboardProps {
  initialData?: PaygUsage;
}

const PRICING_TIERS = [
  { max: 10000, rate: 0.001, label: '0-10k' },
  { max: 100000, rate: 0.0008, label: '10k-100k' },
  { max: 1000000, rate: 0.0005, label: '100k-1M' },
  { max: Infinity, rate: 0.0003, label: '1M+' },
];

export function PaygUsageDashboard({ initialData }: PaygUsageDashboardProps) {
  const [usage, setUsage] = useState<PaygUsage | null>(initialData ?? null);
  const [isLoading, setIsLoading] = useState(!initialData);
  const [fetchError, setFetchError] = useState(false);

  useEffect(() => {
    if (!initialData) {
      fetchUsage();
    }
  }, [initialData]);

  const fetchUsage = async () => {
    setFetchError(false);
    try {
      const response = await fetch('/v1/billing/payg/usage', { credentials: 'include' });
      if (response.ok) {
        const data = await response.json();
        setUsage(data);
      } else {
        setFetchError(true);
      }
    } catch (error) {
      setFetchError(true);
      if (process.env.NODE_ENV !== 'production') {
        console.error('Failed to fetch PAYG usage:', error);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const formatCurrency = (cents: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }).format(cents / 100);
  };

  const formatNumber = (num: number) => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(0)}k`;
    return num.toString();
  };

  const getCurrentTierIndex = (emailsSent: number) => {
    return PRICING_TIERS.findIndex(tier => emailsSent <= tier.max);
  };

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="animate-pulse space-y-3">
            <div className="h-3 bg-muted rounded w-24" />
            <div className="h-8 bg-muted rounded w-32" />
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!usage) {
    if (fetchError) {
      return (
        <Card>
          <CardContent className="p-6 flex flex-col items-center gap-3">
            <p className="text-sm text-destructive">Failed to load usage data.</p>
            <button onClick={fetchUsage} className="text-sm font-medium text-primary hover:underline">Retry</button>
          </CardContent>
        </Card>
      );
    }
    return null;
  }

  const currentTierIndex = getCurrentTierIndex(usage.usage.emailsSent);
  const currentTier = PRICING_TIERS[currentTierIndex];
  const timezone = getLocalTimeZone();

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base font-medium">Usage This Period</CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        {/* Total Cost - Primary metric, prominent */}
        <div>
          <p className="text-3xl font-semibold apex-metric-number tracking-tight">
            {formatCurrency(usage.cost.totalCost)}
          </p>
          <p className="text-xs text-muted-foreground mt-0.5">
            {formatShortDate(usage.period.start)} – {formatShortDate(usage.period.end)} • {timezone}
          </p>
        </div>

        {/* Usage metrics - Simple, scannable */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <div className="flex items-center gap-1.5 text-muted-foreground mb-1">
              <Mail className="w-3.5 h-3.5" />
              <span className="text-xs">Emails</span>
            </div>
            <p className="text-lg font-semibold apex-metric-number">
              {formatNumber(usage.usage.emailsSent)}
            </p>
            <p className="text-xs text-muted-foreground">
              {formatCurrency(usage.cost.emailCost)}
            </p>
          </div>
          <div>
            <div className="flex items-center gap-1.5 text-muted-foreground mb-1">
              <Code className="w-3.5 h-3.5" />
              <span className="text-xs">API Calls</span>
            </div>
            <p className="text-lg font-semibold apex-metric-number">
              {formatNumber(usage.usage.apiCalls)}
            </p>
            <p className="text-xs text-muted-foreground">
              {formatCurrency(usage.cost.apiCost)}
            </p>
          </div>
        </div>

        {/* Pricing tiers - Minimal, informative */}
        <div className="pt-3 border-t">
          <p className="text-xs text-muted-foreground mb-2">Your rate</p>
          <div className="flex gap-1">
            {PRICING_TIERS.map((tier, index) => (
              <div
                key={tier.label}
                className={`flex-1 py-1.5 px-2 rounded text-center transition-colors ${
                  index === currentTierIndex
                    ? 'bg-amber-100 text-amber-800'
                    : 'bg-muted/40 text-muted-foreground'
                }`}
              >
                <p className="text-[10px] leading-tight">{tier.label}</p>
                <p className={`text-xs font-medium ${index === currentTierIndex ? 'text-amber-900' : ''}`}>
                  ${tier.rate}
                </p>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
