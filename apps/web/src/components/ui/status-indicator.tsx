import {
  AlertCircle,
  CheckCircle2,
  Circle,
  Clock,
  Pause,
  XCircle,
} from '@/components/ui/icons';
import { Badge } from '@/components/ui/badge';

type WebStatusKey =
  | 'draft'
  | 'scheduled'
  | 'sending'
  | 'sent'
  | 'paused'
  | 'subscribed'
  | 'unsubscribed'
  | 'bounced'
  | 'complained'
  | 'delivered'
  | 'queued'
  | 'failed';

const STATUS_CONFIG: Record<WebStatusKey, { label: string; variant: 'secondary' | 'info' | 'warning' | 'success' | 'outline' | 'error'; Icon: typeof Circle }> = {
  draft: { label: 'Draft', variant: 'secondary', Icon: Circle },
  scheduled: { label: 'Scheduled', variant: 'info', Icon: Clock },
  sending: { label: 'Sending', variant: 'warning', Icon: Clock },
  sent: { label: 'Sent', variant: 'success', Icon: CheckCircle2 },
  paused: { label: 'Paused', variant: 'outline', Icon: Pause },
  subscribed: { label: 'Subscribed', variant: 'success', Icon: CheckCircle2 },
  unsubscribed: { label: 'Unsubscribed', variant: 'secondary', Icon: Pause },
  bounced: { label: 'Bounced', variant: 'warning', Icon: AlertCircle },
  complained: { label: 'Complained', variant: 'error', Icon: XCircle },
  delivered: { label: 'Delivered', variant: 'success', Icon: CheckCircle2 },
  queued: { label: 'Queued', variant: 'secondary', Icon: Clock },
  failed: { label: 'Failed', variant: 'error', Icon: XCircle },
};

interface StatusIndicatorProps {
  status: WebStatusKey | string;
  className?: string;
}

export function StatusIndicator({ status, className }: StatusIndicatorProps) {
  const normalized = status.toLowerCase() as WebStatusKey;
  const config = STATUS_CONFIG[normalized] ?? {
    label: status,
    variant: 'secondary' as const,
    Icon: Circle,
  };

  return (
    <Badge variant={config.variant} className={className}>
      <config.Icon className="mr-1 h-3 w-3" />
      {config.label}
    </Badge>
  );
}
