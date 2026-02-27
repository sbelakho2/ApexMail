import {
    User,
    Bell,
    Shield,
    CreditCard,
    Mail,
    Webhook,
    Building2,
} from '@/components/ui/icons';

export const settingsSections = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'account', label: 'Account', icon: Building2 },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'email', label: 'Email Settings', icon: Mail },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'api', label: 'API & Webhooks', icon: Webhook },
    { id: 'billing', label: 'Billing', icon: CreditCard },
] as const;
