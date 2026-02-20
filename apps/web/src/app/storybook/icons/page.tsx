import {
    Home,
    Mail,
    Users,
    BarChart3,
    Settings,
    Send,
    ListFilter,
    Shield,
    Bot,
    CreditCard,
    HelpCircle,
    Bell,
    Search,
} from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent } from '@/components/ui/card';

const icons = [
    { name: 'Home', Icon: Home },
    { name: 'Mail', Icon: Mail },
    { name: 'Users', Icon: Users },
    { name: 'BarChart3', Icon: BarChart3 },
    { name: 'Settings', Icon: Settings },
    { name: 'Send', Icon: Send },
    { name: 'ListFilter', Icon: ListFilter },
    { name: 'Shield', Icon: Shield },
    { name: 'Bot', Icon: Bot },
    { name: 'CreditCard', Icon: CreditCard },
    { name: 'HelpCircle', Icon: HelpCircle },
    { name: 'Bell', Icon: Bell },
    { name: 'Search', Icon: Search },
];

export default function StorybookIconsPage() {
    return (
        <div className="space-y-6 p-6">
            <PageHeader title="Icons" description="Icon set overview" breadcrumbs={[{ label: 'Storybook' }, { label: 'Icons' }]} />
            <Card>
                <CardContent className="grid gap-6 p-6 sm:grid-cols-2 lg:grid-cols-4">
                    {icons.map(({ name, Icon }) => (
                        <div key={name} className="flex items-center gap-3">
                            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted">
                                <Icon className="h-5 w-5" />
                            </div>
                            <div className="text-sm font-medium">{name}</div>
                        </div>
                    ))}
                </CardContent>
            </Card>
        </div>
    );
}