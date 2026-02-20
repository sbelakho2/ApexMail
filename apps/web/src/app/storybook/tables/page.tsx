import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';

const rows = [
    { name: 'Welcome Flow', status: 'Active', sent: '18,942' },
    { name: 'Product Launch', status: 'Scheduled', sent: '0' },
    { name: 'Monthly Digest', status: 'Paused', sent: '92,155' },
];

export default function StorybookTablesPage() {
    return (
        <div className="space-y-6 p-6">
            <PageHeader title="Tables" description="Data grid styling" breadcrumbs={[{ label: 'Storybook' }, { label: 'Tables' }]} />
            <Card>
                <CardContent className="p-6">
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>Campaign</TableHead>
                                <TableHead>Status</TableHead>
                                <TableHead className="text-right">Sent</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {rows.map((row) => (
                                <TableRow key={row.name}>
                                    <TableCell className="font-medium">{row.name}</TableCell>
                                    <TableCell>
                                        <Badge variant={row.status === 'Active' ? 'secondary' : 'outline'}>
                                            {row.status}
                                        </Badge>
                                    </TableCell>
                                    <TableCell className="text-right">{row.sent}</TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </CardContent>
            </Card>
        </div>
    );
}