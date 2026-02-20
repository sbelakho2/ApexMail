import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

const teamMembers = [
    { name: 'Avery Chen', role: 'Owner', email: 'avery@apexmail.com', status: 'active' },
    { name: 'Jordan Reed', role: 'Admin', email: 'jordan@apexmail.com', status: 'active' },
    { name: 'Riley Park', role: 'Analyst', email: 'riley@apexmail.com', status: 'invited' },
];

export default function SettingsTeamPage() {
    return (
        <div className="space-y-6">
            <PageHeader
                title="Team"
                description="Manage teammates, roles, and access."
                breadcrumbs={[{ label: 'Settings', href: '/settings' }, { label: 'Team' }]}
                actions={<Button>Invite Member</Button>}
            />

            <Card>
                <CardHeader>
                    <CardTitle>Team Members</CardTitle>
                    <CardDescription>Keep roles aligned with responsibilities.</CardDescription>
                </CardHeader>
                <CardContent>
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>Member</TableHead>
                                <TableHead>Role</TableHead>
                                <TableHead>Status</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {teamMembers.map((member) => (
                                <TableRow key={member.email}>
                                    <TableCell>
                                        <div className="flex items-center gap-3">
                                            <Avatar size="sm">
                                                <AvatarImage src="/avatar.png" alt={member.name} />
                                                <AvatarFallback>{member.name.split(' ').map((p) => p[0]).join('')}</AvatarFallback>
                                            </Avatar>
                                            <div>
                                                <div className="font-medium">{member.name}</div>
                                                <div className="text-sm text-muted-foreground">{member.email}</div>
                                            </div>
                                        </div>
                                    </TableCell>
                                    <TableCell>{member.role}</TableCell>
                                    <TableCell>
                                        <Badge variant={member.status === 'active' ? 'secondary' : 'outline'}>
                                            {member.status}
                                        </Badge>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </CardContent>
            </Card>
        </div>
    );
}