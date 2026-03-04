'use client';

import * as React from 'react';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import {
    Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useAPI, postFetcher } from '@/hooks/use-api';
import { useUserStore } from '@/stores';
import { toast } from '@/hooks/use-toast';

interface TeamMember {
    name: string;
    role: string;
    email: string;
    status: string;
    avatarUrl?: string;
}

interface TeamResponse {
    members: TeamMember[];
}

export default function SettingsTeamPage() {
    const { data, isLoading, error, mutate } = useAPI<TeamResponse>('/v1/team/members');
    const canAccess = useUserStore((s) => s.canAccess);
    const [inviteOpen, setInviteOpen] = React.useState(false);
    const [inviteEmail, setInviteEmail] = React.useState('');
    const [inviteRole, setInviteRole] = React.useState('member');
    const [inviteLoading, setInviteLoading] = React.useState(false);

    async function handleInvite() {
        const email = inviteEmail.trim();
        if (!email) return;
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            toast({ title: 'Invalid email address', variant: 'destructive' });
            return;
        }
        setInviteLoading(true);
        try {
            await postFetcher('/v1/team/invite', { arg: { email, role: inviteRole } });
            await mutate();
            setInviteOpen(false);
            setInviteEmail('');
            setInviteRole('member');
            toast({ title: 'Invitation sent' });
        } catch {
            toast({ title: 'Failed to send invitation', variant: 'destructive' });
        } finally {
            setInviteLoading(false);
        }
    }

    if (!canAccess('team')) {
        return (
            <div className="space-y-6">
                <PageHeader
                    title="Team"
                    description="Manage teammates, roles, and access."
                    breadcrumbs={[{ label: 'Settings', href: '/settings' }, { label: 'Team' }]}
                />
                <Card>
                    <CardContent className="py-12 text-center">
                        <p className="text-muted-foreground">You do not have permission to manage team members. Contact an admin.</p>
                    </CardContent>
                </Card>
            </div>
        );
    }

    const teamMembers = data?.members ?? [];

    return (
        <div className="space-y-6">
            <PageHeader
                title="Team"
                description="Manage teammates, roles, and access."
                breadcrumbs={[{ label: 'Settings', href: '/settings' }, { label: 'Team' }]}
                actions={<Button onClick={() => setInviteOpen(true)}>Invite Member</Button>}
            />

            <Card>
                <CardHeader>
                    <CardTitle>Team Members</CardTitle>
                    <CardDescription>Keep roles aligned with responsibilities.</CardDescription>
                </CardHeader>
                <CardContent>
                    {isLoading ? (
                        <div className="animate-pulse space-y-3 py-4">
                            <div className="h-4 bg-muted rounded w-48" />
                            <div className="h-4 bg-muted rounded w-64" />
                            <div className="h-4 bg-muted rounded w-40" />
                        </div>
                    ) : error ? (
                        <p className="text-sm text-destructive py-4">Failed to load team members. Please try again.</p>
                    ) : (
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
                                                    <AvatarImage src={member.avatarUrl || '/avatar.png'} alt={member.name} />
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
                                {teamMembers.length === 0 && (
                                    <TableRow>
                                        <TableCell colSpan={3} className="text-center text-muted-foreground py-8">
                                            No team members found. Invite someone to get started.
                                        </TableCell>
                                    </TableRow>
                                )}
                            </TableBody>
                        </Table>
                    )}
                </CardContent>
            </Card>

            <Dialog open={inviteOpen} onOpenChange={setInviteOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Invite Team Member</DialogTitle>
                        <DialogDescription>Send an invitation to join your team.</DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4 py-2">
                        <div className="space-y-2">
                            <Label htmlFor="invite-email">Email address</Label>
                            <Input id="invite-email" type="email" placeholder="colleague@company.com" value={inviteEmail} onChange={e => setInviteEmail(e.target.value)} />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="invite-role">Role</Label>
                            <Select value={inviteRole} onValueChange={setInviteRole}>
                                <SelectTrigger id="invite-role"><SelectValue /></SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="admin">Admin</SelectItem>
                                    <SelectItem value="member">Member</SelectItem>
                                    <SelectItem value="viewer">Viewer</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setInviteOpen(false)}>Cancel</Button>
                        <Button onClick={handleInvite} disabled={inviteLoading || !inviteEmail.trim()}>
                            {inviteLoading ? 'Sending…' : 'Send Invitation'}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}