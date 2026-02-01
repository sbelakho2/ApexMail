'use client';

import * as React from 'react';
import Link from 'next/link';
import {
    Plus,
    Search,
    MoreHorizontal,
    Users,
    Upload,
    Download,
    Trash2,
    Pencil,
    Eye,
    Tag,
    Filter,
    ChevronLeft,
    ChevronRight,
    Mail,
    UserPlus,
    AlertCircle,
} from 'lucide-react';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { cn, formatNumber, formatRelativeTime, getInitials } from '@/lib/utils';

// Mock data
const mockContacts = [
    {
        id: '1',
        email: 'john.doe@example.com',
        firstName: 'John',
        lastName: 'Doe',
        company: 'Acme Inc',
        status: 'subscribed' as const,
        tags: ['vip', 'customer'],
        score: 85,
        createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        lastActivity: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    },
    {
        id: '2',
        email: 'jane.smith@company.org',
        firstName: 'Jane',
        lastName: 'Smith',
        company: 'Tech Corp',
        status: 'subscribed' as const,
        tags: ['lead'],
        score: 72,
        createdAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString(),
        lastActivity: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    },
    {
        id: '3',
        email: 'bob.wilson@mail.com',
        firstName: 'Bob',
        lastName: 'Wilson',
        status: 'unsubscribed' as const,
        tags: [],
        score: 0,
        createdAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
        lastActivity: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
    },
    {
        id: '4',
        email: 'sarah@startup.io',
        firstName: 'Sarah',
        lastName: 'Johnson',
        company: 'Startup.io',
        status: 'subscribed' as const,
        tags: ['vip', 'enterprise'],
        score: 94,
        createdAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
        lastActivity: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(),
    },
    {
        id: '5',
        email: 'invalid@bounced.com',
        firstName: 'Invalid',
        lastName: 'User',
        status: 'bounced' as const,
        tags: [],
        score: 0,
        createdAt: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString(),
        lastActivity: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString(),
    },
];

const mockLists = [
    { id: 'all', name: 'All Contacts', count: 48293 },
    { id: '1', name: 'Newsletter', count: 28450 },
    { id: '2', name: 'VIP Customers', count: 5420 },
    { id: '3', name: 'Product Updates', count: 12320 },
];

const statusStyles = {
    subscribed: { label: 'Subscribed', variant: 'success' as const },
    unsubscribed: { label: 'Unsubscribed', variant: 'secondary' as const },
    bounced: { label: 'Bounced', variant: 'destructive' as const },
    complained: { label: 'Complained', variant: 'warning' as const },
};

function ScoreBadge({ score }: { score: number }) {
    const variant = score >= 80 ? 'success' : score >= 50 ? 'warning' : 'secondary';
    return <Badge variant={variant}>{score}</Badge>;
}

export default function ContactsPage() {
    const [selectedIds, setSelectedIds] = React.useState<string[]>([]);
    const [selectedList, setSelectedList] = React.useState('all');
    const [statusFilter, setStatusFilter] = React.useState<string>('all');
    const [searchQuery, setSearchQuery] = React.useState('');
    const [addContactOpen, setAddContactOpen] = React.useState(false);
    const [importOpen, setImportOpen] = React.useState(false);

    // Filter contacts
    const filteredContacts = React.useMemo(() => {
        let result = mockContacts;

        if (statusFilter !== 'all') {
            result = result.filter((c) => c.status === statusFilter);
        }

        if (searchQuery) {
            const query = searchQuery.toLowerCase();
            result = result.filter(
                (c) =>
                    c.email.toLowerCase().includes(query) ||
                    c.firstName?.toLowerCase().includes(query) ||
                    c.lastName?.toLowerCase().includes(query) ||
                    c.company?.toLowerCase().includes(query)
            );
        }

        return result;
    }, [statusFilter, searchQuery]);

    const toggleSelectAll = () => {
        if (selectedIds.length === filteredContacts.length) {
            setSelectedIds([]);
        } else {
            setSelectedIds(filteredContacts.map((c) => c.id));
        }
    };

    const toggleSelect = (id: string) => {
        setSelectedIds((prev) =>
            prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
        );
    };

    return (
        <div className="space-y-6">
            <PageHeader
                title="Contacts"
                description="Manage your subscriber list and contact information."
                breadcrumbs={[{ label: 'Contacts' }]}
                actions={
                    <div className="flex gap-2">
                        <Button variant="outline" onClick={() => setImportOpen(true)}>
                            <Upload className="mr-2 h-4 w-4" />
                            Import
                        </Button>
                        <Button onClick={() => setAddContactOpen(true)}>
                            <UserPlus className="mr-2 h-4 w-4" />
                            Add Contact
                        </Button>
                    </div>
                }
            />

            <div className="grid gap-6 lg:grid-cols-4">
                {/* Lists Sidebar */}
                <Card className="lg:col-span-1">
                    <CardHeader>
                        <CardTitle className="text-base">Lists</CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                        <nav className="space-y-1 px-3 pb-3">
                            {mockLists.map((list) => (
                                <button
                                    key={list.id}
                                    onClick={() => setSelectedList(list.id)}
                                    className={cn(
                                        'flex w-full items-center justify-between rounded-lg px-3 py-2 text-sm transition-colors',
                                        selectedList === list.id
                                            ? 'bg-primary/10 text-primary'
                                            : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                                    )}
                                >
                                    <span>{list.name}</span>
                                    <Badge variant="secondary" size="sm">
                                        {formatNumber(list.count)}
                                    </Badge>
                                </button>
                            ))}
                        </nav>
                        <div className="border-t p-3">
                            <Button variant="outline" size="sm" className="w-full">
                                <Plus className="mr-2 h-4 w-4" />
                                Create List
                            </Button>
                        </div>
                    </CardContent>
                </Card>

                {/* Contacts Table */}
                <Card className="lg:col-span-3">
                    <CardContent className="p-4">
                        {/* Filters */}
                        <div className="mb-4 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                            <div className="flex items-center gap-2">
                                <div className="relative">
                                    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                                    <Input
                                        placeholder="Search contacts..."
                                        value={searchQuery}
                                        onChange={(e) => setSearchQuery(e.target.value)}
                                        className="w-64 pl-9"
                                    />
                                </div>
                                <Select value={statusFilter} onValueChange={setStatusFilter}>
                                    <SelectTrigger className="w-40">
                                        <SelectValue placeholder="Status" />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="all">All Status</SelectItem>
                                        <SelectItem value="subscribed">Subscribed</SelectItem>
                                        <SelectItem value="unsubscribed">Unsubscribed</SelectItem>
                                        <SelectItem value="bounced">Bounced</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>
                            {selectedIds.length > 0 && (
                                <div className="flex items-center gap-2">
                                    <span className="text-sm text-muted-foreground">
                                        {selectedIds.length} selected
                                    </span>
                                    <Button variant="outline" size="sm">
                                        <Tag className="mr-2 h-4 w-4" />
                                        Add Tag
                                    </Button>
                                    <Button variant="outline" size="sm">
                                        <Mail className="mr-2 h-4 w-4" />
                                        Send Email
                                    </Button>
                                    <Button variant="destructive" size="sm">
                                        <Trash2 className="mr-2 h-4 w-4" />
                                        Delete
                                    </Button>
                                </div>
                            )}
                        </div>

                        {/* Table */}
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead className="w-12">
                                        <Checkbox
                                            checked={
                                                selectedIds.length === filteredContacts.length &&
                                                filteredContacts.length > 0
                                            }
                                            onCheckedChange={toggleSelectAll}
                                        />
                                    </TableHead>
                                    <TableHead>Contact</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead>Tags</TableHead>
                                    <TableHead className="text-right">Score</TableHead>
                                    <TableHead>Last Activity</TableHead>
                                    <TableHead className="w-12" />
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {filteredContacts.length === 0 ? (
                                    <TableRow>
                                        <TableCell colSpan={7} className="h-32 text-center">
                                            <div className="flex flex-col items-center gap-2 text-muted-foreground">
                                                <Users className="h-8 w-8" />
                                                <p>No contacts found</p>
                                            </div>
                                        </TableCell>
                                    </TableRow>
                                ) : (
                                    filteredContacts.map((contact) => {
                                        const status = statusStyles[contact.status];
                                        const fullName = [contact.firstName, contact.lastName]
                                            .filter(Boolean)
                                            .join(' ');
                                        return (
                                            <TableRow key={contact.id}>
                                                <TableCell>
                                                    <Checkbox
                                                        checked={selectedIds.includes(contact.id)}
                                                        onCheckedChange={() => toggleSelect(contact.id)}
                                                    />
                                                </TableCell>
                                                <TableCell>
                                                    <div className="flex items-center gap-3">
                                                        <Avatar size="sm">
                                                            <AvatarFallback>
                                                                {getInitials(fullName || contact.email)}
                                                            </AvatarFallback>
                                                        </Avatar>
                                                        <div>
                                                            <p className="font-medium">
                                                                {fullName || contact.email}
                                                            </p>
                                                            {fullName && (
                                                                <p className="text-sm text-muted-foreground">
                                                                    {contact.email}
                                                                </p>
                                                            )}
                                                            {contact.company && (
                                                                <p className="text-xs text-muted-foreground">
                                                                    {contact.company}
                                                                </p>
                                                            )}
                                                        </div>
                                                    </div>
                                                </TableCell>
                                                <TableCell>
                                                    <Badge variant={status.variant}>
                                                        {status.label}
                                                    </Badge>
                                                </TableCell>
                                                <TableCell>
                                                    <div className="flex flex-wrap gap-1">
                                                        {contact.tags.length > 0 ? (
                                                            contact.tags.map((tag) => (
                                                                <Badge
                                                                    key={tag}
                                                                    variant="outline"
                                                                    size="sm"
                                                                >
                                                                    {tag}
                                                                </Badge>
                                                            ))
                                                        ) : (
                                                            <span className="text-sm text-muted-foreground">
                                                                -
                                                            </span>
                                                        )}
                                                    </div>
                                                </TableCell>
                                                <TableCell className="text-right">
                                                    {contact.score > 0 ? (
                                                        <ScoreBadge score={contact.score} />
                                                    ) : (
                                                        '-'
                                                    )}
                                                </TableCell>
                                                <TableCell>
                                                    <span className="text-sm text-muted-foreground">
                                                        {formatRelativeTime(
                                                            new Date(contact.lastActivity)
                                                        )}
                                                    </span>
                                                </TableCell>
                                                <TableCell>
                                                    <DropdownMenu>
                                                        <DropdownMenuTrigger asChild>
                                                            <Button variant="ghost" size="icon">
                                                                <MoreHorizontal className="h-4 w-4" />
                                                            </Button>
                                                        </DropdownMenuTrigger>
                                                        <DropdownMenuContent align="end">
                                                            <DropdownMenuItem>
                                                                <Eye className="mr-2 h-4 w-4" />
                                                                View Profile
                                                            </DropdownMenuItem>
                                                            <DropdownMenuItem>
                                                                <Pencil className="mr-2 h-4 w-4" />
                                                                Edit
                                                            </DropdownMenuItem>
                                                            <DropdownMenuItem>
                                                                <Mail className="mr-2 h-4 w-4" />
                                                                Send Email
                                                            </DropdownMenuItem>
                                                            <DropdownMenuSeparator />
                                                            <DropdownMenuItem destructive>
                                                                <Trash2 className="mr-2 h-4 w-4" />
                                                                Delete
                                                            </DropdownMenuItem>
                                                        </DropdownMenuContent>
                                                    </DropdownMenu>
                                                </TableCell>
                                            </TableRow>
                                        );
                                    })
                                )}
                            </TableBody>
                        </Table>

                        {/* Pagination */}
                        <div className="mt-4 flex items-center justify-between">
                            <p className="text-sm text-muted-foreground">
                                Showing {filteredContacts.length} of {mockContacts.length} contacts
                            </p>
                            <div className="flex items-center gap-2">
                                <Button variant="outline" size="sm" disabled>
                                    <ChevronLeft className="h-4 w-4" />
                                    Previous
                                </Button>
                                <Button variant="outline" size="sm" disabled>
                                    Next
                                    <ChevronRight className="h-4 w-4" />
                                </Button>
                            </div>
                        </div>
                    </CardContent>
                </Card>
            </div>

            {/* Add Contact Dialog */}
            <Dialog open={addContactOpen} onOpenChange={setAddContactOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Add Contact</DialogTitle>
                        <DialogDescription>
                            Add a new contact to your subscriber list.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="grid gap-4 py-4">
                        <div className="grid gap-2">
                            <Label htmlFor="email">Email *</Label>
                            <Input id="email" type="email" placeholder="john@example.com" />
                        </div>
                        <div className="grid grid-cols-2 gap-4">
                            <div className="grid gap-2">
                                <Label htmlFor="firstName">First Name</Label>
                                <Input id="firstName" placeholder="John" />
                            </div>
                            <div className="grid gap-2">
                                <Label htmlFor="lastName">Last Name</Label>
                                <Input id="lastName" placeholder="Doe" />
                            </div>
                        </div>
                        <div className="grid gap-2">
                            <Label htmlFor="company">Company</Label>
                            <Input id="company" placeholder="Acme Inc" />
                        </div>
                        <div className="grid gap-2">
                            <Label htmlFor="tags">Tags</Label>
                            <Input id="tags" placeholder="vip, customer (comma separated)" />
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setAddContactOpen(false)}>
                            Cancel
                        </Button>
                        <Button>Add Contact</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Import Dialog */}
            <Dialog open={importOpen} onOpenChange={setImportOpen}>
                <DialogContent size="lg">
                    <DialogHeader>
                        <DialogTitle>Import Contacts</DialogTitle>
                        <DialogDescription>
                            Upload a CSV file to import contacts. Make sure your file includes an
                            email column.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="grid gap-4 py-4">
                        <div className="flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-8">
                            <Upload className="mb-4 h-10 w-10 text-muted-foreground" />
                            <p className="mb-2 text-sm font-medium">
                                Drag and drop your CSV file here
                            </p>
                            <p className="mb-4 text-xs text-muted-foreground">
                                or click to browse
                            </p>
                            <Button variant="outline" size="sm">
                                Choose File
                            </Button>
                        </div>
                        <div className="rounded-lg bg-muted p-4">
                            <h4 className="mb-2 font-medium">CSV Format</h4>
                            <p className="text-sm text-muted-foreground">
                                Required: email
                                <br />
                                Optional: first_name, last_name, company, phone, tags
                            </p>
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setImportOpen(false)}>
                            Cancel
                        </Button>
                        <Button disabled>Import Contacts</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}
