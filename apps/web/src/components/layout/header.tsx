'use client';

import * as React from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import {
 Bell,
 Search,
 Settings,
 User,
 Moon,
 Sun,
 Monitor,
 Plus,
 Menu,
} from '@/components/ui/icons';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
 DropdownMenu,
 DropdownMenuContent,
 DropdownMenuItem,
 DropdownMenuLabel,
 DropdownMenuSeparator,
 DropdownMenuTrigger,
 DropdownMenuGroup,
} from '@/components/ui/dropdown-menu';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { SimpleTooltip } from '@/components/ui/tooltip';
import { formatRelativeTime } from '@/lib/utils';
import { getCsrfToken } from '@/hooks/use-api';
import { useNotificationStore, useUIStore, useUserStore } from '@/stores';

/** Resolve the effective theme ('light' | 'dark') from the store value */
function resolveTheme(theme: 'light' | 'dark' | 'system'): 'light' | 'dark' {
  if (theme !== 'system') return theme;
  if (typeof window === 'undefined') return 'light';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

interface HeaderProps {
 className?: string;
 onMenuClick?: () => void;
 isMobileMenuOpen?: boolean;
}

export const Header = React.memo(function Header({ className, onMenuClick, isMobileMenuOpen }: HeaderProps) {
 const router = useRouter();
 // FIX-095: Use zustand UIStore for persisted theme preference
 const storeTheme = useUIStore((s) => s.theme);
 const setStoreTheme = useUIStore((s) => s.setTheme);
 const [searchOpen, setSearchOpen] = React.useState(false);
 const [searchQuery, setSearchQuery] = React.useState('');
 const searchInputRef = React.useRef<HTMLInputElement | null>(null);
 const lastAppliedThemeRef = React.useRef<'light' | 'dark' | null>(null);
 const user = useUserStore((s) => s.user);
 const unreadCount = useNotificationStore((s) => s.unreadCount);
 const notifications = useNotificationStore((s) => s.notifications);
 const markAllAsRead = useNotificationStore((s) => s.markAllAsRead);

 // Apply theme class to <html> whenever theme changes; avoid redundant reflows.
 React.useEffect(() => {
   const apply = () => {
     const effective = resolveTheme(storeTheme);
     if (lastAppliedThemeRef.current === effective) {
       return;
     }
     const shouldEnableDark = effective === 'dark';
     const hasDarkClass = document.documentElement.classList.contains('dark');
     if (hasDarkClass !== shouldEnableDark) {
       document.documentElement.classList.toggle('dark', shouldEnableDark);
     }
     lastAppliedThemeRef.current = effective;
   };
   apply();

   if (storeTheme !== 'system') {
     return;
   }

   const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
   mediaQuery.addEventListener('change', apply);
   return () => mediaQuery.removeEventListener('change', apply);
 }, [storeTheme]);

 const effectiveTheme = resolveTheme(storeTheme);

 // Cycle: light → dark → system → light
 const cycleTheme = () => {
   const order: Array<'light' | 'dark' | 'system'> = ['light', 'dark', 'system'];
   const idx = order.indexOf(storeTheme);
   setStoreTheme(order[(idx + 1) % order.length]!);
 };

 const displayName = user?.name?.trim() || 'Account';
 const displayEmail = user?.email?.trim() || 'Authenticated user';
 const avatarFallback = displayName
   .split(/\s+/)
   .filter(Boolean)
   .slice(0, 2)
   .map((part) => part[0]?.toUpperCase() || '')
   .join('') || 'AM';

 const handleLogout = async () => {
   try {
     const csrfToken = await getCsrfToken();
     await fetch('/v1/auth/logout', {
       method: 'POST',
       credentials: 'include',
       headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
     });
   } catch {
     // fallback redirect below
   }

   window.location.href = '/login';
 };

 const handleSearchSubmit = React.useCallback(() => {
   const query = searchQuery.trim().toLowerCase();
   if (!query) return;

   if (query.includes('campaign')) {
     router.push('/campaigns');
   } else if (query.includes('contact')) {
     router.push('/contacts');
   } else if (query.includes('report')) {
     router.push('/reports');
   } else if (query.includes('setting') || query.includes('profile') || query.includes('billing')) {
     router.push('/settings');
   } else {
     router.push('/dashboard');
   }
 }, [router, searchQuery]);

 React.useEffect(() => {
   const onKeyDown = (event: KeyboardEvent) => {
     if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
       event.preventDefault();
       setSearchOpen(true);
       window.requestAnimationFrame(() => searchInputRef.current?.focus());
     }
   };

   window.addEventListener('keydown', onKeyDown);
   return () => window.removeEventListener('keydown', onKeyDown);
 }, []);

 return (
 <header
      className={cn(
        'sticky top-0 z-40 flex h-16 items-center justify-between border-b border-surface-200/70 bg-gradient-to-r from-background via-background to-brand-50/50 backdrop-blur-2xl px-6 shadow-[0_10px_30px_rgba(15,23,42,0.06)] transition-all duration-200 dark:border-surface-200/80 dark:from-surface-50 dark:via-surface-50 dark:to-brand-900/25 dark:shadow-[0_14px_36px_rgba(0,0,0,0.45)]',
        className
      )}
    >
      {/* Left side */}
      <div className="flex items-center gap-4">
        <Button
          variant="ghost"
          size="icon"
          className="md:hidden"
          onClick={onMenuClick}
          aria-label={isMobileMenuOpen ? 'Close menu' : 'Open menu'}
          aria-expanded={isMobileMenuOpen}
        >
          <Menu className="h-5 w-5" />
        </Button>

        {/* Search */}
        <div className="relative hidden md:block">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-surface-400" />
          <Input
            ref={searchInputRef}
            type="search"
            role="searchbox"
            aria-label="Search campaigns and contacts"
            placeholder="Search campaigns, contacts..."
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') {
                event.preventDefault();
                handleSearchSubmit();
              }
            }}
            className="w-64 pl-9 lg:w-80 border-surface-200/70 bg-background/90 shadow-sm focus:ring-primary/10 dark:border-surface-200/80 dark:bg-surface-100/80"
          />
          <kbd className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 rounded-sm border border-surface-200 bg-surface-50 px-1.5 font-mono text-[13px] font-bold text-surface-400 shadow-[0_1px_1px_0_rgba(0,0,0,0.05)] dark:border-surface-300 dark:bg-surface-100 dark:text-surface-500">
            ⌘K
          </kbd>
        </div>

 {/* Mobile search toggle */}
 <Button
 variant="ghost"
 size="icon"
 className="md:hidden"
 onClick={() => setSearchOpen(!searchOpen)}
          aria-label="Toggle search"
        >
          <Search className="h-5 w-5" />
        </Button>
      </div>

      {/* Right side */}
      <div className="flex items-center gap-2">
        {/* Quick action */}
        <SimpleTooltip content="Create Campaign">
          <Link href="/campaigns/new">
            <Button size="sm" className="hidden sm:flex" aria-label="Create Campaign">
              <Plus className="h-4 w-4 mr-2" />
              New Campaign
            </Button>
          </Link>
        </SimpleTooltip>
        <SimpleTooltip content="Create Campaign">
          <Link href="/campaigns/new">
            <Button size="icon" className="sm:hidden" aria-label="Create Campaign">
              <Plus className="h-5 w-5" />
            </Button>
          </Link>
        </SimpleTooltip>

        {/* Theme toggle */}
        <SimpleTooltip content={storeTheme === 'light' ? 'Dark mode' : storeTheme === 'dark' ? 'System theme' : 'Light mode'}>
          <Button variant="ghost" size="icon" onClick={cycleTheme} aria-label="Toggle theme">
            {effectiveTheme === 'light' ? (
              <Moon className="h-5 w-5" />
            ) : storeTheme === 'system' ? (
              <Monitor className="h-5 w-5" />
            ) : (
              <Sun className="h-5 w-5" />
            )}
          </Button>
        </SimpleTooltip>

 {/* Notifications */}
 <DropdownMenu>
 <DropdownMenuTrigger asChild>
 <Button variant="ghost" size="icon" className="relative" aria-label="Notifications">
 <Bell className="h-5 w-5" />
 <span className="sr-only">{unreadCount > 0 ? `${unreadCount} unread notifications` : 'No unread notifications'}</span>
 {unreadCount > 0 ? (
 <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-destructive px-1 text-[10px] font-bold text-destructive-foreground">
 {unreadCount > 99 ? '99+' : unreadCount}
 </span>
 ) : null}
 </Button>
 </DropdownMenuTrigger>
 <DropdownMenuContent align="end" className="w-80">
 <DropdownMenuLabel className="flex items-center justify-between">
 Notifications
 <Badge variant="secondary" size="sm">
 {unreadCount} new
 </Badge>
 </DropdownMenuLabel>
 <DropdownMenuSeparator />
 <div className="max-h-64 overflow-y-auto">
 {notifications.length === 0 ? (
 <div className="p-3 text-sm text-muted-foreground">No notifications</div>
 ) : (
 notifications.slice(0, 10).map((notification) => (
 <DropdownMenuItem key={notification.id} className="flex flex-col items-start gap-1 p-3">
 <div className="flex w-full items-center justify-between">
 <span className="font-medium">{notification.title}</span>
 <span className="text-xs text-muted-foreground">{formatRelativeTime(notification.createdAt)}</span>
 </div>
 <p className="text-sm text-muted-foreground">{notification.message ?? 'New activity'}</p>
 </DropdownMenuItem>
 ))
 )}
 </div>
 <DropdownMenuSeparator />
 <DropdownMenuItem className="justify-center text-primary" onClick={markAllAsRead}>
 Mark all as read
 </DropdownMenuItem>
 </DropdownMenuContent>
 </DropdownMenu>

 {/* User menu */}
 <DropdownMenu>
 <DropdownMenuTrigger asChild>
 <Button variant="ghost" className="relative h-11 w-11 rounded-full" aria-label="User menu" data-testid="user-menu">
 <Avatar size="sm">
 <AvatarImage src="/avatar.png" alt="User" />
 <AvatarFallback>{avatarFallback}</AvatarFallback>
 </Avatar>
 </Button>
 </DropdownMenuTrigger>
 <DropdownMenuContent align="end" className="w-56" data-testid="user-dropdown">
 <DropdownMenuLabel className="font-normal">
 <div className="flex flex-col space-y-1">
 <p className="text-sm font-medium leading-none">{displayName}</p>
 <p className="text-xs leading-none text-muted-foreground">
 {displayEmail}
 </p>
 </div>
 </DropdownMenuLabel>
 <DropdownMenuSeparator />
 <DropdownMenuGroup>
 <DropdownMenuItem asChild>
 <Link href="/settings">
 <User className="mr-2 h-4 w-4" />
 <span>Profile</span>
 </Link>
 </DropdownMenuItem>
 <DropdownMenuItem asChild>
 <Link href="/settings">
 <Settings className="mr-2 h-4 w-4" />
 <span>Settings</span>
 </Link>
 </DropdownMenuItem>
 </DropdownMenuGroup>
 <DropdownMenuSeparator />
 <DropdownMenuItem onClick={handleLogout}>
 <span>Log out</span>
 </DropdownMenuItem>
 </DropdownMenuContent>
 </DropdownMenu>
 </div>

 {/* Mobile search overlay */}
 {searchOpen && (
 <div className="absolute inset-x-0 top-full border-b bg-background p-4 md:hidden">
 <div className="relative">
 <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
 <Input
 type="search"
 role="searchbox"
 aria-label="Search"
 placeholder="Search..."
 value={searchQuery}
 onChange={(event) => setSearchQuery(event.target.value)}
 onKeyDown={(event) => {
 if (event.key === 'Enter') {
 event.preventDefault();
 handleSearchSubmit();
 setSearchOpen(false);
 }
 }}
 className="w-full pl-9"
 autoFocus
 />
 </div>
 </div>
 )}
 </header>
 );
});

Header.displayName = 'Header';
