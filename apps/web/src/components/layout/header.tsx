'use client';

import * as React from 'react';
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
} from 'lucide-react';
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
import { useUIStore } from '@/stores';

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

export function Header({ className, onMenuClick, isMobileMenuOpen }: HeaderProps) {
 // FIX-095: Use zustand UIStore for persisted theme preference
 const storeTheme = useUIStore((s) => s.theme);
 const setStoreTheme = useUIStore((s) => s.setTheme);
 const [searchOpen, setSearchOpen] = React.useState(false);

 // Apply theme class to <html> whenever storeTheme changes or system pref changes
 React.useEffect(() => {
   const apply = () => {
     const effective = resolveTheme(storeTheme);
     document.documentElement.classList.toggle('dark', effective === 'dark');
   };
   apply();

   // Listen for OS-level preference changes when set to 'system'
   const mq = window.matchMedia('(prefers-color-scheme: dark)');
   mq.addEventListener('change', apply);
   return () => mq.removeEventListener('change', apply);
 }, [storeTheme]);

 const effectiveTheme = resolveTheme(storeTheme);

 // Cycle: light → dark → system → light
 const cycleTheme = () => {
   const order: Array<'light' | 'dark' | 'system'> = ['light', 'dark', 'system'];
   const idx = order.indexOf(storeTheme);
   setStoreTheme(order[(idx + 1) % order.length]!);
 };

 return (
 <header
      className={cn(
        'sticky top-0 z-40 flex h-16 items-center justify-between border-b border-surface-200 bg-surface-50/80 backdrop-blur-xl px-6 transition-all duration-200',
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
            type="search"
            placeholder="Search campaigns, contacts..."
            className="w-64 pl-9 lg:w-80 bg-white border-surface-200 focus:ring-primary/10 shadow-sm"
          />
          <kbd className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 rounded-sm border border-surface-200 bg-surface-50 px-1.5 font-mono text-[13px] font-bold text-surface-400 shadow-[0_1px_1px_0_rgba(0,0,0,0.05)]">
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
          <Button size="sm" className="hidden sm:flex" aria-label="Create Campaign">
            <Plus className="h-4 w-4 mr-2" />
            New Campaign
          </Button>
        </SimpleTooltip>
        <SimpleTooltip content="Create Campaign">
          <Button size="icon" className="sm:hidden" aria-label="Create Campaign">
            <Plus className="h-5 w-5" />
          </Button>
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
 <span className="absolute -right-0.5 -top-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-destructive text-[10px] font-bold text-destructive-foreground">
 3
 </span>
 </Button>
 </DropdownMenuTrigger>
 <DropdownMenuContent align="end" className="w-80">
 <DropdownMenuLabel className="flex items-center justify-between">
 Notifications
 <Badge variant="secondary" size="sm">
 3 new
 </Badge>
 </DropdownMenuLabel>
 <DropdownMenuSeparator />
 <div className="max-h-64 overflow-y-auto">
 <DropdownMenuItem className="flex flex-col items-start gap-1 p-3">
 <div className="flex w-full items-center justify-between">
 <span className="font-medium">Campaign Sent</span>
 <span className="text-xs text-muted-foreground">2m ago</span>
 </div>
 <p className="text-sm text-muted-foreground">
 "Summer Sale" was sent to 12,458 subscribers
 </p>
 </DropdownMenuItem>
 <DropdownMenuItem className="flex flex-col items-start gap-1 p-3">
 <div className="flex w-full items-center justify-between">
 <span className="font-medium">High Bounce Rate</span>
 <span className="text-xs text-muted-foreground">1h ago</span>
 </div>
 <p className="text-sm text-muted-foreground">
 List "Newsletter" has 15% bounce rate
 </p>
 </DropdownMenuItem>
 <DropdownMenuItem className="flex flex-col items-start gap-1 p-3">
 <div className="flex w-full items-center justify-between">
 <span className="font-medium">New Subscriber</span>
 <span className="text-xs text-muted-foreground">3h ago</span>
 </div>
 <p className="text-sm text-muted-foreground">
 500 new subscribers this week!
 </p>
 </DropdownMenuItem>
 </div>
 <DropdownMenuSeparator />
 <DropdownMenuItem className="justify-center text-primary">
 View all notifications
 </DropdownMenuItem>
 </DropdownMenuContent>
 </DropdownMenu>

 {/* User menu */}
 <DropdownMenu>
 <DropdownMenuTrigger asChild>
 <Button variant="ghost" className="relative h-11 w-11 rounded-full" aria-label="User menu">
 <Avatar size="sm">
 <AvatarImage src="/avatar.png" alt="User" />
 <AvatarFallback>JD</AvatarFallback>
 </Avatar>
 </Button>
 </DropdownMenuTrigger>
 <DropdownMenuContent align="end" className="w-56">
 <DropdownMenuLabel className="font-normal">
 <div className="flex flex-col space-y-1">
 <p className="text-sm font-medium leading-none">John Doe</p>
 <p className="text-xs leading-none text-muted-foreground">
 john@example.com
 </p>
 </div>
 </DropdownMenuLabel>
 <DropdownMenuSeparator />
 <DropdownMenuGroup>
 <DropdownMenuItem>
 <User className="mr-2 h-4 w-4" />
 <span>Profile</span>
 </DropdownMenuItem>
 <DropdownMenuItem>
 <Settings className="mr-2 h-4 w-4" />
 <span>Settings</span>
 </DropdownMenuItem>
 </DropdownMenuGroup>
 <DropdownMenuSeparator />
 <DropdownMenuItem>
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
 placeholder="Search..."
 className="w-full pl-9"
 autoFocus
 />
 </div>
 </div>
 )}
 </header>
 );
}
