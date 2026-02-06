'use client';

import { DialogProvider } from '../ui/confirm-dialog';

export function Providers({ children }: { children: React.ReactNode }) {
    return <DialogProvider>{children}</DialogProvider>;
}
