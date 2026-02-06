'use client';

import { useState, useCallback, createContext, useContext, useRef, useEffect } from 'react';

interface ConfirmDialogOptions {
    title: string;
    message: string;
    confirmLabel?: string;
    cancelLabel?: string;
    variant?: 'default' | 'destructive';
}

interface AlertDialogOptions {
    title: string;
    message: string;
    confirmLabel?: string;
}

interface DialogContextType {
    confirm: (options: ConfirmDialogOptions) => Promise<boolean>;
    alert: (options: AlertDialogOptions) => Promise<void>;
}

const DialogContext = createContext<DialogContextType | null>(null);

export function useDialog() {
    const ctx = useContext(DialogContext);
    if (!ctx) throw new Error('useDialog must be used within a DialogProvider');
    return ctx;
}

interface DialogState {
    type: 'confirm' | 'alert';
    options: ConfirmDialogOptions | AlertDialogOptions;
    resolve: (value: boolean) => void;
}

export function DialogProvider({ children }: { children: React.ReactNode }) {
    const [dialog, setDialog] = useState<DialogState | null>(null);
    const overlayRef = useRef<HTMLDivElement>(null);

    const confirm = useCallback((options: ConfirmDialogOptions): Promise<boolean> => {
        return new Promise<boolean>((resolve) => {
            setDialog({ type: 'confirm', options, resolve });
        });
    }, []);

    const alert = useCallback((options: AlertDialogOptions): Promise<void> => {
        return new Promise<void>((resolve) => {
            setDialog({ type: 'alert', options, resolve: () => resolve() });
        });
    }, []);

    const handleConfirm = useCallback(() => {
        dialog?.resolve(true);
        setDialog(null);
    }, [dialog]);

    const handleCancel = useCallback(() => {
        dialog?.resolve(false);
        setDialog(null);
    }, [dialog]);

    // Close on Escape key
    useEffect(() => {
        if (!dialog) return;
        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.key === 'Escape') handleCancel();
        };
        document.addEventListener('keydown', handleKeyDown);
        return () => document.removeEventListener('keydown', handleKeyDown);
    }, [dialog, handleCancel]);

    return (
        <DialogContext.Provider value={{ confirm, alert }}>
            {children}
            {dialog && (
                <div
                    ref={overlayRef}
                    className="fixed inset-0 z-[200] flex items-center justify-center bg-black/50 backdrop-blur-sm"
                    onClick={(e) => {
                        if (e.target === overlayRef.current) handleCancel();
                    }}
                >
                    <div
                        className="bg-card border border-border rounded-xl shadow-2xl p-6 max-w-md w-full mx-4 animate-in fade-in zoom-in-95 duration-200"
                        role="alertdialog"
                        aria-modal="true"
                        aria-labelledby="dialog-title"
                        aria-describedby="dialog-message"
                    >
                        <h2
                            id="dialog-title"
                            className="text-lg font-semibold text-foreground mb-2"
                        >
                            {dialog.options.title}
                        </h2>
                        <p
                            id="dialog-message"
                            className="text-sm text-muted-foreground mb-6"
                        >
                            {dialog.options.message}
                        </p>
                        <div className="flex justify-end gap-3">
                            {dialog.type === 'confirm' && (
                                <button
                                    onClick={handleCancel}
                                    className="px-4 py-2 rounded-lg text-sm font-medium bg-muted text-foreground hover:bg-muted/80 transition-colors"
                                >
                                    {(dialog.options as ConfirmDialogOptions).cancelLabel ?? 'Cancel'}
                                </button>
                            )}
                            <button
                                onClick={handleConfirm}
                                autoFocus
                                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                                    dialog.type === 'confirm' &&
                                    (dialog.options as ConfirmDialogOptions).variant === 'destructive'
                                        ? 'bg-destructive text-destructive-foreground hover:bg-destructive/90'
                                        : 'bg-primary text-primary-foreground hover:bg-primary/90'
                                }`}
                            >
                                {dialog.options.confirmLabel ?? 'OK'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </DialogContext.Provider>
    );
}
