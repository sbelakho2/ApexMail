'use client';

import * as React from 'react';
import type { ToastActionElement, ToastProps } from '@/components/ui/toast';

const TOAST_LIMIT = 5;
const TOAST_REMOVE_DELAY = 5000;

type ToasterToast = ToastProps & {
    id: string;
    title?: React.ReactNode;
    description?: React.ReactNode;
    action?: ToastActionElement;
};

const actionTypes = {
    ADD_TOAST: 'ADD_TOAST',
    UPDATE_TOAST: 'UPDATE_TOAST',
    DISMISS_TOAST: 'DISMISS_TOAST',
    REMOVE_TOAST: 'REMOVE_TOAST',
} as const;

type ActionType = typeof actionTypes;

type Action =
    | {
          type: ActionType['ADD_TOAST'];
          toast: ToasterToast;
      }
    | {
          type: ActionType['UPDATE_TOAST'];
          toast: Partial<ToasterToast>;
      }
    | {
          type: ActionType['DISMISS_TOAST'];
          toastId?: ToasterToast['id'];
      }
    | {
          type: ActionType['REMOVE_TOAST'];
          toastId?: ToasterToast['id'];
      };

interface State {
    toasts: ToasterToast[];
}

interface ToastStore {
    state: State;
    listeners: Array<(state: State) => void>;
    toastTimeouts: Map<string, ReturnType<typeof setTimeout>>;
    count: number;
}

declare global {
    interface Window {
        __apexmailToastStore__?: ToastStore;
    }
}

function createToastStore(): ToastStore {
    return {
        state: { toasts: [] },
        listeners: [],
        toastTimeouts: new Map<string, ReturnType<typeof setTimeout>>(),
        count: 0,
    };
}

function getToastStore(): ToastStore {
    if (typeof window === 'undefined') {
        return createToastStore();
    }

    if (!window.__apexmailToastStore__) {
        window.__apexmailToastStore__ = createToastStore();
    }

    return window.__apexmailToastStore__;
}

function genId(): string {
    const store = getToastStore();
    store.count = (store.count + 1) % Number.MAX_SAFE_INTEGER;
    return store.count.toString();
}

const addToRemoveQueue = (toastId: string) => {
    const store = getToastStore();

    if (store.toastTimeouts.has(toastId)) {
        return;
    }

    const timeout = setTimeout(() => {
        store.toastTimeouts.delete(toastId);
        dispatch({
            type: 'REMOVE_TOAST',
            toastId: toastId,
        });
    }, TOAST_REMOVE_DELAY);

    store.toastTimeouts.set(toastId, timeout);
};

export const reducer = (state: State, action: Action): State => {
    switch (action.type) {
        case 'ADD_TOAST':
            return {
                ...state,
                toasts: [action.toast, ...state.toasts].slice(0, TOAST_LIMIT),
            };

        case 'UPDATE_TOAST':
            return {
                ...state,
                toasts: state.toasts.map((t) =>
                    t.id === action.toast.id ? { ...t, ...action.toast } : t
                ),
            };

        case 'DISMISS_TOAST': {
            const { toastId } = action;

            if (toastId) {
                addToRemoveQueue(toastId);
            } else {
                state.toasts.forEach((toast) => {
                    addToRemoveQueue(toast.id);
                });
            }

            return {
                ...state,
                toasts: state.toasts.map((t) =>
                    t.id === toastId || toastId === undefined
                        ? {
                              ...t,
                              open: false,
                          }
                        : t
                ),
            };
        }
        case 'REMOVE_TOAST':
            if (action.toastId === undefined) {
                return {
                    ...state,
                    toasts: [],
                };
            }
            return {
                ...state,
                toasts: state.toasts.filter((t) => t.id !== action.toastId),
            };
    }
};

function dispatch(action: Action) {
    const store = getToastStore();
    store.state = reducer(store.state, action);
    store.listeners.forEach((listener) => {
        listener(store.state);
    });
}

type Toast = Omit<ToasterToast, 'id'>;

function toast({ ...props }: Toast) {
    const id = genId();

    const update = (props: ToasterToast) =>
        dispatch({
            type: 'UPDATE_TOAST',
            toast: { ...props, id },
        });
    const dismiss = () => dispatch({ type: 'DISMISS_TOAST', toastId: id });

    dispatch({
        type: 'ADD_TOAST',
        toast: {
            ...props,
            id,
            open: true,
            onOpenChange: (open) => {
                if (!open) dismiss();
            },
        },
    });

    return {
        id: id,
        dismiss,
        update,
    };
}

function useToast() {
    const store = getToastStore();
    const [state, setState] = React.useState<State>(store.state);

    React.useEffect(() => {
        const runtimeStore = getToastStore();
        runtimeStore.listeners.push(setState);
        return () => {
            const index = runtimeStore.listeners.indexOf(setState);
            if (index > -1) {
                runtimeStore.listeners.splice(index, 1);
            }
        };
    }, []);

    return {
        ...state,
        toast,
        dismiss: (toastId?: string) => dispatch({ type: 'DISMISS_TOAST', toastId }),
    };
}

// Convenience methods
toast.success = (props: Omit<Toast, 'variant'>) =>
    toast({ ...props, variant: 'success' });

toast.error = (props: Omit<Toast, 'variant'>) =>
    toast({ ...props, variant: 'destructive' });

toast.warning = (props: Omit<Toast, 'variant'>) =>
    toast({ ...props, variant: 'warning' });

toast.info = (props: Omit<Toast, 'variant'>) =>
    toast({ ...props, variant: 'info' });

export { useToast, toast };
