import type { Config } from 'tailwindcss';

const config: Config = {
    darkMode: ['class'],
    content: [
        './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
        './src/components/**/*.{js,ts,jsx,tsx,mdx}',
        './src/app/**/*.{js,ts,jsx,tsx,mdx}',
    ],
    theme: {
        extend: {
            // Control Plane uses IDENTICAL design tokens as customer console
            // This enforces the "Theme Lock" requirement from checklist 6.5.3
            colors: {
                border: 'rgb(var(--border) / <alpha-value>)',
                input: 'rgb(var(--input) / <alpha-value>)',
                ring: 'rgb(var(--ring) / <alpha-value>)',
                background: 'rgb(var(--background) / <alpha-value>)',
                foreground: 'rgb(var(--foreground) / <alpha-value>)',
                primary: {
                    DEFAULT: 'rgb(var(--primary) / <alpha-value>)',
                    foreground: 'rgb(var(--primary-foreground) / <alpha-value>)',
                },
                secondary: {
                    DEFAULT: 'rgb(var(--secondary) / <alpha-value>)',
                    foreground: 'rgb(var(--secondary-foreground) / <alpha-value>)',
                },
                destructive: {
                    DEFAULT: 'rgb(var(--destructive) / <alpha-value>)',
                    foreground: 'rgb(var(--destructive-foreground) / <alpha-value>)',
                },
                muted: {
                    DEFAULT: 'rgb(var(--muted) / <alpha-value>)',
                    foreground: 'rgb(var(--muted-foreground) / <alpha-value>)',
                },
                accent: {
                    DEFAULT: 'rgb(var(--accent) / <alpha-value>)',
                    foreground: 'rgb(var(--accent-foreground) / <alpha-value>)',
                },
                popover: {
                    DEFAULT: 'rgb(var(--popover) / <alpha-value>)',
                    foreground: 'rgb(var(--popover-foreground) / <alpha-value>)',
                },
                card: {
                    DEFAULT: 'rgb(var(--card) / <alpha-value>)',
                    foreground: 'rgb(var(--card-foreground) / <alpha-value>)',
                },
                success: {
                    DEFAULT: 'rgb(var(--success-500) / <alpha-value>)',
                    foreground: 'rgb(var(--success-100) / <alpha-value>)',
                },
                warning: {
                    DEFAULT: 'rgb(var(--warning-500) / <alpha-value>)',
                    foreground: 'rgb(var(--warning-100) / <alpha-value>)',
                },
                info: {
                    DEFAULT: 'rgb(var(--info-500) / <alpha-value>)',
                    foreground: 'rgb(var(--info-100) / <alpha-value>)',
                },
                surface: {
                    0: 'rgb(var(--surface-0) / <alpha-value>)',
                    50: 'rgb(var(--surface-50) / <alpha-value>)',
                    100: 'rgb(var(--surface-100) / <alpha-value>)',
                    200: 'rgb(var(--surface-200) / <alpha-value>)',
                    300: 'rgb(var(--surface-300) / <alpha-value>)',
                    400: 'rgb(var(--surface-400) / <alpha-value>)',
                    500: 'rgb(var(--surface-500) / <alpha-value>)',
                    600: 'rgb(var(--surface-600) / <alpha-value>)',
                    700: 'rgb(var(--surface-700) / <alpha-value>)',
                    800: 'rgb(var(--surface-800) / <alpha-value>)',
                    900: 'rgb(var(--surface-900) / <alpha-value>)',
                },
                // Control plane accent - subtle indicator this is admin UI
                'control-plane': {
                    DEFAULT: 'rgb(var(--control-plane) / <alpha-value>)',
                    foreground: 'rgb(var(--control-plane-foreground) / <alpha-value>)',
                },
            },
            borderRadius: {
                xl: 'var(--radius-xl)',
                lg: 'var(--radius-lg)',
                md: 'var(--radius-md)',
                sm: 'var(--radius-sm)',
            },
        },
    },
    plugins: [],
};

export default config;
