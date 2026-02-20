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
                    foreground: 'rgb(var(--primary-foreground) / <alpha-value>)',
                },
                danger: 'rgb(var(--danger) / <alpha-value>)',
                error: 'rgb(var(--error) / <alpha-value>)',
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
                success: 'rgb(var(--success) / <alpha-value>)',
                warning: 'rgb(var(--warning) / <alpha-value>)',
                info: 'rgb(var(--info) / <alpha-value>)',
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
                // ApexMail brand colors (Style Guide v1)
                brand: {
                    50: 'rgb(var(--brand-50) / <alpha-value>)',
                    100: 'rgb(var(--brand-100) / <alpha-value>)',
                    200: 'rgb(var(--brand-200) / <alpha-value>)',
                    300: 'rgb(var(--brand-300) / <alpha-value>)',
                    400: 'rgb(var(--brand-400) / <alpha-value>)',
                    500: 'rgb(var(--brand-500) / <alpha-value>)',
                    600: 'rgb(var(--brand-600) / <alpha-value>)',
                    700: 'rgb(var(--brand-700) / <alpha-value>)',
                    800: 'rgb(var(--brand-800) / <alpha-value>)',
                    900: 'rgb(var(--brand-900) / <alpha-value>)',
                },
            },
            boxShadow: {
                'premium': '0 1px 2px rgba(16,24,40,0.06), 0 10px 20px rgba(16,24,40,0.06)',
                'premium-hover': '0 14px 40px rgba(15,23,42,0.08)',
            },
            borderRadius: {
                xl: 'var(--radius-xl)',
                lg: 'var(--radius-lg)',
                md: 'var(--radius-md)',
                sm: 'var(--radius-sm)',
            },
            fontFamily: {
                sans: ['var(--font-display)', 'serif'],
                display: ['var(--font-display)', 'serif'],
                mono: ['var(--font-mono)', 'monospace'],
            },
            spacing: {
                '1': 'var(--space-1)',
                '2': 'var(--space-2)',
                '3': 'var(--space-3)',
                '4': 'var(--space-4)',
                '6': 'var(--space-6)',
                '8': 'var(--space-8)',
                '12': 'var(--space-12)',
            },
        },
    },
    plugins: [],
};

export default config;
