/** @type {import('tailwindcss').Config} */
module.exports = {
  content: {
    relative: true,
    files: [
      './src/**/*.rs',
      './assets/globals.input.css',
    ],
    // Rust source stores class names inside escaped string literals
    // (class=\"...\") which Tailwind's default extractor misses. Use a
    // broader extract that treats the raw file text as a class source so
    // utilities referenced only from Rust render correctly.
    extract: {
      rs: (content) => {
        return content.match(/[A-Za-z0-9-_:/[\]()%]+/g) || [];
      },
    },
  },
  // Layout-critical utilities that are assembled dynamically in Rust (sidebar
  // width, viewport breakpoints) are safelisted so they are always emitted
  // even if the extractor cannot see their definition site.
  safelist: [
    'w-16', 'w-56', 'w-60', 'w-64', 'md:ml-56', 'w-72', 'w-80',
    'md:ml-16', 'md:ml-56', 'md:ml-60', 'md:ml-64',
    'min-h-[44px]', 'min-w-[44px]', 'shrink-0',
    // KiwiCaptcha widget classes — generated at runtime, not in static HTML
    'bg-brand-50', 'bg-brand-100', 'bg-brand-500',
    'text-brand-600', 'text-brand-700',
    'border-brand-200', 'border-brand-300',
    'ease-premium', 'duration-300',
    'hover:border-surface-300',
    'bg-success-50', 'text-success-600', 'text-success-700',
    'border-success-200', 'border-success-50',
    'bg-primary/5', 'bg-primary/10',
    'border-primary/30',
    'animate-pulse',
    'tabular-nums',
    'font-mono',
    'tracking-[0.12em]',
    'tracking-[0.16em]',
  ],
  theme: {
    extend: {
      colors: {
        background: withAlpha('--background'),
        foreground: withAlpha('--foreground'),
        card: {
          DEFAULT: withAlpha('--card'),
          foreground: withAlpha('--card-foreground'),
        },
        popover: {
          DEFAULT: withAlpha('--popover'),
          foreground: withAlpha('--popover-foreground'),
        },
        primary: {
          DEFAULT: withAlpha('--primary'),
          foreground: withAlpha('--primary-foreground'),
        },
        secondary: {
          DEFAULT: withAlpha('--secondary'),
          foreground: withAlpha('--secondary-foreground'),
        },
        muted: {
          DEFAULT: withAlpha('--muted'),
          foreground: withAlpha('--muted-foreground'),
        },
        accent: {
          DEFAULT: withAlpha('--accent'),
          foreground: withAlpha('--accent-foreground'),
        },
        destructive: {
          DEFAULT: withAlpha('--destructive'),
          foreground: withAlpha('--destructive-foreground'),
        },
        border: withAlpha('--border'),
        input: withAlpha('--input'),
        ring: withAlpha('--ring'),
        brand: colorScale('brand'),
        surface: colorScale('surface'),
        success: semanticScale('success'),
        warning: semanticScale('warning'),
        info: semanticScale('info'),
        error: withAlpha('--error'),
      },
      fontFamily: {
        apex: ['var(--font-sans)'],
        sans: ['var(--font-sans)'],
        display: ['var(--font-display)'],
        mono: ['var(--font-mono)'],
      },
      borderRadius: {
        sm: 'var(--radius-sm)',
        md: 'var(--radius-md)',
        lg: 'var(--radius-lg)',
        xl: 'var(--radius-xl)',
      },
      boxShadow: {
        premium: '0 10px 30px rgba(0, 0, 0, 0.08), 0 1px 3px rgba(0, 0, 0, 0.05)',
        'premium-sm': '0 4px 12px rgba(0, 0, 0, 0.05)',
        'premium-hover': '0 20px 40px rgba(0, 0, 0, 0.12)',
        inner: 'inset 0 2px 4px 0 rgb(0 0 0 / 0.05)',
      },
      transitionTimingFunction: {
        premium: 'cubic-bezier(0.23, 1, 0.32, 1)',
      },
      transitionDuration: {
        180: '180ms',
      },
      maxHeight: {
        106: '26.5rem',
      },
    },
  },
};

function colorScale(name) {
  return {
    50: withAlpha(`--${name}-50`),
    100: withAlpha(`--${name}-100`),
    200: withAlpha(`--${name}-200`),
    300: withAlpha(`--${name}-300`),
    400: withAlpha(`--${name}-400`),
    500: withAlpha(`--${name}-500`),
    600: withAlpha(`--${name}-600`),
    700: withAlpha(`--${name}-700`),
    800: withAlpha(`--${name}-800`),
    900: withAlpha(`--${name}-900`),
    950: withAlpha(`--${name}-950`),
  };
}

function semanticScale(name) {
  return {
    DEFAULT: withAlpha(`--${name}`),
    ...colorScale(name),
  };
}

function withAlpha(variableName) {
  return `rgb(var(${variableName}) / <alpha-value>)`;
}