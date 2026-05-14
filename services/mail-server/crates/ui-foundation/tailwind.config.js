/** @type {import('tailwindcss').Config} */
module.exports = {
  content: {
    relative: true,
    files: [
      './src/**/*.rs',
      './assets/globals.input.css',
    ],
  },
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