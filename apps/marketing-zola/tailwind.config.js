/** @type {import('tailwindcss').Config} */
module.exports = {
  content: {
    relative: true,
    files: [
      './templates/**/*.html',
      './content/**/*.{html,md}',
      './static/js/**/*.js',
    ],
  },
  theme: {
    extend: {
      colors: {
        brand: colorScale('brand'),
        primary: colorScale('brand'),
        accent: colorScale('brand'),
        surface: colorScale('surface'),
        success: colorScale('success'),
        warning: colorScale('warning'),
        info: colorScale('info'),
        // danger/destructive/error now reference a dedicated red palette
        // (audit 1.4) — previously they aliased `brand`, which made every
        // "destructive" button render in the brand color.
        danger: colorScale('danger'),
        destructive: colorScale('danger'),
        error: colorScale('danger'),
      },
      fontFamily: {
        sans: ['var(--font-apex)'],
        display: ['var(--font-display)'],
        mono: ['var(--font-mono)'],
      },
      borderRadius: {
        sm: 'var(--radius-sm)',
        md: 'var(--radius-md)',
        lg: 'var(--radius-lg)',
        xl: 'var(--radius-xl)',
        '2xl': 'var(--radius-2xl)',
      },
      boxShadow: {
        // Multi-layer ambient-occlusion system (audit 1.2). Must stay in sync
        // with the .shadow-premium* component classes in input.css.
        premium: '0 20px 50px -12px rgb(0 0 0 / 0.15), 0 0 1px rgb(0 0 0 / 0.05)',
        'premium-hover': '0 30px 60px -12px rgb(0 0 0 / 0.25), 0 0 1px rgb(0 0 0 / 0.06)',
        'card-hover': '0 30px 60px -12px rgb(0 0 0 / 0.25), 0 0 1px rgb(0 0 0 / 0.06)',
        'premium-sm': '0 8px 24px -8px rgb(0 0 0 / 0.10), 0 0 1px rgb(0 0 0 / 0.04)',
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

function withAlpha(variableName) {
  return `rgb(var(${variableName}) / <alpha-value>)`;
}
