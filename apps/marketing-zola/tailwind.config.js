/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './templates/**/*.html',
    './content/**/*.{html,md}',
    './static/js/**/*.js',
  ],
  theme: {
    extend: {
      colors: {
        brand: colorScale('brand'),
        primary: colorScale('brand'),
        surface: colorScale('surface'),
        success: withAlpha('--success'),
        warning: withAlpha('--warning'),
        danger: withAlpha('--danger'),
        info: withAlpha('--info'),
        destructive: withAlpha('--destructive'),
        error: withAlpha('--error'),
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
      },
      boxShadow: {
        premium: 'none',
        'premium-hover': 'none',
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
