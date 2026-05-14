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
        danger: colorScale('brand'),
        destructive: colorScale('brand'),
        error: colorScale('brand'),
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
        premium: '0 10px 30px rgba(0, 0, 0, 0.08), 0 1px 3px rgba(0, 0, 0, 0.05)',
        'premium-hover': '0 20px 40px rgba(0, 0, 0, 0.12)',
        'premium-sm': '0 4px 12px rgba(0, 0, 0, 0.05)',
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
