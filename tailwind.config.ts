import type { Config } from 'tailwindcss'
import typography from '@tailwindcss/typography'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        lime: '#d4ff3f',
        surface: {
          DEFAULT: '#111111',
          raised: '#1a1a1a',
          elevated: '#242424',
          border: '#2a2a2a',
        },
      },
      fontFamily: {
        display: ['"Fraunces"', 'Georgia', 'serif'],
        sans: ['"Inter Tight"', 'Inter', 'ui-sans-serif', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'Consolas', 'monospace'],
      },
      typography: () => ({
        hunt: {
          css: {
            '--tw-prose-body': '#d4d4d8',
            '--tw-prose-headings': '#f4f4f5',
            '--tw-prose-lead': '#a1a1aa',
            '--tw-prose-links': '#d4ff3f',
            '--tw-prose-bold': '#f4f4f5',
            '--tw-prose-counters': '#71717a',
            '--tw-prose-bullets': '#52525b',
            '--tw-prose-hr': '#3f3f46',
            '--tw-prose-quotes': '#d4d4d8',
            '--tw-prose-quote-borders': '#3f3f46',
            '--tw-prose-captions': '#71717a',
            '--tw-prose-code': '#d4ff3f',
            '--tw-prose-pre-code': '#d4d4d8',
            '--tw-prose-pre-bg': '#1a1a1a',
            '--tw-prose-th-borders': '#3f3f46',
            '--tw-prose-td-borders': '#27272a',
            maxWidth: 'none',
          },
        },
      }),
    },
  },
  plugins: [typography],
} satisfies Config
