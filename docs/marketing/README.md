# Marketing Website

The ApexMail marketing website is a Next.js 14 application showcasing the platform's features, pricing, and capabilities.

## Overview

The marketing site serves as the primary public-facing website for ApexMail, featuring:

- **Homepage** - Hero section, features overview, live API demo
- **Pricing** - Plan comparison and interactive calculator
- **Compliance** - GDPR, CCPA, and consent management features
- **Private Cloud** - Dedicated infrastructure options
- **Forensic Debugging** - Time-travel debugging capabilities
- **API Console** - Interactive API explorer

## Technology Stack

| Technology | Version | Purpose |
|------------|---------|---------|
| Next.js | 14.2.0 | React framework |
| React | 18.2.0 | UI library |
| TypeScript | 5.3.0 | Type safety |
| Tailwind CSS | 3.4.0 | Styling |
| Framer Motion | 11.0.0 | Animations |
| Three.js | 0.162.0 | 3D graphics |

## Project Structure

```
apps/marketing/
├── src/
│   ├── app/
│   │   ├── layout.tsx          # Root layout
│   │   ├── page.tsx            # Homepage
│   │   ├── globals.css         # Global styles
│   │   ├── pricing/
│   │   │   ├── page.tsx        # Pricing page
│   │   │   └── calculator/
│   │   │       └── page.tsx    # Pricing calculator
│   │   ├── compliance/
│   │   │   └── page.tsx        # Compliance features
│   │   ├── private-cloud/
│   │   │   └── page.tsx        # Private cloud info
│   │   ├── forensic/
│   │   │   └── page.tsx        # Forensic debugging
│   │   └── api-console/
│   │       └── page.tsx        # API explorer
│   ├── components/
│   │   ├── layout/
│   │   │   ├── Header.tsx      # Site header
│   │   │   └── Footer.tsx      # Site footer
│   │   ├── ui/
│   │   │   └── CodeBlock.tsx   # Syntax highlighted code
│   │   ├── home/
│   │   │   ├── HeroSection.tsx
│   │   │   ├── FeaturesSection.tsx
│   │   │   ├── LiveAPIConsole.tsx
│   │   │   ├── ComparisonSection.tsx
│   │   │   ├── PricingCalculator.tsx
│   │   │   ├── SecuritySection.tsx
│   │   │   ├── TestimonialsSection.tsx
│   │   │   └── CTASection.tsx
│   │   ├── compliance/
│   │   │   ├── ComplianceHero.tsx
│   │   │   ├── ConsentLedger.tsx
│   │   │   ├── AutoDPA.tsx
│   │   │   ├── RightToBeForgotten.tsx
│   │   │   ├── AuditTrail.tsx
│   │   │   └── ComplianceCTA.tsx
│   │   ├── private-cloud/
│   │   │   ├── PrivateCloudHero.tsx
│   │   │   ├── LatencyComparison.tsx
│   │   │   ├── DeploymentOptions.tsx
│   │   │   ├── SecurityIsolation.tsx
│   │   │   ├── DedicatedIPs.tsx
│   │   │   └── PrivateCloudCTA.tsx
│   │   ├── forensic/
│   │   │   ├── ForensicHero.tsx
│   │   │   ├── TimeTravelDemo.tsx
│   │   │   ├── RenderHistory.tsx
│   │   │   ├── DebugTools.tsx
│   │   │   └── ForensicCTA.tsx
│   │   ├── api-console/
│   │   │   ├── APIConsoleHero.tsx
│   │   │   ├── InteractiveConsole.tsx
│   │   │   ├── EndpointExplorer.tsx
│   │   │   └── APIConsoleCTA.tsx
│   │   ├── pricing/
│   │   │   ├── PricingHero.tsx
│   │   │   ├── PricingPlans.tsx
│   │   │   ├── PricingFAQ.tsx
│   │   │   └── PricingCTA.tsx
│   │   └── calculator/
│   │       ├── CalculatorHero.tsx
│   │       ├── InteractiveCalculator.tsx
│   │       ├── CompetitorBreakdown.tsx
│   │       └── CalculatorCTA.tsx
│   └── lib/
│       └── utils.ts            # Utility functions
├── public/                     # Static assets
├── package.json
├── tsconfig.json
├── next.config.mjs
├── tailwind.config.ts
└── postcss.config.js
```

## Getting Started

### Prerequisites

- Node.js 18+
- pnpm 8+

### Installation

```bash
cd apps/marketing
pnpm install
```

### Development

```bash
pnpm dev
```

The site will be available at `http://localhost:3000`.

### Build

```bash
pnpm build
```

### Production

```bash
pnpm start
```

## Pages

### Homepage (`/`)

The main landing page featuring:

- **Hero Section** - Main value proposition with animated gradient background
- **Features Section** - Key platform capabilities with icons
- **Live API Console** - Interactive code demo
- **Comparison Section** - ApexMail vs competitors
- **Pricing Calculator** - Quick cost estimation
- **Security Section** - Security certifications and features
- **Testimonials** - Customer quotes and logos
- **CTA Section** - Sign-up call to action

### Pricing (`/pricing`)

Comprehensive pricing information:

- **Plan Comparison** - Starter, Growth, Scale, Enterprise tiers
- **Feature Matrix** - Detailed feature comparison
- **FAQ** - Common pricing questions
- **Enterprise CTA** - Custom pricing contact

### Pricing Calculator (`/pricing/calculator`)

Interactive cost calculator:

- **Volume Slider** - Adjust monthly email volume
- **Feature Toggles** - Add/remove features
- **Competitor Comparison** - Side-by-side cost analysis
- **Total Estimate** - Real-time price calculation

### Compliance (`/compliance`)

Compliance and privacy features:

- **Consent Ledger** - Consent tracking visualization
- **Auto DPA** - Automated Data Processing Agreements
- **Right to be Forgotten** - Data deletion workflows
- **Audit Trail** - Compliance logging

### Private Cloud (`/private-cloud`)

Dedicated infrastructure options:

- **Latency Comparison** - Shared vs dedicated performance
- **Deployment Options** - Cloud, hybrid, on-premise
- **Security Isolation** - Network and data isolation
- **Dedicated IPs** - IP reputation management

### Forensic Debugging (`/forensic`)

Advanced debugging capabilities:

- **Time Travel Demo** - Replay email rendering
- **Render History** - Version comparison
- **Debug Tools** - Diagnostic features

### API Console (`/api-console`)

Interactive API documentation:

- **Endpoint Explorer** - Browse available endpoints
- **Live Testing** - Make real API calls
- **Code Generation** - Get code snippets

## Components

### Layout Components

#### Header (`components/layout/Header.tsx`)

Navigation header with:
- Logo
- Main navigation links
- Mobile menu toggle
- Sign in / Sign up buttons

#### Footer (`components/layout/Footer.tsx`)

Site footer with:
- Company information
- Product links
- Resource links
- Legal links
- Social media

### UI Components

#### CodeBlock (`components/ui/CodeBlock.tsx`)

Syntax-highlighted code display with:
- Language detection
- Copy to clipboard
- Line numbers
- Multiple themes

### Home Components

| Component | Description |
|-----------|-------------|
| `HeroSection` | Main hero with gradient animation |
| `FeaturesSection` | Feature grid with icons |
| `LiveAPIConsole` | Interactive API demo |
| `ComparisonSection` | Competitor comparison table |
| `PricingCalculator` | Quick price calculator |
| `SecuritySection` | Security features and certs |
| `TestimonialsSection` | Customer testimonials |
| `CTASection` | Final call to action |

## Styling

### Design Tokens

The marketing app uses tokenized Tailwind color mappings from `tailwind.config.ts`:

- Brand scale via `--brand-50` to `--brand-900`
- Surface scale via `--surface-50` to `--surface-900`
- Semantic state tokens (`--success`, `--warning`, `--danger`, `--info`)
- Shared spacing/radius/typography tokens (`--space-*`, `--radius-*`, `--font-*`)

### Premium Styling Standards

- Prefer token classes (`bg-brand-*`, `text-surface-*`, `border-*`) over hard-coded color values.
- Use restrained depth via `shadow-premium` and `shadow-premium-hover`.
- Keep section/card hierarchy border-led and readable in both light/dark variants.
- Reuse shared spacing and radius tokens to maintain consistent rhythm and shape language.

### Icons

Marketing UI icons are provided by the local Apex icon module:

- `src/components/ui/icons.tsx`

Use imports from that module instead of external icon libraries.

```tsx
import { ArrowRight, Shield, Cloud } from '@/components/ui/icons';
```

## Animations

Using Framer Motion for animations:

```tsx
import { motion } from 'framer-motion';

const fadeIn = {
  initial: { opacity: 0, y: 20 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.5 }
};

<motion.div {...fadeIn}>
  Content
</motion.div>
```

## SEO

Each page includes metadata:

```tsx
export const metadata = {
  title: 'ApexMail - Enterprise Email Infrastructure',
  description: 'Send transactional and marketing emails with 99.99% deliverability.',
  openGraph: {
    title: 'ApexMail',
    description: 'Enterprise Email Infrastructure',
    images: ['/og-image.png'],
  },
};
```

## Performance

### Optimization Strategies

1. **Image Optimization** - Next.js Image component
2. **Code Splitting** - Automatic per-page bundles
3. **Font Optimization** - next/font for web fonts
4. **Static Generation** - Pre-rendered pages
5. **Lazy Loading** - Dynamic imports for heavy components

### Lighthouse Targets

| Metric | Target |
|--------|--------|
| Performance | 95+ |
| Accessibility | 100 |
| Best Practices | 100 |
| SEO | 100 |

## Deployment

### Vercel (Recommended)

```bash
vercel
```

### Docker

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN pnpm install
COPY . .
RUN pnpm build
EXPOSE 3000
CMD ["pnpm", "start"]
```

### Static Export

```bash
pnpm build
# Output in /out directory
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `NEXT_PUBLIC_API_URL` | API base URL | Yes |
| `NEXT_PUBLIC_GA_ID` | Google Analytics ID | No |
| `NEXT_PUBLIC_SEGMENT_KEY` | Segment write key | No |

## Contributing

1. Follow the component structure
2. Use TypeScript for all new code
3. Use token-based Tailwind classes for styling
4. Include animations with Framer Motion
5. Test responsive design
6. Use Apex icons from `src/components/ui/icons.tsx` (do not add `lucide-react` imports)
7. Run linting before commits

## Related Documentation

- [API Documentation](../api/README.md)
- [Enterprise Features](./README.md)
- [Architecture Overview](../architecture/README.md)
- [Apex Style System (Premium UI + Apex Icons)](../development/style-system.md)
