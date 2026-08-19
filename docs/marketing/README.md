# Marketing Surface

The ApexMail public marketing surface lives in `apps/marketing-zola`. It is built as a Zola static site, and the generated documents are served in production by the Rust browser-surface stack.

## Overview

The marketing surface currently covers:

- Homepage and feature landing pages
- Pricing and calculator pages
- Compliance, privacy, DPA, and SLA pages
- Private cloud, forensic, compare, and API console pages
- Case studies and status content

## Technology Stack

| Technology | Purpose |
|------------|---------|
| Zola | Static site generation |
| Static CSS assets | Site styling |
| Rust `ui-foundation` | Production serving of exported marketing documents |

## Project Structure

```text
apps/marketing-zola/
├── config.toml           # Zola site configuration
├── content/              # Markdown content for marketing routes
│   ├── _index.md
│   ├── api-explorer/
│   ├── case-studies/
│   ├── compliance/
│   ├── features/
│   ├── pricing/
│   └── private-cloud/
├── static/               # CSS, fonts, robots, redirects, manifest
├── templates/            # Zola templates and partials
├── public/               # Zola build output
└── static/               # Checked-in CSS and asset files
```

## Local Development

### Prerequisites

- Zola installed locally

### Run

```bash
zola serve --root apps/marketing-zola --port 1111
```

## Build

```bash
zola build --root apps/marketing-zola
```

This writes the generated static site to `apps/marketing-zola/public/`.

## Production Model

- Marketing pages are generated statically from Zola content and templates.
- Production serves exported marketing documents through the Rust browser-surface stack.
- The Rust browser-surface stack serves the exported marketing documents for the `marketing-zola` routes.

## Related Documentation

- [API Documentation](../api/openapi.yaml)
- [Architecture Overview](../architecture/overview.md)
- [Navigation Taxonomy](../development/navigation-taxonomy.md)
