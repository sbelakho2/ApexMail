# White-Label & Custom Branding

ApexMail's white-label solution allows agencies and enterprises to offer email services under their own brand, with complete customization of the user experience.

## Overview

White-label features include:

- **Custom Domain** - Use your own domain for the dashboard and APIs
- **Complete UI Branding** - Custom colors, logos, and styling
- **Branded Emails** - Customize all system emails with your branding
- **Custom CSS & Branding Assets** - Full control over the interface styling
- **Removal of ApexMail References** - Complete brand anonymity

## Setup Process

### 1. Configure Custom Domain

```bash
curl -X POST https://enterprise.apexmail.ee/whitelabel \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "accountId": "acc_xxx",
    "customDomain": "mail.yourcompany.com",
    "apiDomain": "api.mail.yourcompany.com"
  }'
```

### 2. DNS Configuration

Add these DNS records to your domain:

| Type | Name | Value | Purpose |
|------|------|-------|---------|
| CNAME | mail | proxy.apexmail.ee | Dashboard |
| CNAME | api.mail | api-proxy.apexmail.ee | API Gateway |
| TXT | _apexmail-verify | verify_token_xxx | Domain verification |

### 3. SSL Certificate

ApexMail automatically provisions and renews SSL certificates for all white-label domains. Alternatively, upload your own:

```bash
curl -X POST https://enterprise.apexmail.ee/whitelabel/ssl \
  -H "X-API-Key: YOUR_API_KEY" \
  -F "certificate=@certificate.pem" \
  -F "privateKey=@private-key.pem" \
  -F "chain=@chain.pem"
```

## Brand Configuration

### Complete Branding Example

```bash
curl -X PUT https://enterprise.apexmail.ee/whitelabel/branding \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "accountId": "acc_xxx",
    "companyName": "YourMail Pro",
    "logo": {
      "light": "https://assets.yourcompany.com/logo-light.svg",
      "dark": "https://assets.yourcompany.com/logo-dark.svg",
      "favicon": "https://assets.yourcompany.com/favicon.ico"
    },
    "colors": {
      "primary": "#dc2626",
      "secondary": "#52525b",
      "accent": "#f59e0b",
      "background": "#ffffff",
      "text": "#18181b",
      "success": "#16a34a",
      "warning": "#f59e0b",
      "error": "#dc2626"
    },
    "typography": {
      "fontFamily": "Inter, system-ui, sans-serif",
      "headingFont": "Cal Sans, system-ui, sans-serif"
    },
    "links": {
      "documentation": "https://docs.yourcompany.com",
      "support": "https://support.yourcompany.com",
      "termsOfService": "https://yourcompany.com/terms",
      "privacyPolicy": "https://yourcompany.com/privacy"
    }
  }'
```

### Color Scheme Options

Configure light and dark mode themes:

```json
{
  "themes": {
    "light": {
      "primary": "#dc2626",
      "background": "#ffffff",
      "surface": "#ffffff",
      "text": "#18181b",
      "textSecondary": "#71717a"
    },
    "dark": {
      "primary": "#dc2626",
      "background": "#09090b",
      "surface": "#18181b",
      "text": "#f4f4f5",
      "textSecondary": "#a1a1aa"
    }
  }
}
```

## Email Templates

### System Email Customization

Customize all system-generated emails:

```bash
curl -X PUT https://enterprise.apexmail.ee/whitelabel/emails \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "welcomeEmail": {
      "subject": "Welcome to {{company_name}}",
      "htmlTemplate": "<html>...</html>",
      "textTemplate": "Welcome to {{company_name}}..."
    },
    "passwordReset": {
      "subject": "Reset your {{company_name}} password",
      "htmlTemplate": "<html>...</html>",
      "textTemplate": "Reset your password..."
    },
    "invoiceEmail": {
      "subject": "Your {{company_name}} Invoice",
      "htmlTemplate": "<html>...</html>",
      "textTemplate": "Your invoice..."
    }
  }'
```

### Available Template Variables

| Variable | Description |
|----------|-------------|
| `{{company_name}}` | Your white-label company name |
| `{{logo_url}}` | URL to your logo |
| `{{primary_color}}` | Your primary brand color |
| `{{support_email}}` | Your support email |
| `{{user_name}}` | Recipient's name |
| `{{action_url}}` | Primary action URL |

## Custom CSS & Branding Assets

### Custom CSS Injection

```bash
curl -X PUT https://enterprise.apexmail.ee/whitelabel/custom-css \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: text/css" \
  -d '
    /* Custom button styles */
    .btn-primary {
      border-radius: 0px;
      font-weight: 600;
    }
    
    /* Custom header */
    .dashboard-header {
      border-bottom: 2px solid var(--primary);
    }
    
    /* Remove ApexMail attribution */
    .powered-by {
      display: none;
    }
  '
```

## Dashboard Customization

### Navigation Menu

Configure dashboard navigation:

```json
{
  "navigation": {
    "showAnalytics": true,
    "showTemplates": true,
    "showContacts": true,
    "showDomains": true,
    "showWebhooks": true,
    "showApiKeys": true,
    "customLinks": [
      {
        "label": "Help Center",
        "url": "https://help.yourcompany.com",
        "icon": "help-circle"
      }
    ]
  }
}
```

### Feature Visibility

Control which features your customers see:

```json
{
  "features": {
    "templateEditor": true,
    "codeEditor": true,
    "analytics": true,
    "realTimeStats": true,
    "webhooks": true,
    "apiConsole": true,
    "suppressionManagement": true,
    "teamManagement": true,
    "billing": false
  }
}
```

## Login Page Customization

```json
{
  "loginPage": {
    "backgroundImage": "https://assets.yourcompany.com/login-bg.jpg",
    "backgroundOverlay": "rgba(0, 0, 0, 0.5)",
    "showTestimonial": true,
    "testimonial": {
      "quote": "The best email platform we've ever used.",
      "author": "Jane Smith",
      "company": "Acme Corp"
    },
    "socialLogin": {
      "google": true,
      "microsoft": false,
      "github": false
    }
  }
}
```

## API Response Customization

Remove ApexMail branding from API responses:

```json
{
  "apiCustomization": {
    "removeApexMailHeaders": true,
    "customServerHeader": "YourMail-API",
    "customPoweredBy": "YourMail Pro"
  }
}
```

## Verification

### Check White-Label Status

```bash
curl https://enterprise.apexmail.ee/whitelabel/status/{account_id} \
  -H "X-API-Key: YOUR_API_KEY"
```

Response:
```json
{
  "status": "active",
  "customDomain": {
    "domain": "mail.yourcompany.com",
    "verified": true,
    "sslStatus": "active",
    "sslExpiry": "2025-01-15T00:00:00Z"
  },
  "apiDomain": {
    "domain": "api.mail.yourcompany.com",
    "verified": true
  },
  "branding": {
    "configured": true,
    "lastUpdated": "2024-01-15T10:30:00Z"
  }
}
```

### Verify Custom Domain

```bash
curl -X POST https://enterprise.apexmail.ee/whitelabel/verify \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"accountId": "acc_xxx"}'
```

## Multi-Tier White-Label

Enable your customers to white-label for their clients:

```json
{
  "multiTierWhiteLabel": {
    "enabled": true,
    "allowSubAccountBranding": true,
    "inheritParentBranding": true,
    "maxTiers": 2
  }
}
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/whitelabel` | POST | Initialize white-label |
| `/whitelabel/branding` | PUT | Update branding |
| `/whitelabel/custom-css` | PUT | Update custom CSS |
| `/whitelabel/custom-js` | PUT | Update custom JS |
| `/whitelabel/emails` | PUT | Update email templates |
| `/whitelabel/ssl` | POST | Upload SSL certificate |
| `/whitelabel/verify` | POST | Verify custom domain |
| `/whitelabel/status/{accountId}` | GET | Get white-label status |

## Best Practices

1. **Consistent Branding** - Match your existing brand guidelines
2. **Mobile Testing** - Verify branding on mobile devices
3. **Accessibility** - Ensure color contrast meets WCAG standards
4. **SSL Monitoring** - Set up alerts for certificate expiration
5. **Backup Configurations** - Export white-label settings regularly
6. **Staged Rollout** - Test changes in development before production
