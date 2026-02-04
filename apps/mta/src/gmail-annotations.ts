/**
 * Gmail Annotations Service
 * 
 * Gmail Annotations allow emails to display rich previews in the Gmail Promotions tab,
 * including product carousels, deal badges, and logo/image previews.
 * 
 * This service generates the required schema.org JSON-LD markup for:
 * - Product carousels (PromotionCard)
 * - Deal badges with discount amounts
 * - Image previews and logos
 * - Expiration dates for time-sensitive offers
 * 
 * @see https://developers.google.com/gmail/promotab/
 * @see https://www.validity.com/blog/gmail-annotations-in-2025
 */

export interface PromotionCardProduct {
  name: string;
  imageUrl: string;
  price: number;
  currency: string;
  url: string;
  priceCurrency?: string;
  description?: string;
  discount?: {
    type: 'percentage' | 'fixed';
    value: number;
  };
}

export interface DealBadge {
  discountCode?: string;
  discountDescription: string;
  availabilityStarts?: Date;
  availabilityEnds?: Date;
}

export interface GmailAnnotationConfig {
  // Basic preview settings
  logoUrl?: string;
  featuredImageUrl?: string;
  subjectLine?: string;
  
  // Deal/promotion settings
  deal?: DealBadge;
  
  // Product carousel (up to 10 products)
  products?: PromotionCardProduct[];
  
  // Go-to action button
  goToAction?: {
    name: string;
    url: string;
    description?: string;
  };
  
  // Organization info
  organization?: {
    name: string;
    url: string;
    logoUrl?: string;
  };
}

export interface GmailAnnotationResult {
  jsonLd: string;
  html: string;
  validation: ValidationResult;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Gmail Annotations Service for generating rich email previews
 */
export class GmailAnnotationsService {
  private readonly MAX_PRODUCTS = 10;
  private readonly MAX_IMAGE_SIZE_KB = 50;
  private readonly RECOMMENDED_IMAGE_WIDTH = 538;
  private readonly RECOMMENDED_IMAGE_HEIGHT = 138;

  /**
   * Generate Gmail Annotations for a promotional email
   */
  generateAnnotations(config: GmailAnnotationConfig): GmailAnnotationResult {
    const validation = this.validateConfig(config);
    const schemas: object[] = [];

    // Add organization schema if provided
    if (config.organization) {
      schemas.push(this.generateOrganizationSchema(config.organization));
    }

    // Add promotion/deal schema
    if (config.deal || config.products) {
      schemas.push(this.generatePromotionSchema(config));
    }

    // Add Go-to action
    if (config.goToAction) {
      schemas.push(this.generateGoToActionSchema(config.goToAction));
    }

    // Combine all schemas
    const combinedSchema = schemas.length === 1 ? schemas[0] : schemas;
    const jsonLd = JSON.stringify(combinedSchema, null, 2);
    
    // Generate HTML with embedded JSON-LD
    const html = this.generateHtml(jsonLd);

    return {
      jsonLd,
      html,
      validation,
    };
  }

  /**
   * Generate Organization schema
   */
  private generateOrganizationSchema(org: NonNullable<GmailAnnotationConfig['organization']>): object {
    return {
      '@context': 'https://schema.org',
      '@type': 'Organization',
      name: org.name,
      url: org.url,
      ...(org.logoUrl && { logo: org.logoUrl }),
    };
  }

  /**
   * Generate Promotion schema with optional product carousel
   */
  private generatePromotionSchema(config: GmailAnnotationConfig): object {
    const schema: Record<string, unknown> = {
      '@context': 'https://schema.org',
      '@type': 'DiscountOffer',
    };

    // Add deal information
    if (config.deal) {
      schema.description = config.deal.discountDescription;
      
      if (config.deal.discountCode) {
        schema.discountCode = config.deal.discountCode;
      }
      
      if (config.deal.availabilityStarts) {
        schema.availabilityStarts = config.deal.availabilityStarts.toISOString();
      }
      
      if (config.deal.availabilityEnds) {
        schema.availabilityEnds = config.deal.availabilityEnds.toISOString();
      }
    }

    // Add featured image
    if (config.featuredImageUrl) {
      schema.image = config.featuredImageUrl;
    }

    // Add product carousel
    if (config.products && config.products.length > 0) {
      const products = config.products.slice(0, this.MAX_PRODUCTS);
      schema.priceSpecification = products.map(product => this.generateProductSchema(product));
    }

    return schema;
  }

  /**
   * Generate individual product schema for carousel
   */
  private generateProductSchema(product: PromotionCardProduct): object {
    const schema: Record<string, unknown> = {
      '@type': 'Product',
      name: product.name,
      image: product.imageUrl,
      url: product.url,
      offers: {
        '@type': 'Offer',
        price: product.price,
        priceCurrency: product.currency || product.priceCurrency || 'USD',
      },
    };

    if (product.description) {
      schema.description = product.description;
    }

    // Add discount information
    if (product.discount) {
      const offer = schema.offers as Record<string, unknown>;
      if (product.discount.type === 'percentage') {
        offer.discount = `${product.discount.value}%`;
      } else {
        offer.discount = product.discount.value;
      }
    }

    return schema;
  }

  /**
   * Generate Go-to action schema
   */
  private generateGoToActionSchema(action: NonNullable<GmailAnnotationConfig['goToAction']>): object {
    return {
      '@context': 'https://schema.org',
      '@type': 'ViewAction',
      name: action.name,
      url: action.url,
      ...(action.description && { description: action.description }),
    };
  }

  /**
   * Generate complete HTML with embedded JSON-LD
   */
  private generateHtml(jsonLd: string): string {
    return `<script type="application/ld+json">
${jsonLd}
</script>`;
  }

  /**
   * Validate annotation configuration
   */
  validateConfig(config: GmailAnnotationConfig): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Validate logo URL
    if (config.logoUrl && !this.isValidUrl(config.logoUrl)) {
      errors.push('Logo URL is not a valid HTTPS URL');
    }

    // Validate featured image
    if (config.featuredImageUrl) {
      if (!this.isValidUrl(config.featuredImageUrl)) {
        errors.push('Featured image URL is not a valid HTTPS URL');
      }
    } else {
      warnings.push('No featured image provided - consider adding one for better preview');
    }

    // Validate deal expiration
    if (config.deal?.availabilityEnds) {
      if (config.deal.availabilityEnds < new Date()) {
        errors.push('Deal expiration date is in the past');
      }
    }

    // Validate products
    if (config.products) {
      if (config.products.length > this.MAX_PRODUCTS) {
        warnings.push(`Only first ${this.MAX_PRODUCTS} products will be shown in carousel`);
      }

      config.products.forEach((product, index) => {
        if (!product.name) {
          errors.push(`Product ${index + 1}: name is required`);
        }
        if (!this.isValidUrl(product.imageUrl)) {
          errors.push(`Product ${index + 1}: invalid image URL`);
        }
        if (product.price < 0) {
          errors.push(`Product ${index + 1}: price must be positive`);
        }
        if (!product.currency) {
          warnings.push(`Product ${index + 1}: no currency specified, defaulting to USD`);
        }
      });
    }

    // Validate go-to action
    if (config.goToAction) {
      if (!config.goToAction.name) {
        errors.push('Go-to action name is required');
      }
      if (!this.isValidUrl(config.goToAction.url)) {
        errors.push('Go-to action URL is not valid');
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Validate URL format
   */
  private isValidUrl(url: string): boolean {
    try {
      const parsed = new URL(url);
      return parsed.protocol === 'https:';
    } catch {
      return false;
    }
  }

  /**
   * Generate preview badge HTML for testing
   */
  generatePreviewBadge(config: GmailAnnotationConfig): string {
    if (!config.deal) {
      return '';
    }

    const badgeStyle = `
      display: inline-block;
      background: #1a73e8;
      color: white;
      padding: 4px 12px;
      border-radius: 4px;
      font-family: Arial, sans-serif;
      font-size: 12px;
      font-weight: 500;
    `;

    let badgeContent = config.deal.discountDescription;
    if (config.deal.discountCode) {
      badgeContent += ` - Code: ${config.deal.discountCode}`;
    }

    return `<span style="${badgeStyle}">${badgeContent}</span>`;
  }

  /**
   * Get image recommendations
   */
  getImageRecommendations(): {
    featuredImage: { width: number; height: number; maxSizeKb: number };
    productImage: { width: number; height: number; maxSizeKb: number };
    logo: { width: number; height: number; maxSizeKb: number };
  } {
    return {
      featuredImage: {
        width: this.RECOMMENDED_IMAGE_WIDTH,
        height: this.RECOMMENDED_IMAGE_HEIGHT,
        maxSizeKb: this.MAX_IMAGE_SIZE_KB,
      },
      productImage: {
        width: 250,
        height: 250,
        maxSizeKb: 30,
      },
      logo: {
        width: 200,
        height: 200,
        maxSizeKb: 20,
      },
    };
  }

  /**
   * Generate a complete promotion email annotation
   */
  generatePromotionEmailAnnotations(params: {
    organizationName: string;
    organizationUrl: string;
    logoUrl: string;
    discountPercent: number;
    discountCode: string;
    expiresAt: Date;
    featuredImageUrl: string;
    ctaText: string;
    ctaUrl: string;
    products?: PromotionCardProduct[];
  }): GmailAnnotationResult {
    return this.generateAnnotations({
      organization: {
        name: params.organizationName,
        url: params.organizationUrl,
        logoUrl: params.logoUrl,
      },
      logoUrl: params.logoUrl,
      featuredImageUrl: params.featuredImageUrl,
      deal: {
        discountDescription: `${params.discountPercent}% off`,
        discountCode: params.discountCode,
        availabilityEnds: params.expiresAt,
      },
      goToAction: {
        name: params.ctaText,
        url: params.ctaUrl,
      },
      products: params.products,
    });
  }
}

/**
 * Factory function
 */
export function createGmailAnnotationsService(): GmailAnnotationsService {
  return new GmailAnnotationsService();
}

export default GmailAnnotationsService;
