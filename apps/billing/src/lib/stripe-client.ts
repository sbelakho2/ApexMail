/**
 * Stripe Client - Singleton instance with proper typing
 */

import Stripe from 'stripe';
import { getConfig } from '../config.js';
import { STRIPE_TIMEOUT_MS } from './constants.js';

let stripeClient: Stripe | null = null;

export function getStripe(): Stripe {
  if (!stripeClient) {
    const config = getConfig();
    stripeClient = new Stripe(config.STRIPE_SECRET_KEY, {
      apiVersion: '2023-10-16',
      typescript: true,
      appInfo: {
        name: 'ApexMail',
        version: '1.0.0',
        url: 'https://apexmail.ee',
      },
      maxNetworkRetries: 3,
      timeout: STRIPE_TIMEOUT_MS,
    });
  }
  return stripeClient;
}

/**
 * Reset stripe client (for testing)
 */
export function resetStripeClient(): void {
  stripeClient = null;
}

/**
 * Alias for getStripe for backward compatibility
 */
export const getStripeClient = getStripe;
