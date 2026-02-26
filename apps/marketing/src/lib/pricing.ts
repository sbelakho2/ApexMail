export interface ApexMailPlanTier {
  name: 'Free' | 'Starter' | 'Pro' | 'Growth' | 'Scale' | 'Enterprise';
  maxMonthlyEmails: number;
  monthlyPrice: number;
}

export const APEXMAIL_PLAN_TIERS: ApexMailPlanTier[] = [
  { name: 'Free', maxMonthlyEmails: 3000, monthlyPrice: 0 },
  { name: 'Starter', maxMonthlyEmails: 50000, monthlyPrice: 25 },
  { name: 'Pro', maxMonthlyEmails: 150000, monthlyPrice: 65 },
  { name: 'Growth', maxMonthlyEmails: 500000, monthlyPrice: 150 },
  { name: 'Scale', maxMonthlyEmails: 2000000, monthlyPrice: 350 },
  { name: 'Enterprise', maxMonthlyEmails: Infinity, monthlyPrice: 800 },
];

export function getApexMailPlanForVolume(volume: number): ApexMailPlanTier {
  return APEXMAIL_PLAN_TIERS.find((tier) => volume <= tier.maxMonthlyEmails) ?? APEXMAIL_PLAN_TIERS[APEXMAIL_PLAN_TIERS.length - 1];
}

export function getApexMailBasePriceForVolume(volume: number): number {
  return getApexMailPlanForVolume(volume).monthlyPrice;
}