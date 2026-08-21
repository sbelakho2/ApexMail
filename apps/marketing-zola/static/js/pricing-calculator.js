/* ApexMail pricing calculator (external file — CSP script-src 'self').
 * Logic is the former inline island script, unchanged except that the
 * pricing catalog is read from #apexmail-calculator[data-pricing].
 */

(function () {
  'use strict';

  // Pricing data injected from data/pricing.json via Zola load_data (audit 2.1).
  // Pricing data comes from the #apexmail-calculator data-pricing
  // attribute (HTML-escaped JSON) — keeps this file CSP-clean and
  // identical across builds.
  var host = document.getElementById('apexmail-calculator');
  if (!host) return;
  var PRICING = JSON.parse(host.getAttribute('data-pricing'));
  var plans = PRICING.plans.map(function (p) {
    return {
      name: p.name,
      monthlyPrice: p.monthly_price,
      annualPricePerMonth: p.annual_price_per_month,
      includedVolume: p.included_volume,
      overagePer1K: p.overage_per_1k,
      includedIPs: p.included_ips,
      dedicatedIPAddOnAvailable: p.dedicated_ip_addon_available,
      includedDomains: p.included_domains,
      includedUsers: p.included_users,
      support: p.support
    };
  });
  var IP_COST = PRICING.ip_cost;
  var CCY = PRICING.currency_symbol;

  function fmtCurrency(n) {
    if (typeof n !== 'number' || Number.isNaN(n)) return '\u2014';
    return CCY + n.toLocaleString('en-US', { minimumFractionDigits: 0, maximumFractionDigits: 0 });
  }
  function fmtCurrency2(n) {
    if (typeof n !== 'number' || Number.isNaN(n)) return '\u2014';
    return CCY + n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }
  function fmtPricePer1K(n) {
    if (typeof n !== 'number' || Number.isNaN(n) || n === 0) return '\u2014';
    return CCY + n.toFixed(2);
  }
  function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

  function recommendPlan(volume) {
    for (var i = 0; i < plans.length; i++) {
      if (volume <= plans[i].includedVolume) return i;
    }
    return plans.length - 1;
  }
  function calcDedicatedIPCost(plan, requestedIPs) {
    if (!plan.dedicatedIPAddOnAvailable) return 0;
    if (requestedIPs <= plan.includedIPs) return 0;
    return (requestedIPs - plan.includedIPs) * IP_COST;
  }
  function calcOverage(plan, volume) {
    if (plan.overagePer1K === null) return 0;
    var over = Math.max(0, volume - plan.includedVolume);
    // Match billing-service `calculate_overage_cost`: overage at the plan's
    // per-1K rate, rounded up to the nearest cent.
    return Math.ceil(over * plan.overagePer1K / 10) / 100;
  }

  function calcNextPlanCrossover(planIndex, volume, isAnnual, ipCost) {
    if (planIndex >= plans.length - 1) return null;
    var current = plans[planIndex];
    var next = plans[planIndex + 1];
    var currentBase = isAnnual ? current.annualPricePerMonth : current.monthlyPrice;
    var nextBase = isAnnual ? next.annualPricePerMonth : next.monthlyPrice;
    var currentOverage = calcOverage(current, volume);
    var currentTotal = currentBase + currentOverage + ipCost;
    var nextOverageAtCurrentVolume = calcOverage(next, volume);
    var nextIPCost = calcDedicatedIPCost(next, requestedIPs());
    var nextTotal = nextBase + nextOverageAtCurrentVolume + nextIPCost;
    if (nextTotal < currentTotal && volume <= next.includedVolume * 1.5) {
      return { volume: next.includedVolume + 1000, save: currentTotal - nextTotal };
    }
    var breakEvenVolume = null;
    if (current.overagePer1K !== null) {
      for (var v = current.includedVolume + 1000; v <= next.includedVolume + 100000; v += 1000) {
        var cO = calcOverage(current, v);
        var nO = calcOverage(next, v);
        var cT = currentBase + cO + ipCost;
        var nT = nextBase + nO + nextIPCost;
        if (nT <= cT) { breakEvenVolume = v; break; }
      }
    }
    return { volume: breakEvenVolume || (next.includedVolume + 1000), save: null };
  }

  function domainsOk(plan, domains) { return plan.includedDomains < 0 || domains <= plan.includedDomains; }
  function usersOk(plan, users) { return plan.includedUsers < 0 || users <= plan.includedUsers; }
  function dedicatedIPsOk(plan, requestedIPs) { return requestedIPs === 0 || plan.dedicatedIPAddOnAvailable; }
  function supportOk(plan, support) {
    var ranks = { community: 0, email: 1, priority: 2, dedicated: 3 };
    return (ranks[plan.support] || 0) >= (ranks[support] || 0);
  }

  function el(id) { return document.getElementById(id); }
  function requestedIPs() { return clamp(parseInt(el('calc-dedicated-ips').value, 10) || 0, 0, 100); }
  function requestedDomains() { return clamp(parseInt(el('calc-domains').value, 10) || 1, 1, 1000); }
  function requestedUsers() { return clamp(parseInt(el('calc-team-users').value, 10) || 1, 1, 5000); }
  function requestedSupport() { return el('calc-support').value; }

  function validateConstraints(planIndex, requestedIPs, domains, users, support) {
    var warnings = [];
    var plan = plans[planIndex];
    if (!domainsOk(plan, domains)) warnings.push('Domains (' + domains + ') exceed ' + plan.name + ' limit (' + plan.includedDomains + '). Upgrade to a higher tier.');
    if (!usersOk(plan, users)) warnings.push('Team users (' + users + ') exceed ' + plan.name + ' limit (' + plan.includedUsers + '). Upgrade to a higher tier.');
    if (!dedicatedIPsOk(plan, requestedIPs)) warnings.push('Dedicated IPs require Pro or a higher plan.');
    if (!supportOk(plan, support)) warnings.push('Support level "' + support + '" requires a higher plan (' + plan.name + ' provides "' + plan.support + '").');
    return warnings;
  }

  function render(volume, isAnnual, ipReq, domains, users, support) {
    var planIndex = recommendPlan(volume);
    var plan = plans[planIndex];
    while (planIndex < plans.length - 1 &&
           (!dedicatedIPsOk(plan, ipReq) || !domainsOk(plan, domains) || !usersOk(plan, users) || !supportOk(plan, support))) {
      planIndex++;
      plan = plans[planIndex];
    }
    var basePrice = isAnnual ? plan.annualPricePerMonth : plan.monthlyPrice;
    var overageCost = calcOverage(plan, volume);
    var ipCost = calcDedicatedIPCost(plan, ipReq);
    var monthlyTotal = basePrice + overageCost + ipCost;
    var annualTotal = monthlyTotal * 12;
    var effectivePer1K = volume > 0 ? (monthlyTotal / volume * 1000) : 0;
    var overageVolume = Math.max(0, volume - plan.includedVolume);

    el('calc-result-plan').textContent = plan.name;
    el('calc-result-included').textContent = plan.includedVolume.toLocaleString();
    el('calc-result-overage').textContent = overageVolume.toLocaleString();
    el('calc-result-base').textContent = fmtCurrency(basePrice) + '/mo';
    el('calc-result-ip').textContent = ipCost > 0 ? fmtCurrency(ipCost) + '/mo' : CCY + '0';
    el('calc-result-monthly').textContent = fmtCurrency2(monthlyTotal) + '/mo';
    el('calc-result-annual').textContent = fmtCurrency2(annualTotal) + '/yr';
    el('calc-result-per1k').textContent = fmtPricePer1K(effectivePer1K);
    el('calc-result-domains').textContent = plan.includedDomains < 0 ? 'Unlimited' : String(plan.includedDomains);
    el('calc-result-users').textContent = plan.includedUsers < 0 ? 'Unlimited' : String(plan.includedUsers);
    el('calc-result-support').textContent = plan.support;

    if (overageCost > 0) {
      el('calc-result-overage-val').textContent = fmtCurrency2(overageCost) + '/mo';
      el('calc-result-overage-val').parentElement.removeAttribute('hidden');
    } else {
      el('calc-result-overage-val').parentElement.setAttribute('hidden', '');
    }

    var nextPlanEl = el('calc-next-plan');
    var nextPlanText = el('calc-next-plan-text');
    var crossover = calcNextPlanCrossover(planIndex, volume, isAnnual, ipCost);
    if (crossover && crossover.volume > volume) {
      var next = plans[planIndex + 1];
      var msg = 'Upgrade to ' + next.name + ' at ~' + crossover.volume.toLocaleString() + ' emails/month. ';
      msg += next.name + ' base: ' + fmtCurrency(isAnnual ? next.annualPricePerMonth : next.monthlyPrice) + '/mo with ' + next.includedVolume.toLocaleString() + ' included.';
      if (crossover.save !== null && crossover.save > 0) {
        msg += ' Estimated savings: ' + fmtCurrency2(crossover.save) + '/mo at crossover volume.';
      }
      nextPlanText.textContent = msg;
      nextPlanEl.removeAttribute('hidden');
    } else if (planIndex === plans.length - 1 && volume > plan.includedVolume) {
      nextPlanText.textContent = 'Volume exceeds ' + plan.includedVolume.toLocaleString() + '/month. Contact sales for Enterprise custom pricing, Dedicated Tenant, or BYOC options.';
      nextPlanEl.removeAttribute('hidden');
    } else if (planIndex === plans.length - 1) {
      nextPlanText.textContent = 'Enterprise plan covers ' + plan.includedVolume.toLocaleString() + ' emails/mo with 10 included IPs, unlimited domains/users, and named CSM. Contact sales for custom scoping.';
      nextPlanEl.removeAttribute('hidden');
    } else {
      nextPlanEl.setAttribute('hidden', '');
    }

    var warnEl = el('calc-warnings');
    var warnText = el('calc-warnings-text');
    var warnings = validateConstraints(planIndex, ipReq, domains, users, support);
    if (warnings.length > 0) {
      warnText.textContent = warnings.join(' ');
      warnEl.removeAttribute('hidden');
    } else {
      warnEl.setAttribute('hidden', '');
    }
  }

  var state = { volume: 50000, isAnnual: false, dedicatedIPs: 0, domains: 2, users: 3, support: 'email' };

  function update() {
    render(state.volume, state.isAnnual, requestedIPs(), requestedDomains(), requestedUsers(), requestedSupport());
  }
  function syncFromSlider() { state.volume = parseInt(el('calc-volume-slider').value, 10); el('calc-volume').value = state.volume; update(); }
  function syncFromInput() { state.volume = clamp(parseInt(el('calc-volume').value, 10) || 0, 0, 100000000); el('calc-volume-slider').value = state.volume; update(); }
  function syncDedicatedIPs() { state.dedicatedIPs = requestedIPs(); update(); }
  function syncDomains() { state.domains = requestedDomains(); update(); }
  function syncUsers() { state.users = requestedUsers(); update(); }
  function syncSupport() { state.support = requestedSupport(); update(); }
  function syncPeakDaily() {
    var peak = clamp(parseInt(el('calc-peak-daily').value, 10) || 0, 0, 50000000);
    state.volume = Math.max(state.volume, peak * 20);
    el('calc-volume').value = state.volume;
    el('calc-volume-slider').value = state.volume;
    update();
  }
  function setPeriod(isAnnual) {
    state.isAnnual = isAnnual;
    if (isAnnual) {
      el('calc-monthly-btn').className = 'px-4 py-2 text-xs font-bold tracking-[0.05em] uppercase text-surface-500 hover:text-surface-950 transition-colors';
      el('calc-monthly-btn').setAttribute('aria-checked', 'false');
      el('calc-annual-btn').className = 'px-4 py-2 text-xs font-bold tracking-[0.05em] uppercase bg-surface-950 text-white transition-colors';
      el('calc-annual-btn').setAttribute('aria-checked', 'true');
    } else {
      el('calc-monthly-btn').className = 'px-4 py-2 text-xs font-bold tracking-[0.05em] uppercase bg-surface-950 text-white transition-colors';
      el('calc-monthly-btn').setAttribute('aria-checked', 'true');
      el('calc-annual-btn').className = 'px-4 py-2 text-xs font-bold tracking-[0.05em] uppercase text-surface-500 hover:text-surface-950 transition-colors';
      el('calc-annual-btn').setAttribute('aria-checked', 'false');
    }
    update();
  }

  el('calc-volume-slider').addEventListener('input', syncFromSlider);
  el('calc-volume').addEventListener('change', syncFromInput);
  el('calc-volume').addEventListener('input', function () { state.volume = clamp(parseInt(el('calc-volume').value, 10) || 0, 0, 100000000); });
  el('calc-dedicated-ips').addEventListener('input', syncDedicatedIPs);
  el('calc-domains').addEventListener('input', syncDomains);
  el('calc-team-users').addEventListener('input', syncUsers);
  el('calc-support').addEventListener('change', syncSupport);
  el('calc-peak-daily').addEventListener('change', syncPeakDaily);
  el('calc-monthly-btn').addEventListener('click', function () { setPeriod(false); });
  el('calc-annual-btn').addEventListener('click', function () { setPeriod(true); });

  update();
})();
