(() => {
  "use strict";

  const banner = document.getElementById("cookie-consent-banner");
  const buttons = Array.from(document.querySelectorAll("[data-cookie-consent-choice]"));
  const consentCookie = banner?.dataset.cookieConsentCookieName || "apexmail_cookie_consent";
  const analyticsUrl = banner?.dataset.analyticsPixelUrl || "";
  const consentChoices = buttons.map((button) => ({
    value: button.dataset.cookieConsentValue || "",
    analytics: button.dataset.cookieConsentAnalytics === "true",
  }));

  function readConsent() {
    const prefix = `${consentCookie}=`;
    const entry = document.cookie
      .split(";")
      .map((part) => part.trim())
      .find((part) => part.startsWith(prefix));
    return entry ? decodeURIComponent(entry.slice(prefix.length)) : "";
  }

  function writeConsent(value) {
    document.cookie = `${consentCookie}=${encodeURIComponent(value)}; Path=/; Max-Age=31536000; SameSite=Lax`;
  }

  function injectAnalyticsPixel() {
    if (!analyticsUrl || document.querySelector('[data-analytics-pixel="configured"]')) {
      return;
    }

    const pixel = document.createElement("img");
    pixel.src = analyticsUrl;
    pixel.alt = "";
    pixel.width = 1;
    pixel.height = 1;
    pixel.loading = "lazy";
    pixel.referrerPolicy = "no-referrer-when-downgrade";
    pixel.style.position = "absolute";
    pixel.style.width = "0";
    pixel.style.height = "0";
    pixel.dataset.analyticsPixel = "configured";
    document.body.appendChild(pixel);
  }

  function hideBanner() {
    if (banner) {
      banner.hidden = true;
    }
  }

  function applyConsent(value) {
    writeConsent(value);
    hideBanner();

    const choice = consentChoices.find((entry) => entry.value === value);
    if (choice?.analytics) {
      injectAnalyticsPixel();
    }
  }

  function closeAllDropdowns() {
    document.querySelectorAll("[data-dropdown-toggle]").forEach((toggle) => {
      toggle.setAttribute("aria-expanded", "false");
      toggle.dataset.state = "closed";
      toggle.parentElement?.querySelector("[data-dropdown-menu]")?.classList.add("hidden");
    });
  }

  function openDropdown(toggle) {
    const menu = toggle.parentElement?.querySelector("[data-dropdown-menu]");
    if (!menu) {
      return;
    }

    toggle.setAttribute("aria-expanded", "true");
    toggle.dataset.state = "open";
    menu.classList.remove("hidden");
    window.setTimeout(() => menu.querySelector("[role=menuitem]")?.focus(), 0);
  }

  function moveMenuFocus(currentItem, direction) {
    const items = Array.from(currentItem.closest("[role=menu]")?.querySelectorAll("[role=menuitem]") || []);
    const currentIndex = items.indexOf(currentItem);
    if (currentIndex === -1 || items.length === 0) {
      return;
    }

    const nextIndex = (currentIndex + direction + items.length) % items.length;
    items[nextIndex].focus();
  }

  function syncMobileMenuAria() {
    const mobileMenuState = document.getElementById("nav-toggle");
    const mobileMenuToggle = document.getElementById("mobile-menu-toggle");
    if (!mobileMenuState || !mobileMenuToggle) {
      return;
    }
    mobileMenuToggle.setAttribute("aria-expanded", mobileMenuState.checked ? "true" : "false");
  }

  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      const value = button.dataset.cookieConsentValue;
      if (value) {
        applyConsent(value);
      }
    });
  });

  document.addEventListener("click", (event) => {
    const toggle = event.target.closest("[data-dropdown-toggle]");
    if (toggle) {
      event.preventDefault();
      const isOpen = toggle.getAttribute("aria-expanded") === "true";
      closeAllDropdowns();
      if (!isOpen) {
        openDropdown(toggle);
      }
      return;
    }

    if (!event.target.closest("[data-dropdown]")) {
      closeAllDropdowns();
    }
  });

  document.addEventListener("keydown", (event) => {
    const menuItem = event.target.closest("[role=menuitem]");
    if (menuItem) {
      if (event.key === "ArrowDown") {
        event.preventDefault();
        moveMenuFocus(menuItem, 1);
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        moveMenuFocus(menuItem, -1);
      } else if (event.key === "Home") {
        event.preventDefault();
        menuItem.closest("[role=menu]")?.querySelector("[role=menuitem]")?.focus();
      } else if (event.key === "End") {
        event.preventDefault();
        const items = menuItem.closest("[role=menu]")?.querySelectorAll("[role=menuitem]");
        items?.[items.length - 1]?.focus();
      } else if (event.key === "Escape") {
        event.preventDefault();
        const toggle = menuItem.closest("[data-dropdown]")?.querySelector("[data-dropdown-toggle]");
        closeAllDropdowns();
        toggle?.focus();
      }
      return;
    }

    if (event.key === "Escape") {
      const openDropdownToggle = document.querySelector('[data-dropdown-toggle][aria-expanded="true"]');
      if (openDropdownToggle) {
        event.preventDefault();
        closeAllDropdowns();
        openDropdownToggle.focus();
        return;
      }

      const mobileMenuState = document.getElementById("nav-toggle");
      if (mobileMenuState?.checked) {
        mobileMenuState.checked = false;
        mobileMenuState.dispatchEvent(new Event("change", { bubbles: true }));
      }
    }
  });

  const mobileMenuState = document.getElementById("nav-toggle");
  const mobileMenuToggle = document.getElementById("mobile-menu-toggle");
  if (mobileMenuState && mobileMenuToggle) {
    syncMobileMenuAria();
    mobileMenuState.addEventListener("change", syncMobileMenuAria);
    mobileMenuToggle.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") {
        return;
      }
      event.preventDefault();
      mobileMenuState.checked = !mobileMenuState.checked;
      mobileMenuState.dispatchEvent(new Event("change", { bubbles: true }));
    });
  }

  const existingConsent = readConsent();
  const storedChoice = consentChoices.find((entry) => entry.value === existingConsent);
  if (storedChoice) {
    hideBanner();
    if (storedChoice.analytics) {
      injectAnalyticsPixel();
    }
  }
})();