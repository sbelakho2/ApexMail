(() => {
  "use strict";

  document.documentElement.setAttribute("data-js", "true");

  const banner = document.getElementById("cookie-consent-banner");
  const buttons = Array.from(document.querySelectorAll("[data-cookie-consent-choice]"));
  const consentCookie = banner?.dataset.cookieConsentCookieName || "apexmail_cookie_consent";
  const analyticsEnabled = banner?.dataset.analyticsEnabled === "true";
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

  function activateAnalytics() {
    // Unshield the Plausible-compatible analytics script
    const shielded = document.getElementById("apex-analytics");
    if (shielded && shielded.getAttribute("type") === "text/plain") {
      shielded.setAttribute("type", "text/javascript");
      // Re-create the script element to trigger execution
      const newScript = document.createElement("script");
      for (const attr of shielded.attributes) {
        if (attr.name !== "type" && attr.name !== "id") {
          newScript.setAttribute(attr.name, attr.value);
        }
      }
      newScript.src = shielded.src;
      newScript.id = "apex-analytics";
      newScript.dataset.analyticsActivated = "true";
      shielded.parentNode?.replaceChild(newScript, shielded);
    }

    // Legacy pixel support (backward compat with analytics_pixel_url)
    const pixelUrl = banner?.dataset.analyticsPixelUrl;
    if (pixelUrl && !document.querySelector('[data-analytics-pixel="configured"]')) {
      const pixel = document.createElement("img");
      pixel.src = pixelUrl;
      pixel.alt = "";
      pixel.width = 1;
      pixel.height = 1;
      pixel.loading = "lazy";
      pixel.referrerPolicy = "no-referrer-when-downgrade";
      pixel.dataset.analyticsPixel = "configured";
      // Use standard 1x1 transparent pixel approach - no visibility hacks
      pixel.style.position = "absolute";
      pixel.style.width = "1px";
      pixel.style.height = "1px";
      pixel.style.opacity = "0";
      pixel.style.pointerEvents = "none";
      document.body.appendChild(pixel);
    }
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
    if (choice?.analytics && analyticsEnabled) {
      activateAnalytics();
    }
  }

  const dropdownCloseTimers = new WeakMap();

  function closeDropdown(toggle) {
    const menu = toggle.parentElement?.querySelector("[data-dropdown-menu]");
    if (!menu) {
      return;
    }

    toggle.setAttribute("aria-expanded", "false");
    toggle.dataset.state = "closed";
    menu.classList.add("hidden");
  }

  function closeAllDropdowns(exceptToggle = null) {
    document.querySelectorAll("[data-dropdown-toggle]").forEach((toggle) => {
      if (exceptToggle && toggle === exceptToggle) {
        return;
      }
      closeDropdown(toggle);
    });
  }

  function openDropdown(toggle, options = {}) {
    const { focusFirstItem = false } = options;
    const menu = toggle.parentElement?.querySelector("[data-dropdown-menu]");
    if (!menu) {
      return;
    }

    toggle.setAttribute("aria-expanded", "true");
    toggle.dataset.state = "open";
    menu.classList.remove("hidden");

    if (focusFirstItem) {
      window.setTimeout(() => menu.querySelector("[role=menuitem]")?.focus(), 0);
    }

    const dropdown = toggle.closest("[data-dropdown]");
    if (dropdown) {
      const handler = (event) => handleDropdownKeydown(event, menu, toggle);
      menu.addEventListener("keydown", handler, { once: true });
      dropdown.addEventListener(
        "focusout",
        () => {
          menu.removeEventListener("keydown", handler);
        },
        { once: true }
      );
    }
  }

  function clearDropdownCloseTimer(dropdown) {
    const timer = dropdownCloseTimers.get(dropdown);
    if (!timer) {
      return;
    }
    window.clearTimeout(timer);
    dropdownCloseTimers.delete(dropdown);
  }

  function scheduleDropdownClose(dropdown, toggle) {
    clearDropdownCloseTimer(dropdown);
    const timer = window.setTimeout(() => {
      closeDropdown(toggle);
      dropdownCloseTimers.delete(dropdown);
    }, 150);
    dropdownCloseTimers.set(dropdown, timer);
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

  function handleDropdownKeydown(event, dropdown, toggle) {
    const items = dropdown.querySelectorAll('[role="menuitem"]:not([hidden])');
    const currentIndex = Array.from(items).indexOf(document.activeElement);

    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault();
        const nextIndex = currentIndex < items.length - 1 ? currentIndex + 1 : 0;
        items[nextIndex]?.focus();
        break;
      case 'ArrowUp':
        event.preventDefault();
        const prevIndex = currentIndex > 0 ? currentIndex - 1 : items.length - 1;
        items[prevIndex]?.focus();
        break;
      case 'Escape':
        event.preventDefault();
        closeAllDropdowns();
        toggle?.focus();
        break;
      case 'Home':
        event.preventDefault();
        items[0]?.focus();
        break;
      case 'End':
        event.preventDefault();
        items[items.length - 1]?.focus();
        break;
    }
  }

  function trapFocus(element, event) {
    const focusable = element.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    if (event.key === 'Tab') {
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    }
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
        openDropdown(toggle, { focusFirstItem: true });
      }
      return;
    }

    if (!event.target.closest("[data-dropdown]")) {
      closeAllDropdowns();
    }
  });

  document.querySelectorAll("[data-dropdown]").forEach((dropdown) => {
    const toggle = dropdown.querySelector("[data-dropdown-toggle]");
    if (!toggle) {
      return;
    }

    dropdown.addEventListener("mouseenter", () => {
      clearDropdownCloseTimer(dropdown);
      closeAllDropdowns(toggle);
      openDropdown(toggle);
    });

    dropdown.addEventListener("mouseleave", () => {
      scheduleDropdownClose(dropdown, toggle);
    });

    dropdown.addEventListener("focusin", () => {
      clearDropdownCloseTimer(dropdown);
      closeAllDropdowns(toggle);
      openDropdown(toggle);
    });

    dropdown.addEventListener("focusout", (event) => {
      const next = event.relatedTarget;
      if (next && dropdown.contains(next)) {
        return;
      }
      scheduleDropdownClose(dropdown, toggle);
    });
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
    if (storedChoice.analytics && analyticsEnabled) {
      activateAnalytics();
    }
  }

  // ── Cookie Consent Focus Trap ─────────────────────────────
  const consentBanner = document.querySelector("[data-focus-trap=\"true\"]");
  if (consentBanner) {
    consentBanner.addEventListener("keydown", (event) => {
      trapFocus(consentBanner, event);
    });
  }

  // ── Header Scroll Effect ─────────────────────────────────
  const siteHeader = document.getElementById("site-header");
  if (siteHeader) {
    const updateHeader = () => {
      if (window.scrollY > 20) {
        siteHeader.classList.remove("border-transparent");
        siteHeader.classList.add("bg-white/95", "backdrop-blur-md", "border-surface-200", "shadow-premium-sm");
      } else {
        siteHeader.classList.remove("border-transparent", "shadow-premium-sm");
        siteHeader.classList.add("bg-white/95", "backdrop-blur-md", "border-surface-200");
      }
    };
    window.addEventListener("scroll", updateHeader, { passive: true });
    updateHeader();
  }

  // ── Back to Top ──────────────────────────────────────────
  const backToTop = document.getElementById("back-to-top");
  if (backToTop) {
    backToTop.setAttribute("data-back-to-top", "true");
    const updateBackToTop = () => {
      if (window.scrollY > 400) {
        backToTop.classList.remove("hidden", "opacity-0");
        backToTop.classList.add("opacity-100");
      } else {
        backToTop.classList.add("opacity-0");
        setTimeout(() => {
          if (window.scrollY <= 400) {
            backToTop.classList.add("hidden");
          }
        }, 300);
      }
    };
    window.addEventListener("scroll", updateBackToTop, { passive: true });
    updateBackToTop();

    backToTop.addEventListener("click", (e) => {
      e.preventDefault();
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }
})();
