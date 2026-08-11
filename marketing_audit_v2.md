### Hyper-Detailed Design & Functional Audit: ApexMail Marketing Ecosystem (v2.0)

This document provides a pixel-perfect, logic-deep audit of the ApexMail marketing application (`apps/marketing-zola`). Every finding is categorized by severity and impact on the "Premium" brand identity.

---

### 1. Design Language & Pixel-Level Inconsistencies

#### 1.1 Primitive Radius Fragility
*   **Finding:** Systemic use of `rounded-sm` (2px radius) across all cards, buttons, inputs, and icon containers.
*   **Impact:** 2px is structurally "sharp" and evokes legacy industrial/commodity software. It conflicts with the `rounded-2xl` (12px) standard established in 'Design for Logins.png'.
*   **Fix:**
    *   **Cards:** Standardize on `rounded-2xl` (12px) for `apex-card`.
    *   **Buttons/Inputs:** Standardize on `rounded-lg` (8px).
    *   **Small Elements:** Standardize on `rounded-md` (6px) for badges and icon backgrounds.

#### 1.2 Shadow Depth & Ambient Occlusion
*   **Finding:** `shadow-premium` is a single-layer, high-blur shadow (`0 10px 30px rgba(0,0,0,0.08)`) that disappears on non-white surfaces.
*   **Impact:** Lack of visual hierarchy and depth.
*   **Fix:** Implement a multi-layered ambient occlusion shadow preset:
    *   `shadow-premium: 0 20px 50px -12px rgb(0 0 0 / 0.15), 0 0 1px rgb(0 0 0 / 0.05)`.
    *   `shadow-card-hover: 0 30px 60px -12px rgb(0 0 0 / 0.25)`.

#### 1.3 Typography Scale & Legibility
*   **Finding:**
    *   Labels and table headers use `text-[10px]` with `tracking-[0.2em]`.
    *   Buttons use `text-xs` (12px).
    *   Subtitles use `text-[17px]` (non-standard Tailwind).
*   **Impact:** Poor legibility for older users and lack of "weight" in primary CTAs.
*   **Fix:**
    *   **Eyebrow/Caps:** Upgrade to `text-xs` (12px) with `font-bold` and `tracking-[0.05em]`.
    *   **Buttons:** Standardize on `text-sm` (14px) with `font-semibold`.
    *   **Headers:** Standardize H1 at `text-5xl` (48px) and H2 at `text-4xl` (36px).

#### 1.4 Color Logic Desynchronization
*   **Finding:** Inconsistent use of brand colors. `bg-brand-50/20` used in tables, `bg-surface-950` used for buttons, and hardcoded `bg-green-500` for status dots.
*   **Impact:** Fragmentation of brand identity across pages.
*   **Fix:** Standardize all accent colors to use CSS variables: `--brand-primary`, `--brand-surface`, `--brand-text`.

---

### 2. Logic & Technical Audit (Every App/Interactive Code)

#### 2.1 Pricing Calculator (`pricing/calculator.html`)
*   **Finding:**
    *   **Logic Redundancy:** The `plans` array is hardcoded in JS (174-181) AND in a static HTML table in `pricing-calculator-island.html`.
    *   **Currency Hardcoding:** `fmtEUR` uses literal `\u20AC`.
    *   **DOM Manipulation:** `initResultsDOM` (424) builds the entire results UI using string concatenation in JS.
*   **Fix:**
    *   Move pricing data to `data/pricing.json`.
    *   Inject via Zola's `load_data` into templates for static tables.
    *   Inject via `JSON.parse` into the JS calculator for logic.
    *   Refactor `initResultsDOM` to use template cloning or pre-rendered shells to avoid layout shifts.

#### 2.2 Navigation & Dropdown Logic (`apexmail-site.js`)
*   **Finding:**
    *   **Brittle State:** `window.dropdowns` (12) tracks open states manually.
    *   **Timer Clamping:** `setTimeout` (15, 68) is used for closing delays without proper cleanup of pending timeouts.
    *   **Global Pollution:** Too many items attached to `window`.
*   **Fix:**
    *   Use a `Proxy` or `state` object for UI state management.
    *   Use `requestAnimationFrame` for transitions.
    *   Implement proper event delegation for all `data-dropdown` triggers.

#### 2.3 Analytics & Consent (`analytics.html`, `cookie-consent.html`)
*   **Finding:**
    *   **CSP Risk:** `apexmail-site.js` manually reconstructs script tags from `text/plain` templates (119-142). This will fail in modern strict CSP environments.
    *   **Small UI:** Consent banner uses `text-[10px]`.
*   **Fix:**
    *   Use a standardized `consent-manager.js` bridge.
    *   Increase typography for accessibility (14px base).
    *   Use `POST` to the analytics endpoint instead of pixel-loading where possible.

#### 2.4 Status API Bridge (`footer.html`)
*   **Finding:** Hardcoded `STATUS_API = 'https://apexmail.ee/api/status-data'`.
*   **Fix:** Inject via `{{ config.extra.api_url }}/status-data`.

---

### 3. Page-by-Page Pixel Audit

#### 3.1 Home Page
*   **Hero:** Logo is text-only. The "Terminal" mockup lacks winking mascot whimsy.
*   **Comparison Section:** Table uses manual `border-r` on cells, creating a "boxed" look that feels cheap.
*   **Integrations:** Icon grid uses `rounded-sm` which looks like generic 2010s UI.

#### 3.2 Pricing Page
*   **Plans Grid:** The toggle for Monthly/Annual has zero animation; it's an instant state flip.
*   **Calculator:** Result tiles are too small (`text-lg` for prices) given their importance.

#### 3.3 Comparison Pages (`/compare/*`)
*   **Architecture:** The `resend/index.md` file contains ~80 lines of raw Tailwind HTML.
*   **Finding:** Any design change to the "Win/Tie/Loss" indicator requires manual regex across all comparison files.
*   **Fix:** Create Tera macros for `comparison_row`, `win_indicator`, and `feature_category`.

#### 3.4 Compliance Page
*   **Hero:** The animated badges use `aspect-square` but have non-centered content if the label is long.

---

### 4. Branding & "Whimsy" (Mascot Integration)

#### 4.1 Logo Inconsistency
*   **Finding:** The header uses text-only `ApexMail`. The footer uses text-only `ApexMail`.
*   **Impact:** Fails to build brand recognition for the winking kiwi mascot.
*   **Fix:** Replace all header/footer logo spans with the winking `kiwi_shield` mascot as an inline SVG.

#### 4.2 Interactive Whimsy Points
*   **Hero Terminal:** Add a small SVG kiwi peeking from the top-right of the terminal on `hover:code`.
*   **Calculator:** If a user selects a volume that results in "60%+ savings," trigger a "sparkle" effect on the "You Save" badge (matching KiwiCaptcha success).

---

### 5. Developer Experience (DX) & Reliability

#### 5.1 Broken Links
*   **Finding:** 404 at `https://app.apexmail.ee/reset` in `quickstart/index.md`.
*   **Fix:** Correct to `/auth/forgot-password`.

#### 5.2 i18n Fragility
*   **Finding:** Templates are littered with `{% if i18n_data and i18n_data[l] ... %}`.
*   **Fix:** Standardize on `{{ trans(key="...", lang=l) }}` using Zola's native translation engine where possible, or a cleaner macro wrapper.

#### 5.3 Cachebusting
*   **Finding:** Font files are referenced without cachebusting in `input.css`.
*   **Fix:** Use `get_url(path=..., cachebust=true)` for all assets.

---

### 6. KiwiCaptcha Policy
*   **Constraint:** "KiwiCaptcha should go nowhere near marketing website!"
*   **Finding:** Currently absent, but logic for `auth-server` integration is present in `config.toml`.
*   **Enforcement:** Add a build-time check or `grep` in `Makefile` to ensure no `kiwicaptcha` scripts or assets are injected into the marketing build.

---

### 7. Summary of Required "Premium" Upgrades

| Feature | Current (Cheap) | Target (Premium) |
| :--- | :--- | :--- |
| **Border Radius** | 2px (`rounded-sm`) | 12px (`rounded-2xl`) |
| **Typography** | `Inter`, `text-xs` (12px) | `Inter`, `font-display`, `text-sm` (14px) |
| **Shadows** | Single-layer, flat | Multi-layer, ambient occlusion |
| **Mascot** | Absent (Text only) | Winking Kiwi Mascot (Inline SVG) |
| **Layouts** | Hardcoded HTML in MD | Macro-driven, semantic components |
| **State** | Brittle `window` globals | Centralized UI state / event bridge |
