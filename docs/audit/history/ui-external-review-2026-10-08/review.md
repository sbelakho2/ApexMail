analyze fully to fully and precisely understand then fix very very rigorously and fully then scan to make sure you fixed everything fully:

Overall assessment
ApexMail already has a distinctive visual direction. It does not need a new aesthetic.

The strongest parts of the current direction are:

Red/near-black branding on neutral zinc surfaces.
Border-led, restrained product layouts.
Inter for operational interfaces.
Fraunces for editorial marketing headings.
JetBrains Mono for technical information, identifiers, and financial figures.
The existing arch-shaped containers, concentric focus treatment, technical slots, receipts, and small geometric details.
Native server-rendered navigation and forms instead of unnecessary client-side machinery.
The main obstacle to a genuinely premium experience is not insufficient decoration. It is inconsistency between:

What a control promises.
What the rendered page exposes.
What the handler actually performs.
What the worker or service ultimately does.
What the documentation and marketing say.
The right direction is to make the existing Apex language calmer, more coherent, and more dependable—not more elaborate.

1. Scope, evidence, and limits
The audit covered the UI implementation across:

Rust customer-console and control-plane rendering.
Shared primitives, shells, charts, tokens, and stylesheet sources.
All 71 Zola HTML templates.
The 177 marketing Markdown files, organized into 54 content families:
54 English files.
41 German files.
41 Spanish files.
41 French files.
Marketing catalogs, localization, assets, configuration, and serving boundaries.
Nine canonical CAPTCHA browser assets and their distribution mirrors.
Authentication/security emails.
Error pages.
Five PDF presentation templates and the actual PDF generation path.
UI manifests, regression gates, and fixture-generation infrastructure.
The principal Rust view file, leptos_views.rs, was read end-to-end; production views were reviewed in detail, while its embedded tests were reviewed more selectively.

Render validation
All 150 existing HTML fixtures were rendered using the current stylesheet assets at:

Mobile width: 390px.
Desktop width: 1440px.
Light theme.
Dark theme.
That produced 600 read-only render checks.

Results:

Check	Result
Documents with more or fewer than one main landmark	0
Documents with more or fewer than one top-level heading	0
Document-level horizontal overflow	0
Mobile/theme checks where the closed drawer intercepted content	172
These structural results do not establish full accessibility compliance, usable table scrolling, or successful authenticated workflows.

Important limitations
Backend files affecting UI were traced at relevant handlers/loaders; this is not a claim that every backend line in the repository received a full audit.
Existing fixtures are not equivalent to all populated production states.
No account creation, sending, billing, deletion, or other mutating flows were executed.
Other processes changed parts of the workspace during the audit. Affected findings were rechecked where visible, but this remains a review of an evolving working tree.
Generated CSS, goldens, and snapshots are treated as derivative artifacts—not independently designed screens.
“Defect” below means a source-established mismatch or directly observed rendering problem. “Refinement” means a recommended improvement, not a proven failure.
2. What must remain unchanged artistically
The original references—Correct Design.png and Design for Logins.png—establish the restrained product foundation. The current implementation adds its own arch/spiral technical language.

Preserve both the foundation and the implemented evolution.

Preserve
Neutral surfaces and clear borders.
Red as the recognizable brand/action accent.
Sparse, purposeful depth.
Inter in dashboards and forms.
Fraunces in marketing display typography.
Mono typography where the information is genuinely technical.
Arch geometry and concentric focus as recurring signatures.
Technical detail at a small scale, supporting—not dominating—the content.
Native browser interactions where they fit the server-rendered architecture.
Do not introduce
A new blue, purple, or gradient identity.
Glassmorphism throughout the product.
Heavy shadows on every panel.
Animated page transitions.
Decorative illustrations unrelated to the current system.
More badges, receipts, borders, or iconography merely to make pages “premium.”
A SPA conversion as a prerequisite for solving ordinary UX problems.
Custom ARIA widgets whose interaction behavior is not actually implemented.
Premium here should mean precision, confidence, and restraint.

3. Highest-priority fixes
These should precede cosmetic work.

Priority	Finding	Evidence and required correction
P1	Editing a campaign can use the create path	The full editor posts to the create endpoint even in edit mode. Separate create/update action selection and verify identity-preserving saves. See the leptos_views.rs:1329-1337, dispatch, and handlers.
P1	Scheduling copy contradicts executable behavior	The UI says scheduled campaigns wait for manual Start; the worker starts due scheduled campaigns. Correct the authorization wording before users schedule real sends. See leptos_views.rs:1337 and campaigns.rs:271-345.
P1	Closed mobile navigation blocks content	A closed disclosure still occupies a 320px-wide, full-height hit area. Put drawer dimensions/background/scrolling under the open state; the closed state should occupy only the summary control. See shell.rs:295-303 and globals.css:997-1008.
P1	Populated bulk tables emit nested forms	Row-delete forms are placed inside the bulk-action form. Use sibling forms with explicit form associations. See leptos_views.rs:1057-1073 and leptos_views.rs:1126-1140.
P1	Live settings rendering removes existing actions	Data-backed replacement pages can omit creation/invitation/registration/request forms present in handwritten counterparts. Compose live tables with their action forms instead of replacing the entire page body. See routing and data.rs:2531-2946.
P1	Domain Verify DNS targets the wrong route	The detail view generates a different POST path from the mounted browser handler. Correct the action target and add a rendered-form route test. See leptos_views.rs:547-556 and browser router.
P1	Template editing is not a coherent round trip	The editor starts blank, promises preservation on blank input, but Save rejects blank HTML; redirects also disagree with the implemented editor route. Load existing content and make save/redirect semantics consistent. See leptos_views.rs:4104-4122 and save handler.
P1	Native select options are not escaped at their rendering boundary	Tenant-controlled list/segment names are interpolated into option markup. Escape labels, values, IDs, and names in the primitive. See primitives.rs:551-574.
P1	Authored and compiled console styles have diverged	Essential recipes and changed tokens exist in the served artifact but not its input. Rebuilding can discard fixes. Restore one reproducible authority. See input, artifact, and development build.
P1	Translated quickstarts are empty	German, French, and Spanish have metadata but no tutorial body. Publish the actual guide or explicitly route to the English guide with a language notice. See DE, FR, and ES.
P1	Translated SLAs omit most substantive terms	They contain performance targets but omit most English scope, uptime, credits, exclusions, and claims content. Restore equivalent terms, not merely matching dates. See EN, DE, FR, and ES.
P1/P2	Failed-form replay can restore incorrect controls	Replay is not reliably confined to the matching form; checkbox defaults and existing attributes can survive. Render retained state structurally within the correct form and associate errors with controls. See rendering pipeline.
P1/P2	MFA QR interoperability risk	Mask formulas 1, 2, and 4 use transposed coordinates; the test decoder shares that implementation. Correct the formulas and validate with an independent decoder. See qr.rs:156-165.
P2	Placement detail ignores real results	Detail dispatch always uses the static waiting view. Wire the requested test’s results and explicit running/completed/failed states. See dispatch.
P2	Calculator slider is not authoritative	The slider and number field are independent; the handler reads the number field. Use one actual volume control under the no-script design. See calculator.html:40-46.
P2	Several public claims disagree with the catalog	Recurring Free volume, annual savings, dedicated-IP entitlements, and SDK availability diverge between pages. Correct them from shared data, not independent text edits. See pricing catalog.
P2	Delivered PDFs do not use the designed layouts	Typst templates exist, but the current renderer produces generic data-oriented output instead. Wire the intended presentation or label downloads accurately as exports. See compiler.rs:778-804.
No P0 incident was established by this read-only audit.

4. Global UI/UX recommendations
4.1 Establish one truthful page composition model
The most consequential architectural UX problem is the split between:

Handwritten page bodies.
Generic data-backed list bodies.
Fallback fixtures.
Actual handler-owned detail pages.
A polished page should not lose its creation controls merely because real data is available.

Use a consistent composition:

Page identity and short description.
Primary action.
Optional scope/time-window summary.
Relevant metrics.
Filters.
Data or state-specific content.
Pagination/export/secondary actions.
For forms, compose:

Resource/context summary.
Fields.
Inline guidance.
Error summary and field messages.
Consequence summary.
Primary submit and secondary return action.
Do not allow fallback and live implementations to become separate products.

4.2 Reduce implementation-exposing copy
Repeated statements such as:

“Nothing has been fabricated.”
“No scripts.”
“Plain form posts.”
“Signed outcome.”
“The store did not answer.”
Raw API paths inside disabled controls.
are useful for engineering review but too prominent for customers.

Replace them with user-centered wording:

Current tendency	Better user-facing direction
“Nothing has been fabricated here”	“Metrics will appear after your first send.”
“The store did not answer”	“This information is temporarily unavailable. Reload to try again.”
“No scripts—tick every row”	“Select the rows you want to remove.”
“JSON-only mutation…”	“This action is not available in the console.” Then provide appropriate documentation or implement the native form.
“Signed confirmation…”	Explain the resource and consequence, not the signature mechanism.
Retain technical detail in expandable help, API documentation, or diagnostic references.

Confidence is more premium than defensive explanation.

4.3 Make state language consistent
Every data surface needs a distinct presentation for:

First use.
Successful empty result.
Filtered zero matches.
Data unavailable.
Permission restriction.
Plan restriction.
Feature disabled.
Work in progress.
Completed.
Failed.
Stale information.
These must not collapse into one “Nothing here yet” block.

Recommended behavior
First use: contextual explanation and a real next action.
No matches: preserve filters and offer Clear filters.
Unavailable: retain page context; explain retry, not creation.
Restricted: explain why and who can resolve it.
Running: show the current phase and observation time.
Failed: show a safe recovery action and reference.
Stale: display last observed time; do not present it as current health.
Unknown values should be visually compact, but not silently ambiguous. A dash can work if the card or table clearly explains why it is unknown.

4.4 Strengthen action hierarchy
The current brand color can support both primary and destructive actions, but color alone cannot carry the distinction.

Use:

One primary action per local task.
Secondary outlined actions for navigation or alternate workflow.
Tertiary links for supporting actions.
Destructive actions with explicit verbs, context, and confirmation.
Disabled actions with a visible reason—not only a tooltip.
In dense operator tables, avoid equally emphasized clusters of Suspend, Impersonate, Delete, and View.

Prioritize the ordinary action; move consequential actions into deliberate, native workflows.

4.5 Keep the existing typography, but assign clearer jobs
Inter
Use for:

Product headings.
Navigation.
Forms.
Explanations.
Table labels.
Operational statuses.
Fraunces
Use for:

Marketing headlines.
Selected editorial section headings.
Not routine dashboard labels or data-heavy controls.
JetBrains Mono
Use for:

DNS values.
IDs.
API scopes.
Code.
Technical timestamps where appropriate.
Financial/numeric slots already using the technical visual language.
Avoid using uppercase mono labels for every sentence or making customer guidance feel like a machine log.

Hierarchy refinement
One dominant heading.
One concise subtitle.
Eyebrow only when it adds information.
Avoid breadcrumb → eyebrow → heading repeating the same noun three times.
Keep long descriptive copy out of tightly tracked uppercase styles.
Preserve tabular numerals for prices and metrics.
4.6 Preserve whitespace, eliminate accidental emptiness
There is a difference between restrained whitespace and a page that appears unfinished.

Refine:

Single-card hubs occupying large two-column grids.
Four-item marketing grids laid out as three plus an orphan.
Large title-to-content gaps without a compositional purpose.
Empty tables that provide no nearby action.
Broad cards containing only one short sentence.
Use the existing spacing contract from premium-experience-spec.md, but make its implementation match its stated rules.

Do not “solve” emptiness by adding decorative cards or fake metrics.

4.7 Keep depth selective
The border-led language is appropriate.

Recommendations:

Resting panels should remain calm.
Hover elevation should communicate actual interactivity.
Noninteractive cards should not look clickable merely because their shadow changes.
Dialogs/popovers may use stronger elevation.
Dark mode should rely on controlled surface and border separation—not indiscriminate black shadows.
The subtle contrast between dark canvas and dark card is not itself a text-accessibility failure.

4.8 Repair mobile behavior before tightening mobile layouts
The closed drawer interception is a real blocker.

After that:

Keep the menu trigger at its visible location in the focus order.
Keep account/workspace context discoverable on narrow screens.
Prevent fixed consent bars from covering focused content.
Let long action groups wrap or stack.
Make horizontal table regions explicitly discoverable and keyboard reachable.
Do not force feature descriptions into tiny two-column cards at every mobile width.
Test 200% zoom and larger text—not only nominal device widths.
A document with no horizontal overflow can still contain clipped or inaccessible content.

4.9 Native controls should remain native
The server-rendered approach is a strength when used consistently.

Use:

Native select.
Native checkbox/radio.
Native range only when its value actually controls the submitted result.
Native disclosure.
Real links for server-rendered tabs/sections.
Real confirmation pages/forms for consequential actions.
Do not export a custom switch, tablist, select, modal, or slider as “implemented” when it only renders a visual shell.

Adding data-keyboard-* attributes does not implement keyboard behavior.

4.10 Form feedback should feel composed, not appended
Required refinements:

Preserve values only in the intended form.
Replace previous selected/checked state rather than accumulating attributes.
Give error messages stable IDs.
Associate them with inputs, selects, and textareas.
Include a concise error summary with links to fields.
Use a redirect fragment for error-summary focus where compatible with the native flow.
Keep reveal-once secrets inside a stable receipt area.
Keep the action result adjacent to the action that caused it.
Do not place a successful secret receipt arbitrarily near the first closing container.

4.11 Scheduling needs explicit consent to send
Saving a scheduled campaign is not merely storing metadata if a worker will automatically send it.

The editor should communicate:

The exact send time.
Timezone.
Audience.
Whether the schedule is active.
Whether saving authorizes automatic sending.
How to cancel or return to draft.
Before submission, use a concise consequence summary such as:

Scheduled delivery will begin automatically at the selected time.

The exact wording must reflect the actual active worker configuration.

4.12 Separate preview from email-client fidelity
The sanitizer should remain.

However:

A sanitized structural preview is not an exact rendering of the recipient email.
Removing inline/style content materially changes layout.
The UI must not imply client-specific or production-delivery fidelity.
If true email-client preview is not implemented, say so plainly.
This is a trust fix, not a request to weaken sanitization.

4.13 Pricing needs one commercial authority
The current catalog establishes:

Plan	Monthly	Included monthly emails
Free	€0	3,000
Developer	€29	50,000
Pro	€89	150,000
Growth	€229	500,000
Business	€699	2,000,000
Enterprise Cloud	€1,750	5,000,000
The one-time 30,000-email launch allowance is not the recurring Free quota.

Annual billing at ten monthly payments means approximately 16.7% savings against twelve monthly payments, not 10%.

All of these should derive from shared commercial data:

Cards.
Teasers.
Calculator.
FAQs.
Comparison pages.
Quickstart.
Enterprise procurement tables.
Signup intent.
Console plan labels.
PDF/invoice output.
4.14 Localization must cover the journey, not just navigation
The localization catalog has consistent key coverage, but that does not mean the product is fully localized.

Problems are concentrated in:

Hardcoded template strings.
Static partials.
Empty translated content bodies.
Translated pages whose links target English fragments.
Pricing claims that remain obsolete in translated strings.
A user should not encounter:

A localized headline.
English pricing controls.
An empty localized guide.
A localized SLA containing only one section.
That is visibly incomplete, regardless of how polished the header is.

4.15 Brand consistency must extend beyond the app
The social card at og-image.png is visibly clipped and retains a blue/slate treatment inconsistent with the current red identity.

Fix the composition within the existing direction:

Safe text bounds.
Current red/neutral identity.
Current typography.
Fewer, clearer claims.
No clipped subtitle or lower cards.
Likewise, system emails, error pages, and PDFs should feel like the same product—not independent implementations.

5. Shared Rust UI: file-by-file recommendations
5.1 Runtime and presentation files
File	Required fixes and refinements
leptos_views.rs	Correct action wiring, campaign scheduling/preview wording, nested forms, settings composition, and template editing. Reduce repeated engineering-oriented explanations. Keep shared page/header/form patterns instead of parallel fallback products.
axum_router.rs	Normalize aliases before dispatch; preserve specialized data on aliases; compose forms with data-backed tables; scope retained fields/errors to the correct form; retain filters during refresh; use stable feedback slots; use HTTP redirects for relocation.
primitives.rs	Escape native-select values/labels; implement native textarea limits; remove misleading static counters; distinguish usable native primitives from inert legacy custom controls; allow stable caller-provided IDs.
shell.rs	Repair closed mobile hit area, banner/header stacking, single-most-specific active matching, and narrow-screen identity access. Preserve native disclosures and session-derived labels.
charts.rs	Correct area closure and zero-bar geometry; handle large datasets; use actual SVG stroke/fill properties; provide meaningful summaries and accessible data alternatives. Do not imply unused renderers already power live dashboards.
tokens.rs	Validate current theme authorities instead of historical snapshots. Make source-versus-artifact drift visible.
icons.rs	Escape interpolated class attributes; retain one consistent icon stroke/scale contract. No new decorative icon family is needed.
lib.rs	Validate light and dark token blocks independently. Keep stylesheet versioning and embedded-asset authority explicit.
view_data.rs	Make page-state distinctions explicit; prevent inverted/out-of-range result summaries; carry time-window, freshness, permission, and action context as typed data.
data.rs	Separate historical client-data contracts from actual native POST/redirect/GET behavior. Avoid documentation that implies unavailable client features.
routing.rs	Inventory actual dynamic routes, host surfaces, and aliases—not only representative manifest examples.
ssr.rs	Compare rendered coverage with independently extracted mounted routes; avoid deriving both sides of a coverage assertion from the same manifest.
flash.rs	Bound feedback payloads to a browser-safe cookie budget; preserve persistent, accessible PRG feedback rather than reviving nonfunctional timed toasts.
csrf.rs	Preserve the token design; extend consumer/cookie-binding tests so malformed rendered forms cannot silently break workflows. No visual redesign is needed.
qr.rs	Correct mask coordinates and validate externally. Preserve selectable manual setup information as an accessible fallback.
tracking_domain.rs	Keep parent-domain context navigable and CNAME information inspectable after verification; make prerequisites, entitlement, and retry states task-oriented.
explorer.rs	Repair invalid fallback CSS, add clear result-page headings, use configured marketing-origin return links, and retain inputs for revise/retry flows.
marketing.rs	Clearly deprecate inert historical widgets and distinguish fallback renderers from the active Zola documents.
fixture_states.rs	Add populated bulk tables, failed multi-form replay, secret receipts, permission restrictions, and real create/edit variants. Empty-state fixtures alone miss important defects.
5.2 Styles, build, and package ownership
File	Recommendation
globals.input.css	Restore all maintained recipes here. Replace shared transition-all declarations with approved property lists. Use canonical timings. Preserve arch/concentric details and restrained surfaces.
globals.css	Treat as a reproducible artifact; remove independent maintenance. Verify regenerated output retains mobile, focus, panel, and shell fixes.
tailwind.config.js	Scan every authoritative renderer that emits UI classes; make token mappings and generated-class completeness testable.
build.rs	Require complete, provenance-stamped marketing output—not merely an existing homepage—to establish build freshness.
Cargo.toml	Add independent HTML/QR conformance coverage where appropriate; do not replace the runtime architecture merely to fix test gaps.
README.md	Document actual surface ownership, native PRG behavior, embedded assets, fallback semantics, and fixture authority.
Specific primitive refinements
Textarea: emit native maxlength; replace the SSR-only “live” count with a truthful limit helper.
Native select: escape at the primitive boundary, not at each caller.
Custom select: prefer the working native counterpart.
Custom switch/checkbox/radio/slider: use actual native controls before production use.
Tabs: use real route/query links if switching is server-rendered.
Dialog/alert dialog: use a tested native/declarative implementation or a confirmation page.
Dropdown/popover: use real links/forms and truthful disclosure semantics.
Accordion: use native disclosure; height-zero is not equivalent to semantically hidden.
Pagination: retain the working link-based renderer; deprecate inert button output.
Toast: current disabled toast surface should remain disabled until behavior is real.
These legacy exports are library risks, not proof that every current page is broken.

6. Customer console: page-by-page fixes
The pages below are implemented primarily in leptos_views.rs, with live data and form ownership in data.rs and web.rs.

6.1 Authentication and entry
Page	Fixes within the current vision
Application landing	Make “Go to Dashboard” lead to the actual dashboard. Keep the entry screen concise and task-oriented.
Login	Clarify persistence beside “Keep me signed in.” Preserve the current centered card, hierarchy, and provider buttons.
Signup	Elevate selected-plan intent and “starts on Free” into one short onboarding summary. Avoid making a paid selection look activated before billing.
MFA challenge	Place code instructions immediately beside the field. Preserve recovery-code login; reduce repeated verification explanations.
Forgot password	Give the submitted state concise inbox/spam guidance without revealing account existence.
Reset password	Existing missing-link notice is useful; add a direct request-another-link action and avoid inviting entry into an unusable form.
Email verification	Offer resend in the pending state as well as error recovery. Keep the action and account address unmistakable.
Customer 404	Offer a direct console recovery path, not only a public landing page.
Destructive confirmation	Lead with readable resource name, selected count, and consequence. IDs/signatures belong in secondary technical context.
6.2 Campaigns, contacts, and lists
Page	Fixes
Dashboard	Keep real aggregate metrics; add one clear next-work action. Do not restore unsupported fallback “all systems operational” claims.
Campaign list	Include Scheduled in filtering; make status, next action, and last change scannable. Repair bulk/per-row form structure.
New campaign	Group essentials first: identity, audience, content, scheduling. Put tracking/UTM/throttle/IP settings in clearly named advanced sections.
Campaign editor	Fix update routing first. Show actual campaign status rather than an unconditional Draft badge where inappropriate. Use native field types where their semantics fit.
Campaign scheduling	Show timezone and automatic-send consequence immediately before Save. Separate Save draft from schedule authorization.
Campaign detail	Reflect actual lifecycle and scheduled behavior. Replace missing-audience ambiguity with distinct unavailable/no-list states and a Create list link.
Campaign preview	Label as sanitized structural preview; disclose stripped styling and lack of recipient-client fidelity.
Contacts list	Restore CSV export to the live header. Label row selection using readable contact identity rather than only an ID.
Add/import contact	Resolve Name being labeled optional while rendered required. Clearly distinguish single-entry and CSV import paths.
Contact edit	Show audience membership context and the scope of what can be edited. Do not imply full segmentation management.
Lists	Explain lists versus saved segments consistently. Keep member counts and campaign usage easy to find.
New list	Add a clear Cancel/parent return action. Keep name-only creation compact.
List detail	Add a members view or direct members link beneath the count. A subscriber total without inspection is an incomplete management path.
List edit	Identify the list being renamed and provide an explicit return destination.
6.3 Templates, analytics, and diagnostics
Page	Fixes
Templates list	Expose an actual editor navigation action in live rows.
New template	Describe the real capability as HTML editing, not a visual builder. Provide a useful starter example.
Template edit	Load existing content; align blank-body rules with Save; redirect to the valid editor/detail route.
Reports	Link report rows to relevant campaign statistics. Make reporting scope explicit.
Deliverability report	Distinguish MX acceptance, bounce/complaint events, engagement, and actual inbox placement.
Inbox-placement list	Give tests a real results action and clear running/completed/failed labels.
New placement test	Summarize selected providers and the probe-send consequence before submission.
Placement detail	Render real results; do not indefinitely display a static “reload later” promise.
Analytics	Keep the actual aggregate loader; make the observation window, denominator, and unavailable values visible.
Events	Provide a message-timeline handoff from relevant rows.
Message timeline	Render as a chronological diagnostic narrative with phase boundaries; raw evidence remains available secondarily.
6.4 Domains, assistant, and settings
Page	Fixes
Domains list	Make each status lead to its specific DNS/setup recovery task.
Add domain	Explain the next DNS step before Add; adding is not equivalent to sending readiness.
Domain detail	Correct Verify DNS’s POST target. Preserve selectable records and distinguish host/type/value/status clearly.
Tracking domain	Keep parent sending-domain context visible and navigable. Retain the record after verification.
Assistant	Replace “never guesses” with bounded, evidence-grounded language. Keep citations, capability gating, and escalation/handoff clear.
Settings hub	Group identity/access, sending infrastructure, and billing rather than equal undifferentiated destinations.
API keys	Restore creation beside live rows. Group scopes by task and encourage least privilege. Keep reveal-once output stable and unmistakable.
Team	Restore invitation beside membership data. State whether submission creates a record, sends an email, or both.
Billing	Restore actions without implying a log-only request creates checkout, opens a portal, or charges the account.
Dedicated IPs	Restore the request affordance the empty state asks users to use. Explain eligibility and provisioning expectations.
Webhooks	Compose registration/event selection with live endpoint data. Make signing-secret receipt and retry/health interpretation clear.
Suppressions	Preserve read-only behavior where intended; explain reason and sending consequences rather than presenting an unexplained immutable list.
Profile	Show populated identity first, then focused password/MFA/recovery tasks. Avoid a form that appears to have forgotten the signed-in user.
Additional source responsibilities
File	Recommendations
web.rs	Align create/update/redirect contracts; make request acknowledgements truthful; preserve field state; connect invitation records to an explicit activation/delivery path; test effective form actions.
data.rs	Supply action-aware models, correct empty/unavailable distinctions, readable statuses, freshness/time windows, and detail navigation.
app.rs	Keep host routing and result-return origins coherent; preserve the limited CAPTCHA auth exception without introducing general hydration; verify HTML/asset build consistency.
explorer.rs	Retain submitted input on result/retry pages; distinguish priced fields from context-only fields; make sandbox constraints visible next to actions.
campaigns.rs	Publish scheduling behavior through the same UI contract; test user-facing state transitions against worker execution.
analytics.rs	Keep export values honest: unavailable complaint/unsubscribe values must not be hardcoded observed zeroes.
billing.rs	Reconcile real provider-session operations with browser request twins; make the commercial journey explicit rather than apparently complete.
7. Control plane: page-by-page fixes
Operational principle
The control plane should optimize for:

Fast identification of the next required action.
Clear tenant/resource scope.
Trustworthy freshness and state.
Deliberate consequential operations.
Minimal explanatory clutter.
It should feel like the customer console’s denser operational sibling—not a different visual product.

Page	Fixes
Operator login	Add a concise access-recovery contact. Preserve restricted-access positioning.
Home	Connect recent tenants/KPIs directly to alerts, queues, and tenant work.
Dashboard	Make critical alerts more prominent than ordinary metrics. Do not imply health from absent data.
Audit	Restore filter-preserving CSV access in the live view; the export handler already exists.
Tenants	Make Impersonate role-aware before offering it. Separate ordinary inspection from suspend/delete actions.
New tenant	Explain what is provisioned and what remains to be configured after creation.
Operators	Replace reused sent/draft MFA labels with Enabled/Not configured. Add clear access-management paths where supported.
New operator	State resulting access level and activation/delivery expectations before submission.
Analytics	Describe the actual event metrics—not unimplemented latency/availability measurements.
Discovery	Use Lead Sources consistently; “Service Discovery” describes a different concept. Link the discovery/enrichment task directly.
Jobs	Identify queue/status aggregates as aggregates, not individual execution records.
Infrastructure hub	Match navigation labels to real data. A card describing cluster nodes should not open an outbound IP inventory.
Nodes/IP pool	Rename/reframe around the real outbound IP-pool inventory.
Queues	Show oldest-pending age beside health because it informs that health classification.
Domains	Keep tenant ownership and transfer-review context immediately visible.
Domain transfer	Resolve target tenant to a readable identity before typed confirmation.
Billing hub	Replace a large single-card grid with a compact Plans destination and useful context.
Plans	Label currency, billing interval, and quota units explicitly.
Compliance	Lead with pending requests and the operational queue.
GDPR requests	Add outcome review before Complete/Reject. Do not make consequential transitions look like equivalent ordinary buttons.
Alerts	Lead with severity, age, and acknowledgement; keep rule configuration secondary.
Alert rules	Separate create/edit/toggle/delete hierarchy. Add deliberate native confirmation for deletion.
Settings	Use a compact Security destination rather than a half-empty hub.
Security/MFA	Show enrollment state, manual setup fallback, and recovery-code handoff. Independently validate QR interoperability.
Sales	Put exceptions and required decisions before explanatory sections. Reduce raw endpoint lessons in disabled controls.
Sales review/replay	Native SSR forms can implement these actions without JavaScript. The current read-only limitation is not an unavoidable consequence of the architecture.
Sales alias	Route the same typed sales data through the specialized renderer.
AI draft review	Show the draft itself before Approve + queue. Make the consequence and target message clear.
Demo administration	Provide a clickable viewer action beside the selectable URL; distinguish current step, expiry, and advance behavior.
CP confirmation	Keep resource identity and effect visible; preserve the newly added minimal confirmation chrome.
CP 404	Name the recovery destination explicitly as Control-plane home.
The relevant implementation remains leptos_views.rs, axum_router.rs, and the browser handlers and loaders.

8. Marketing templates: all 71 files
The following recommendations cover every existing template. “Dormant” means no current template/content inclusion was found—not that it can never have an external consumer.

8.1 Page and layout templates
File	Fixes/refinements
base.html	Remove the offscreen desktop navigation tab stop; keep metadata, locale, main landmark, and asset authority coherent. Verify page-specific social metadata rather than generic inheritance.
home.html	Localize the entire pricing teaser and define or remove “most verified.” Keep the compact homepage sequence.
page.html	Define one-heading/prose/empty-content contracts, with an explicit opt-out for fully authored layouts.
section.html	Render section identity, subsections, and an empty-index state; do not silently leave an index without useful navigation.
docs-section.html	Add a useful no-guides state with API/support destinations. Prioritize first-send onboarding.
prose.html	Localize update labels, use a machine-readable date, preserve narrow reading width, and support stable section navigation.
prose-section.html	Apply the same localized date/navigation standards; localize Related.
macros.html	Make comparison tie/unavailable labels translatable and semantically explicit.
pricing.html	Add plans/calculator/FAQ anchors with sticky-header offsets; explain server-submitted estimation.
calculator.html	Distinguish the actual ApexMail estimate from static competitor information. Remove stale JavaScript expectations.
compare.html	Add a concise comparison → methodology → decision-guide path.
compliance.html	Visibly label the showcase as illustrative, not account evidence or a generated review pack.
features.html	Add category/deep-dive navigation before the long card inventory.
private-cloud.html	Add deployment/isolation/IP/review anchors to shorten the decision journey.
email-logs.html	Add diagnostic-specific description and social metadata.
api-explorer.html	Bound workbench width/gutters consistently with the hero. Preserve the dark technical surface.
status.html	Keep it a truthful static handoff with one clear live-status action; avoid repeated warning panels.
404.html	Centralize noindex policy and localize metadata as well as recovery actions. Preserve existing recovery destinations.
8.2 Shared chrome
File	Fixes/refinements
header.html	Use a native mobile disclosure with focus and expanded state attached to the visible control. Remove unsupported promises about automatic Escape handling.
footer.html	Correct brand-block column spans at small/intermediate breakpoints; avoid implicit grid tracks. Keep company/legal/status context clear.
brand-lockup.html	Validate viewBox and text bounds through font swap/enlargement. Preserve the current accessible wordmark.
cookie-consent.html	Clarify equivalent necessary-only choices; reserve space for the fixed mobile bar. Preserve the corrected locale policy link and nonmodal semantics.
analytics.html	Document actual collector/policy ownership; this comment-only partial should not imply it performs collection.
8.3 Home partials
File	Fixes/refinements
hero.html	Mark the trace as an example and align the shown request with the submitted sandbox payload. Do not imply reserved-recipient execution proves recipient-MX delivery.
features.html	Use a balanced four-item arrangement instead of three plus an orphan; tighten the heading-to-card gap.
cta.html	Make Book Architecture Review lead to an actual enquiry/review path, or rename it to match the informational destination.
comparison.html	Dormant: replace broad superiority labels with sourced, plan-scoped capabilities before reuse.
security.html	Dormant: HIPAA Not offered must not carry an Active badge. Separate availability from operational status.
8.4 Pricing and calculator partials
File	Fixes/refinements
hero.html	Localize eyebrow, headline, and supporting explanation. Keep the restrained red display emphasis.
plans.html	Derive names, prices, limits, and feature labels from the public catalog/view model. Preserve self-serve versus commercial-plan separation.
card.html	Localize accessible names and allow recommendation badges to wrap without protruding outside the crown.
calculator.html	Use one authoritative volume control. Distinguish priced factors from contextual fields. Explain next-page results.
calculator-interactive.html	Correct annual 10%-off wording in English fallback and all locale strings. Keep the native select/submit workflow.
cta.html	Prioritize sales/help for the questions-oriented section; use the local calculator anchor instead of restarting the estimate journey.
hero.html	Do not promise live competitor quotes that the form does not calculate.
competitor-breakdown.html	Replace obsolete quota/price/IP claims with current, dated assumptions. Wrap prose cells and name included/unavailable icon states.
cta.html	Replace recurring 30K/month with 3K/month and separately identify the launch allowance.
8.5 Features and comparisons
File	Fixes/refinements
hero.html	Label P95≤500ms as target versus measured result according to its authority. Keep that distinction beside the number.
grid.html	Replace undefined bare color utilities with mapped tokens. Provide readable narrow-screen fallback instead of forced tiny two-up descriptions.
details.html	Do not describe ordinary tags as consent/lawful-basis evidence. Link the actual compliance workflow.
cta.html	Use shared button variants so geometry, focus, sizing, and emphasis remain consistent.
hero.html	Use one neutral missing-competitor fallback; localize shared comparison UI.
table.html	Use semantic table headers/caption. Make scrolling keyboard reachable; keep methodology outside the constrained data scroller.
cta.html	Mark the active comparison and include the complete applicable competitor set. Localize decision-guide copy.
8.6 Compliance
File	Fixes/refinements
hero.html	Correct supporting heading hierarchy; remove pulsing “live” emphasis from static review information.
auto-dpa.html	Label the mock document as illustrative; keep legal/signature boundaries explicit and stack actions when necessary.
data-retention.html	Fix localized privacy fragments; use row headers; allow long retention descriptions to wrap.
cta.html	Make the compliance action lead to an appropriately scoped enquiry; localize action and qualifications.
8.7 Private deployment
File	Fixes/refinements
hero.html	Mark the architecture/IP strip as illustrative, not live provisioned infrastructure. Localize diagram labels.
dedicated-ips.html	Name the reputation metric and associate each meter with its IP/value. The displayed 89.4 average is arithmetically correct; do not “fix” it unnecessarily.
security-isolation.html	Qualify shared-cloud SLA eligibility; add caption/row headers and clear plan/deployment scope.
latency-comparison.html	Align legend colors with scenarios. Label bar lengths as illustrative, not measured proportional results. Localize scenario text.
cta.html	Use a readable ordered process, intermediate-width stacking, and explicitly indicative timing.
8.8 Diagnostics and status
File	Fixes/refinements
hero.html	Add a secondary jump to the example timeline and event documentation.
timeline.html	Use themed card surfaces; label the sample and inert action strip; correct elapsed-time context—shown timestamps span roughly 302 seconds, not 1.98 seconds.
cta.html	Name the sandbox action precisely and distinguish it from the static timeline.
hero.html	Dormant: retire or clearly label the disabled search example before reuse.
hero.html	Render the declared monitored-service list or remove the statement that it is shown. Consolidate repeated static-data warnings.
subscribe.html	Rename to Check service status: neither action currently subscribes to notifications. Stack actions on narrow screens.
8.9 Generated-named partials
These are currently static HTML/CSS files; the name does not establish active generation.

File	Fixes/refinements
api-explorer-island.html	Associate composer help with fields; label No request sent; clarify result-page navigation and failure states.
compliance-demo-island.html	Fix six cells under five headers; visibly qualify sample evidence and entitlement claims.
deployment-options-island.html	Keep radios focusable and labeled in a fieldset, with visible focus on labels; or use native disclosures. Pointer-only labels are insufficient.
pricing-faq-island.html	Localize questions and answers. Preserve native disclosures and accurate annual explanation.
status-overview-island.html	Present the live-service handoff neutrally, not as an amber operational warning.
status-history-island.html	Name the external-history handoff clearly; do not imply no incidents from absent static data.
cookie-consent-island.html	Dormant: retire the obsolete script-dependent modal duplicate.
pricing-calculator-island.html	Dormant: designate as catalog snapshot or retire; correct obsolete Free volume and keep validator authority consistent.
render-history-island.html	Dormant: remove fixed 90-day retention wording inconsistent with plan-dependent retention before reuse.
testimonials-island.html	Dormant capability band: remove obsolete €3,000/10-IP proof and residual testimonial presentation before reuse.
9. Marketing styles, data, configuration, and assets
File	Recommendations
input.css	Repair concentric shadow colors by using RGB tokens correctly; limit no-wrap to numeric/identifier cells; relax forced tiny mobile card layouts; retain current fonts, geometry, and red/zinc language.
styles.css	Keep generated from authored input; verify undefined bare utilities and asset-version delivery. Do not hand-maintain a second design system.
no-js.css	Keep collapsed content genuinely hidden; keep active controls keyboard reachable; correct deployment-radio visibility/focus behavior.
giallo.css	Preserve code readability in both themes; load only where warranted if practical. It should not introduce a third page color language.
tailwind.config.js	Define or avoid bare color utilities lacking default mappings; keep scans and token exposure aligned with emitted templates.
pricing.json	Make it the commercial UI authority; expose recurring versus launch allowance and annual-total semantics explicitly.
canonical.json	Keep availability, deployment scope, and assurance wording consistent across comparisons, features, and compliance.
i18n.json	Correct obsolete quota/discount/SDK claims and route hardcoded template strings through this authority. Existing key parity is a strength.
en.po	Document whether this catalog is active, supplementary, or historical; avoid competing translation authorities.
de.po	Keep glossary/consent terminology aligned with the active JSON catalog.
es.po	Same authority/glossary alignment; do not assume PO coverage supplies Markdown bodies.
fr.po	Same authority/glossary alignment and body-coverage distinction.
config.toml	Keep public URLs, company identity, social metadata, and language fallbacks current and explicit.
Dockerfile	Produce a coherent HTML/CSS/assets build with provenance. Generation comments must reflect actual build steps.
nginx.conf	Verify consent substitution, error-page boundaries, cache behavior, and asset URL handling as part of UI delivery.
staging-parity.json	Include hashed assets, localized bodies, result-origin return journeys, and consent states in parity expectations.
_headers	Keep security/cache assumptions equivalent to the actual nginx/Rust serving path.
_redirects	Keep canonical/locale relocation paths equivalent across deployment modes.
.htaccess	Treat as deployment-specific equivalent behavior, not independent route authority.
manifest.json	Preserve current identity and icons; avoid implying install/offline capabilities that are not supplied.
icon.svg	Preserve the red mark; verify small-size contrast and consistency with the wordmark.
og-image.svg	Recompose safe text bounds and current red/neutral identity.
og-image.png	Regenerate from the corrected composition; current headline/subtitle/lower cards clip.
hero-grid.svg	Keep decorative intensity subordinate to text; no new pattern family is needed.
openapi.yaml	Keep downloadable API contracts aligned with examples and display revision information beside the download.
robots.txt	Keep index policy consistent with canonical/noindex behavior; not a visual redesign task.
security.txt	Preserve reachable, current disclosure destinations and distinguish them from ordinary support.
config-v1.1.xml	Keep client-discovered names/endpoints consistent with setup documentation.
pgp-key.asc and pgp-key.txt	Preserve identical disclosure identity and reachable encryption guidance; no artistic change required.
Font files
Preserve the supplied typefaces.

Inter normal and Inter italic: retain body/product roles.
Fraunces normal WOFF2 and italic WOFF2: retain marketing display roles.
Fraunces normal TTF and italic TTF: keep only where needed by nonbrowser consumers/fallback packaging.
JetBrains Mono normal WOFF2 and italic WOFF2: use for browser delivery instead of larger TTF requests.
JetBrains Mono normal TTF and italic TTF: retain where genuinely required.
NOTICES.md: preserve attribution and packaging provenance.
Observed serving problem
The local marketing page rendered unstyled during inspection. A versioned stylesheet request returned 404 while the bare stylesheet path returned 200.

Treat this as an observed local serving/build-consistency defect, not proof of a production-wide outage. Check versioned URL handling and avoid long-lived immutable caching of failed asset responses.

10. Marketing content: all 177 files
The following tables cover all 54 content families.

For the first table, each row explicitly links the four individual language files. Recommendations apply to each file, with translation-specific defects called out.

10.1 Families present in all four languages — 164 files
Files	File-family fixes
Homepage: _index.md:1, _index.de.md:1, _index.es.md:1, _index.fr.md:1	Keep the same core positioning across languages; localize teaser/CTA content and annual savings consistently.
About: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Present company identity, trading name, deployment context, and contact links in one concise trust block.
Acceptable use: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Add a transactional/marketing/mixed-purpose decision guide before detailed obligations.
Anti-spam: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Reconcile blanket consent/unsubscribe wording with category-specific AUP treatment.
Compare index: _index.md:1, _index.de.md:1, _index.es.md:1, _index.fr.md:1	Distinguish cited comparisons from editorial summaries; expose methodology prominently.
Amazon SES: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Show scenario cost assumptions before raw per-email comparisons; separate managed versus assembled infrastructure.
Mailgun: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Separate region configuration, processing scope, and commercial plan differences.
Comparison methodology: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Add a visible evidence-coverage legend and direct links to cited examples.
Postmark: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Reconcile dedicated-IP entitlements and distinguish included versus qualified additional assignments.
Resend: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Replace vague High delivery-rate labels with defined measurements or Not directly comparable.
SendGrid: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Expose exact compared plans and source consequential capability claims.
Compliance: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Localize static sections and fix privacy-retention fragment destinations.
Contact index: _index.md:1, _index.de.md:1, _index.es.md:1, _index.fr.md:1	Keep the channel-selection matrix complete in every language. Valid mailto links are not inherently broken.
Enterprise contact: enterprise.md:1, enterprise.de.md:1, enterprise.es.md:1, enterprise.fr.md:1	Put scope, preparation checklist, and expected follow-up beside the enquiry action.
Sales contact: sales.md:1, sales.de.md:1, sales.es.md:1, sales.fr.md:1	Keep response expectations beside submission; separate core contact fields from optional procurement detail.
Security contact: security.md:1, security.de.md:1, security.es.md:1, security.fr.md:1	Clarify NDA/document availability and requested review scope beside the action.
Cookies: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Explain equivalent consent outcomes instead of implying different tracking behavior where none exists.
Data locations: data-locations.md:1, data-locations.de.md:1, data-locations.es.md:1, data-locations.fr.md:1	Distinguish active deployment, optional provider, processing, storage, and corporate location.
DPA: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Add concise navigation to scope, retention, subprocessors, obligations, and execution/review path.
Enterprise procurement: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Reconcile the 10-IP claim with the three-IP catalog/solution authority.
Features: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Correct translated recurring quota and SDK-language claims; make feature eligibility scannable.
Inbox placement: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Separate provider-reputation telemetry from seed-account placement testing.
Pricing: _index.md:1, _index.de.md:1, _index.es.md:1, _index.fr.md:1	Localize actual pricing UI and state monthly equivalent, annual total, and contract requirements consistently.
Pricing calculator: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Use one authoritative input and clearly explain server calculation/result navigation.
Privacy: _index.md:1, _index.de.md:1, _index.es.md:1, _index.fr.md:1	Use stable language-independent anchors for cross-page retention links. Document substantive revisions; age alone is not a defect.
Private cloud: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Localize deployment panels and keep illustrative performance separate from commitments.
Quickstart: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Supply all translated bodies; correct English recurring Free quota; preserve the existing first-send and follow-up sequence.
Responsible disclosure: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Present scope, report checklist, encryption, and response expectations together.
Regulated SaaS: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Use a concise Available / Not offered / Contract-dependent decision matrix.
Security: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Group assurance controls by availability/plan and link material statements to supporting documentation.
SLA: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Restore omitted translated terms; consolidate credit bands into one plan-specific matrix; align public plan names.
Solutions index: _index.md:1, _index.de.md:1, _index.es.md:1, _index.fr.md:1	Add a goal-based selector connecting use case, deployment requirement, and next action.
Enterprise solution: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Restore empty translated bodies; distinguish annual commitment total from effective monthly price.
High-volume sending: high-volume-sending.md:1, high-volume-sending.de.md:1, high-volume-sending.es.md:1, high-volume-sending.fr.md:1	Promote warm-up timing, qualification, and throughput constraints beside onboarding.
Migration: migration.md:1, migration.de.md:1, migration.es.md:1, migration.fr.md:1	Turn steps into gated phases with acceptance criteria and rollback triggers.
Regulated industries: regulated-industries.md:1, regulated-industries.de.md:1, regulated-industries.es.md:1, regulated-industries.fr.md:1	Make limitations and required written approvals a procurement checklist.
SaaS platforms: saas-platforms.md:1, saas-platforms.de.md:1, saas-platforms.es.md:1, saas-platforms.fr.md:1	Elevate logical-versus-contractual isolation distinctions and show tenant-boundary responsibilities.
Transactional email: transactional-email.md:1, transactional-email.de.md:1, transactional-email.es.md:1, transactional-email.fr.md:1	Offer the first-send path before the longer narrative; connect it to diagnostics.
Status: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Localize active sections and distinguish manual viewing/JSON access from subscription.
Subprocessors: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Restore translated registers and correct table-cell alignment; keep processing scope/country information readable.
Terms: index.md:1, index.de.md:1, index.es.md:1, index.fr.md:1	Add plain-language renewal/cancellation navigation without replacing controlling terms.
10.2 English-only families — 13 files
File	Fixes/refinements
index.md	Put sandbox/reserved-recipient constraints beside executable actions.
architecture.md	Surface responsibility matrix and distinguish public versus contracted deployment patterns.
_index.md	Prioritize first-send quickstart over secondary discovery cards.
index.md	Summarize incident severity and maintenance expectations compactly.
index.md	Use an annotated timeline to distinguish delivery, engagement, and inbox placement.
_index.md	Add jump navigation and consistent request → response → follow-up structure.
grader.md	Make public-domain checking versus authenticated message submission unmistakable.
index.md	Display revision/version and verification information beside the download.
index.md	Separate usable preview-source instructions from future registry installation. Foreground the HTTP alternative.
index.md	Promote a minimal verified receiver plus retry/deduplication checklist.
index.md	Distinguish recipient-MX acceptance from inbox placement and label sample traces.
index.md	Add metric navigation showing units, denominator, observation window, and exclusions.
do-not-sell.md	Make rights instructions a clear action block; label the English-only destination in localized navigation.
English-only documentation is not intrinsically defective. The missing part is a clear, consistent language handoff.

11. CAPTCHA: file-by-file
The canonical assets are distributed through build.sh. The corresponding files in resources and public matched mechanically.

Do not manually “fix” the mirrors independently.

Canonical file	Fixes/refinements
widget-driver.js	Make every terminal path settle execution; unify cancellation interface; preserve remaining token lifetime; distinguish terminal failure from recoverable retries.
widget.css	Show Retry for execution-unavailable; fix solving-state reduced-motion specificity; align progress values with supported width steps. Preserve the current checksum/arch/slot language.
widget-risk.js	Fix the captured cancellation handle; bound asset preflight duration; do not create work after cancellation or deadline expiry.
widget-locales.js	Replace universal Argon2id/CSP diagnosis with accurate localized recovery copy; keep existing locale/RTL support.
widget-telemetry.js	Preserve default-off, bounded widget-local collection and cleanup. Clarify configuration precedence. No visual redesign needed.
widget-compat.js	Apply lifecycle fixes through delegation; preserve provider migration semantics.
kiwi-worker.js	Preserve bounded work/versioned messages; surface failures through the host widget. No separate worker UI is needed.
execution-interpreter.js	Preserve deterministic execution and framed protocol; avoid introducing competing iframe UI.
kiwicaptcha-wasm.js	Regenerate through the build pipeline; do not hand-edit generated payloads.
Specific interaction defects
Execution-unavailable leaves Retry hidden despite a reacquirable state.
Driver and risk module disagree on whether cancellation is a function or an object.
Solving animation can survive reduced-motion rules.
Progress emits values the CSS does not recognize.
Specialized failures can leave execute() pending.
Error copy claims a specific cause not established by the failure.
Late locale loading can leave live-region text untranslated.
Token lifetime can visually restart after solving even though server expiry began at issuance.
Existing strengths to preserve
Native keyboard-operable Retry.
Polite announcement region.
Theme tokens.
Forced-color handling.
RTL/localization infrastructure.
Bounded challenge requests.
Existing accessibility/security/execution tests.
The auth CAPTCHA exception is real in app.rs. Correct stale comments claiming the widget was completely removed; keep the exception narrow.

12. Emails, error pages, and PDFs
12.1 Transactional emails
Source	Fixes/refinements
forgot_password.rs	Keep current technical identity, expiry, and unrequested-mail warning. Add viewport/background resilience and a visible HTML fallback URL.
auth.rs	Consolidate verification presentation; make MFA plain text include the HTML account context and unrequested-code warning.
web.rs	Align browser verification/reset/resend shells with the API equivalents. Preserve distinct link semantics. Bring reset plain-text warning into parity.
notification_drain.rs	Use explicit action links, currency, and account context; do not expose raw payloads as the ordinary customer presentation.
system_sender.rs	Keep supplied HTML/text presentation responsibility explicit; the queue layer does not magically add a shared branded shell.
Invitation handlers inspected create invited records without an email body/delivery call in those handlers. The UI should not imply completed delivery unless the actual acceptance/delivery path exists.

Missing unsubscribe links are not a blanket defect in these transactional/security messages.

12.2 Error pages
File	Fixes/refinements
404.html	Add a main landmark and deliberate branded focus/forced-color treatment. Preserve self-contained CSS and native recovery links.
50x.html	Remove unsupported “incident is being handled” and mail/API health assurances. Use confirmed-status wording; retain self-contained styling.
50x.html	Add essential inline fallback styling so an external stylesheet failure does not erase the presentation. Preserve its more honest incident wording.
404.html	Keep inherited main/focus behavior; consolidate index policy and locale-specific metadata.
12.3 PDF presentation
File	Fixes/refinements
compiler.rs	Wire the intended layout pipeline or identify current output as a data export. Validate reading order/text extraction independently.
invoice.typ	Derive currency and payment terms from authoritative data; current money formatting is euro-specific. Preserve existing metadata/items/totals structure.
dpa.typ	Align controller/version/retention schema with actual producer data before wiring. Keep agreement identity and execution clear.
compliance_report.typ	Add explicit Unknown rather than mapping unrecognized status to Fail; reconcile author identity and evidence scope.
analytics_export.typ	Define percentage units, unavailable data, fonts, and document identity consistently with the producer.
qbr.typ	Make improvement direction metric-specific: increased bounces, complaints, or latency are not positive improvements.
invoices.rs	Align delivered layout/data/authentication with renderer contracts; verify actual downloadable invoice presentation.
routes.rs	Align PDF payload schemas and renderer credentials; ensure generated agreement/report labels match real output.
13. Legal/compliance source templates
These are separate from public content. Their primary fix is authority and rendering consistency, not visual embellishment.

File	Recommendation
aup.md	Keep category rules aligned with public AUP and anti-spam guidance.
cookie-policy.md	Match actual consent outcomes and collection behavior.
dpa.md	Clearly identify revision, controller/processor roles, scope, and controlling obligations.
privacy-policy.md	Align processing/retention/location wording with deployed configuration and public policy.
sla.md	Use consistent plan-specific service/credit matrices.
terms-of-service.md	Resolve links correctly for the eventual rendered destination; align renewal/cancellation navigation.
compliance.md	Distinguish implemented workflow, assurance, and contractual availability.
data-locations.md	Separate deployed locations from optional-provider configurations.
incident-response.md	Make response stages, ownership, and customer communication expectations scannable.
performance-methodology.md	Keep units, denominators, windows, exclusions, and targets explicit.
responsible-disclosure.md	Keep reporting checklist and security contact authority consistent.
security-measures.md	Separate current controls from planned or contract-dependent controls.
security.txt	Keep machine-readable contact/canonical/encryption destinations current.
subprocessors.md	Keep vendor register columns, scope, and change-notification process consistent.
trust-center.md	Make document availability and review process clear without implying completed certifications.
Do not update policy dates merely to make documents look fresh. Update dates when substantive review or revision actually occurs.

14. Testing, manifests, and generated artifacts
14.1 Rust gates and utilities
File	Fixes/refinements
chrome_tests.rs	Include stateful documents, result pages, aliases, and populated data.
class_integrity_tests.rs	Parse selectors; comments/strings/decimals are not class definitions.
form_hygiene_tests.rs	Apply nesting/association rules to populated state fixtures, not only manifest default renders.
gate_support.rs	Include signed confirmations, retained field maps, reveal-once receipts, and Explorer results.
golden_tests.rs	Repair stylesheet-version normalization and distinguish incidental normalization from meaningful drift.
link_integrity_tests.rs	Validate quoted/unquoted targets, fragments, hosts, methods, and surface ownership.
migration_tests.rs	Remove unconditional absolute-path fixture writing from normal tests; use explicit exporters.
pixel_parity.rs	Compare against independent DOM/render baselines; self-comparison does not establish parity.
theme_contrast_tests.rs	Do not treat arbitrary typography/alignment classes as explicit text colors; test computed pairs and actual themes.
dna_verify.rs	Exit unsuccessfully when a check fails.
export_visual_fixtures.rs	Export complete state coverage with renderer/CSS/marketing hashes and one asset authority.
compare_pricing_parity_gate.rs	Missing required tooling in CI should fail, not appear as a successful skip.
14.2 Python UI gates
File	Recommendation
check_ui_a11y.py	Check controls without IDs and actual error associations.
check_ui_form_hygiene.py	Validate effective submit overrides and nonempty, correctly bound CSRF inputs.
check_ui_links.py	Resolve by host/surface and validate fragments; do not assume absent authority exists.
check_ui_terminology.py	Check visible page copy, not only flash call sites.
ui_html_rules.py	Fail missing/empty referenced fixture coverage.
ui_routes.py	Preserve methods and mounting context during extraction.
ui_flash_extract.py	Extract calls lexically and include raw literals without reading comments as calls.
extract_ui_strings.py	Correct source offsets and include shared renderers/system-email presentation.
ui_a11y_allowlist.json	Keep exceptions narrow, justified, owned, and time-bounded.
ui_links_allowlist.txt	Do not let broad allowances hide host/fragment/action defects.
ui_copy_allowlist.txt	Keep exceptions consistent with customer/operator terminology.
validate_pricing_drift.py	Include rendered locale strings and dormant pricing snapshots explicitly; catalog validation alone misses visible copy drift.
check_marketing_serving.py	Preserve the newly added serving checks and extend them to versioned asset responses/build consistency.
14.3 Browser and visual infrastructure
Existing browser/a11y tests are a strength. They should not be described as absent.

Priorities for a11y.spec.mjs, widget.spec.mjs, asset-mode.spec.mjs, te…