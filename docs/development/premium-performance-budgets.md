# Premium Performance Budgets

Budget definitions for perceived premium smoothness.

## Interaction Budgets

- Hover/focus feedback start: <= 120ms
- Primary UI response after user action: <= 180ms
- In-view transition completion: <= 320ms

Latency-to-motion contract:
- Use `--motion-duration-120` for hover/focus and low-risk feedback.
- Use `--motion-duration-180` for standard interaction response transitions.
- Use `--motion-duration-240` for state handoff transitions (enter/exit UI changes).
- Use `--motion-duration-320` for emphasis-only transitions and skeleton shimmer cadence.

Hover transform budget:
- Max upward translate on hover: `-2px`.
- Max scale on hover: `1.01`.
- Do not combine translate and scale with semantic color change in the same interaction.

## Loading Budgets

- Initial skeleton paint for async cards/lists: <= 400ms after route render
- Replace indefinite spinners with staged skeletons for loads > 600ms
- Preserve layout slots while loading (no major shift)

## State Messaging Budgets

- Mutation pending feedback appears immediately
- Success/error mutation message appears <= 150ms after result
- Retry affordance is visible in same component scope as error

## Measurement Guidance

- Track key route timings and interaction latency in CI/perf runs.
- Validate representative pages for web, control-plane, and marketing.
- Include both light and dark mode checks for visual-state timing parity.
