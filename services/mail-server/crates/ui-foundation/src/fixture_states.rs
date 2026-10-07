//! Representative STATE fixtures for the two bot surfaces (dogfood
//! 2026-10-06 ui-visual).
//!
//! The route-level export renders every route's no-data fallback. On the
//! console assistant and the AI-drafts review queue that fallback is the
//! EMPTY state, so the states the owner directive calls out — the
//! populated / long / escalated transcript, a long single message, the
//! assistant's unavailable state and its PRG flash errors (rate limit /
//! service error), the drafts queue with real rows and long
//! subjects/replies, its unavailable state and its action feedback — were
//! never inventoried by the contrast/layout gates: an unrepresented state
//! cannot fail a gate.
//!
//! This module is the ONE source of truth for those states. It is consumed
//! by:
//!   * `bin/export_visual_fixtures` — writes one html file per state, so
//!     the browser gates (contrast + layout, both manifest-driven) audit
//!     them like any page;
//!   * `gate_support::gate_documents` — so the in-crate markup gates
//!     (gate J theme contrast, gate K class integrity) scan exactly the
//!     same state markup.
//!
//! The content is representative product copy (never lorem ipsum) and is
//! kept clean of the terminology-gate bans ("tenant" on the web surface,
//! subjective superlatives) so these fixtures can ship into the CI fixture
//! directory unchanged.

use crate::axum_router::{render_route_with_data, RouteData, SessionIdentity};
use crate::flash::FlashMessage;
use crate::view_data::{AiDraftData, AiDraftsPageData, AssistantPageData, AssistantTurnData};

/// One bot-surface state fixture: the id is the exported html file stem and
/// the manifest id prefix; the route is the REAL route the state belongs to
/// (so gate reports key it like the page itself).
pub struct BotStateFixture {
    pub id: &'static str,
    pub surface: &'static str,
    pub route: &'static str,
}

pub const BOT_STATE_FIXTURES: [BotStateFixture; 11] = [
    BotStateFixture {
        id: "web-assistant-populated",
        surface: "web",
        route: "/assistant",
    },
    BotStateFixture {
        id: "web-assistant-unavailable",
        surface: "web",
        route: "/assistant",
    },
    BotStateFixture {
        id: "web-assistant-disabled",
        surface: "web",
        route: "/assistant",
    },
    BotStateFixture {
        id: "web-assistant-rate-limited-flash",
        surface: "web",
        route: "/assistant",
    },
    BotStateFixture {
        id: "web-assistant-error-flash",
        surface: "web",
        route: "/assistant",
    },
    BotStateFixture {
        id: "control-plane-reviews-ai-drafts-populated",
        surface: "control-plane",
        route: "/reviews/ai-drafts",
    },
    BotStateFixture {
        id: "control-plane-reviews-ai-drafts-many",
        surface: "control-plane",
        route: "/reviews/ai-drafts",
    },
    BotStateFixture {
        id: "control-plane-reviews-ai-drafts-unavailable",
        surface: "control-plane",
        route: "/reviews/ai-drafts",
    },
    BotStateFixture {
        id: "control-plane-reviews-ai-drafts-approved-flash",
        surface: "control-plane",
        route: "/reviews/ai-drafts",
    },
    BotStateFixture {
        id: "control-plane-reviews-ai-drafts-rejected-flash",
        surface: "control-plane",
        route: "/reviews/ai-drafts",
    },
    BotStateFixture {
        id: "control-plane-reviews-ai-drafts-already-handled-flash",
        surface: "control-plane",
        route: "/reviews/ai-drafts",
    },
];

/// The fixed CSRF secret the exported fixtures use (kept identical to the
/// exporter's, so a state rendered by the gates and a state written to disk
/// differ only in the minted token value).
pub(crate) const FIXTURE_CSRF_SECRET: &str = "ui-foundation-fixture-secret-0123456789abcdef";

/// A single message that is long AND ends in an unbreakable token (a long
/// URL): the state that exercises wrapping/overflow on the transcript.
fn long_question() -> String {
    let mut question = String::from(
        "We are migrating about forty thousand contacts next quarter and need the exact limits. ",
    );
    question.push_str(
        "Please cover custom-field mapping, deduplication, suppression handling and retry behaviour for partial imports, and say which of these is idempotent. ",
    );
    for _ in 0..14 {
        question.push_str(
            "Also: does the same limit apply to segments built from CSV, and how are bounces counted? ",
        );
    }
    question.push_str(
        "The runbook we were given points at https://apexmail.ee/docs/api/imports#bulk-contact-import-with-custom-field-mapping-and-idempotent-retries but it does not answer the retry question.",
    );
    question
}

/// A drafted reply that is long AND carries unbreakable tokens, so the
/// `<pre>`-rendered draft body is exercised for horizontal overflow.
fn long_reply() -> String {
    let mut reply =
        String::from("Hi Lena,\n\nThanks for the detail — here is the short version.\n\n");
    reply.push_str(
        "1. Custom fields are matched by header name; unknown headers are ignored unless you map them.\n2. Duplicates are collapsed on the lowercased email address within the list.\n3. Suppressed addresses are skipped and reported in the import summary, never silently dropped.\n4. Retries are idempotent per row: re-running the same file re-uses the original row key.\n\n",
    );
    for _ in 0..10 {
        reply.push_str(
            "If any of this differs from what you observe, reply with the import id and we will trace the rows.\n",
        );
    }
    reply.push_str(
        "The endpoint reference is https://apexmail.ee/docs/api/imports#bulk-contact-import-with-custom-field-mapping-and-idempotent-retries and the status codes are listed there.\n",
    );
    reply
}

/// The populated console transcript: a short exchange, a grounded answer
/// with citations, a long single message, and an escalated answer.
pub fn assistant_populated() -> AssistantPageData {
    AssistantPageData {
        session_id: Some("chat_dogfood_ui_visual_0001".to_string()),
        turns: vec![
            AssistantTurnData {
                role: "user".to_string(),
                content: "What does the Pro plan include, and is there an annual discount?"
                    .to_string(),
                ..Default::default()
            },
            AssistantTurnData {
                role: "assistant".to_string(),
                content: "The Pro plan includes the shared IP pools, the full API and webhooks, and the standard retention window.\n\nAnnual billing is available for every paid plan; the annual price is shown on the pricing page next to the monthly price.".to_string(),
                citations: vec![
                    serde_json::json!({
                        "title": "Pricing — ApexMail",
                        "url": "https://apexmail.ee/pricing/",
                    }),
                    serde_json::json!({
                        "title": "Billing and invoices",
                        "url": "https://apexmail.ee/docs/billing/",
                    }),
                ],
                escalated: false,
                created_at: "2026-10-06 21:02 UTC".to_string(),
            },
            AssistantTurnData {
                role: "user".to_string(),
                content: long_question(),
                created_at: "2026-10-06 21:07 UTC".to_string(),
                ..Default::default()
            },
            AssistantTurnData {
                role: "assistant".to_string(),
                escalated: true,
                content: "I can confirm the limits and the idempotency contract from the published import reference.\n\nThe retry question is account-specific, so I am handing this to a human rather than guessing.".to_string(),
                citations: vec![serde_json::json!({
                    "title": "Bulk contact imports",
                    "url": "https://apexmail.ee/docs/api/imports",
                })],
                created_at: "2026-10-06 21:07 UTC".to_string(),
            },
        ],
        unavailable: false,
        capability_disabled: false,
    }
}

/// The per-tenant `ai_chat` feature flag switched off for this workspace:
/// the NAMED refusal and no message form (docs/user-guide/assistant.md).
pub fn assistant_disabled() -> AssistantPageData {
    AssistantPageData {
        capability_disabled: true,
        ..Default::default()
    }
}

/// The loader-failure state (session store unreadable): honest copy, never
/// an empty-conversation illusion.
pub fn assistant_unavailable() -> AssistantPageData {
    AssistantPageData {
        unavailable: true,
        ..Default::default()
    }
}

/// Three drafts: the long-subject/long-reply first-response case (an
/// objection with a sub-label), a plain question, and the empty-subject /
/// unclassified case that renders the "(no subject)" / "not classified"
/// display fallbacks.
pub fn drafts_populated() -> AiDraftsPageData {
    AiDraftsPageData {
        drafts: vec![
            AiDraftData {
                id: "draft_dogfood_ui_visual_0001".to_string(),
                tenant_id: "wsp_dogfood_ui_visual".to_string(),
                from_email: "lena.moreau@northwind-saas.example".to_string(),
                subject: "Re: Question about the annual discount and the 4,000-character assistant limit before we migrate forty thousand contacts next quarter".to_string(),
                draft_reply: long_reply(),
                received_at: "2026-10-06 21:14 UTC".to_string(),
                classification: Some("objection".to_string()),
                objection_class: Some("price".to_string()),
                first_response: true,
            },
            AiDraftData {
                id: "draft_dogfood_ui_visual_0002".to_string(),
                tenant_id: "wsp_dogfood_ui_visual".to_string(),
                from_email: "ops@northwind-saas.example".to_string(),
                subject: "Re: Webhook retries during the maintenance window".to_string(),
                draft_reply: "Hi,\n\nDuring the maintenance window webhook deliveries are retried with exponential backoff for up to twenty-four hours. No events are dropped.\n\n— ApexMail".to_string(),
                received_at: "2026-10-06 21:11 UTC".to_string(),
                classification: Some("question".to_string()),
                objection_class: None,
                first_response: true,
            },
            AiDraftData {
                id: "draft_dogfood_ui_visual_0003".to_string(),
                tenant_id: "wsp_dogfood_ui_visual".to_string(),
                from_email: "capped-787ff32e256c4c618025bd9495cd19e2@example.com".to_string(),
                subject: String::new(),
                draft_reply: "Hi,\n\nWe can move the subscription to annual billing at the next renewal without downtime. Your account manager will confirm the date.\n\n— ApexMail".to_string(),
                received_at: "2026-10-06 20:58 UTC".to_string(),
                classification: None,
                objection_class: None,
                first_response: false,
            },
        ],
        unavailable: false,
    }
}

/// The populated queue plus six more rows — the "many rows" scroll state.
pub fn drafts_many() -> AiDraftsPageData {
    let mut data = drafts_populated();
    for index in 4..=9 {
        data.drafts.push(AiDraftData {
            id: format!("draft_dogfood_ui_visual_{index:04}"),
            tenant_id: "wsp_dogfood_ui_visual".to_string(),
            from_email: format!("capped-{index:02}-787ff32e256c4c618025bd9495cd19e2@example.com"),
            subject: format!(
                "Re: Follow-up {index} on the migration checklist for the shared IP pool and the dedicated IP warm-up schedule"
            ),
            draft_reply: "Hi,\n\nWarm-up is staged over the first two weeks; the schedule is on the dedicated IPs page. Nothing sends from the new IP until the warm-up plan is active.\n\n— ApexMail".to_string(),
            received_at: format!("2026-10-06 20:{:02} UTC", 50 - index),
            classification: Some(if index % 2 == 0 { "question" } else { "objection" }.to_string()),
            objection_class: if index % 2 == 0 {
                None
            } else {
                Some("timing".to_string())
            },
            first_response: index % 3 == 0,
        });
    }
    data
}

/// The loader-failure state of the review queue.
pub fn drafts_unavailable() -> AiDraftsPageData {
    AiDraftsPageData {
        unavailable: true,
        ..Default::default()
    }
}

/// Render one state fixture page (the same render the exporter writes to
/// disk). Returns `None` for an unknown id rather than guessing.
pub fn render_bot_state(id: &str) -> Option<String> {
    let mut data = RouteData::default();
    // Every bot-surface page is an authenticated page: the fixtures carry a
    // realistic session identity (display name, long email, plan label) so
    // the shell header renders its real width — the live header overflowed
    // at 768 px only because no fixture had an identity (dogfood 2026-10-06
    // ui-visual).
    data.session_identity = Some(SessionIdentity {
        display_name: "Lena Moreau".to_string(),
        email: "lena.moreau@northwind-saas.example".to_string(),
        plan_label: Some("Free Plan — 3K / mo".to_string()),
    });
    let flash: Vec<FlashMessage> = match id {
        "web-assistant-populated" => {
            data.assistant = Some(assistant_populated());
            Vec::new()
        }
        "web-assistant-unavailable" => {
            data.assistant = Some(assistant_unavailable());
            Vec::new()
        }
        "web-assistant-disabled" => {
            // The per-tenant `ai_chat` feature flag is off: the page names
            // the reason and renders no message form.
            data.assistant = Some(assistant_disabled());
            Vec::new()
        }
        "web-assistant-rate-limited-flash" => vec![FlashMessage::error(
            "The assistant is receiving too many questions right now. Please retry in a minute.",
        )],
        "web-assistant-error-flash" => vec![FlashMessage::error(
            "The assistant is temporarily unavailable. Please try again.",
        )],
        "control-plane-reviews-ai-drafts-populated" => {
            data.ai_drafts = Some(drafts_populated());
            Vec::new()
        }
        "control-plane-reviews-ai-drafts-many" => {
            data.ai_drafts = Some(drafts_many());
            Vec::new()
        }
        "control-plane-reviews-ai-drafts-unavailable" => {
            data.ai_drafts = Some(drafts_unavailable());
            Vec::new()
        }
        "control-plane-reviews-ai-drafts-approved-flash" => {
            data.ai_drafts = Some(drafts_populated());
            vec![FlashMessage::success(
                "Draft approved — the reply is queued.",
            )]
        }
        "control-plane-reviews-ai-drafts-rejected-flash" => {
            data.ai_drafts = Some(drafts_populated());
            vec![FlashMessage::success("Draft rejected.")]
        }
        "control-plane-reviews-ai-drafts-already-handled-flash" => {
            data.ai_drafts = Some(drafts_populated());
            vec![FlashMessage::error("That draft was already handled.")]
        }
        _ => return None,
    };

    let fixture = BOT_STATE_FIXTURES
        .iter()
        .find(|fixture| fixture.id == id)
        .unwrap_or_else(|| panic!("state fixture {id} missing from BOT_STATE_FIXTURES"));

    // `render_route_with_data` takes flash and data together — the
    // flash-only helper drops data (it hardcodes `None`), which would
    // silently render the empty queue under an approval flash.
    render_route_with_data(
        fixture.surface,
        fixture.route,
        None,
        Some(FIXTURE_CSRF_SECRET),
        &flash,
        Some(&data),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_state_fixture_renders_and_ids_are_unique() {
        let mut ids: Vec<&str> = BOT_STATE_FIXTURES.iter().map(|f| f.id).collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count, "state fixture ids must be unique");

        for fixture in &BOT_STATE_FIXTURES {
            let html = render_bot_state(fixture.id)
                .unwrap_or_else(|| panic!("{} must render", fixture.id));
            assert!(
                html.contains("id=\"app-main\""),
                "{} must render through the surface shell",
                fixture.id
            );
        }
        assert!(render_bot_state("no-such-state").is_none());
    }

    #[test]
    fn populated_assistant_carries_the_states_that_used_to_be_invisible() {
        let html = render_bot_state("web-assistant-populated").unwrap();
        // The grounded answer with citations, the escalation notice, the
        // long single message and the per-turn timestamps are exactly what
        // the empty route fixture cannot show.
        assert!(html.contains("Sources"), "citations block must render");
        assert!(
            html.contains("A human will follow up"),
            "escalation notice must render"
        );
        assert!(
            html.contains("2026-10-06 21:02 UTC"),
            "timestamps must render"
        );
        assert!(
            html.contains("bulk-contact-import-with-custom-field-mapping"),
            "the long unbreakable token must be in the transcript"
        );
        // Long content is present in full (escaped), not truncated.
        assert!(
            html.len() > 20_000,
            "populated transcript must be substantial"
        );
    }

    #[test]
    fn unavailable_states_are_honest_and_never_empty() {
        let assistant = render_bot_state("web-assistant-unavailable").unwrap();
        assert!(assistant.contains("Conversation unavailable"));
        assert!(assistant.contains("reload to try again"));
        assert!(
            !assistant.contains("Ask about your workspace"),
            "the unavailable state must not render the empty-state prompt"
        );

        let drafts = render_bot_state("control-plane-reviews-ai-drafts-unavailable").unwrap();
        assert!(drafts.contains("The review queue is unavailable"));
        assert!(
            !drafts.contains("No drafts need review"),
            "the unavailable state must not render the empty-queue claim"
        );
    }

    /// The per-tenant feature-flag-disabled state names the reason and
    /// renders no message form — a form whose every submission is refused is
    /// not an honest disabled state (the page's disabled branch).
    #[test]
    fn disabled_assistant_state_names_the_reason_and_hides_the_form() {
        let html = render_bot_state("web-assistant-disabled").unwrap();
        assert!(
            html.contains("The assistant is not enabled for this workspace"),
            "the disabled state must name the capability, not an outage"
        );
        assert!(html.contains("the capability is disabled"));
        assert!(
            !html.contains("/web/assistant/message"),
            "the disabled state must not render the message form"
        );
        assert!(
            !html.contains("Ask about your workspace"),
            "the disabled state must not render the empty-state prompt"
        );
    }

    #[test]
    fn drafts_states_carry_rows_long_content_and_display_fallbacks() {
        let populated = render_bot_state("control-plane-reviews-ai-drafts-populated").unwrap();
        assert!(populated.contains("first response"), "pill must render");
        assert!(
            populated.contains("objection: price"),
            "objection label must render"
        );
        assert!(
            populated.contains("(no subject)"),
            "empty subject fallback must render"
        );
        assert!(
            populated.contains("not classified"),
            "classification fallback must render"
        );
        assert!(
            populated.contains("bulk-contact-import-with-custom-field-mapping"),
            "the long unbreakable token must be in the draft body"
        );

        let many = render_bot_state("control-plane-reviews-ai-drafts-many").unwrap();
        assert_eq!(
            many.matches("<article class=\"apex-panel\">").count(),
            9,
            "the many-rows state must render every row"
        );
        assert!(many.contains("approve") && many.contains("reject"));
    }

    #[test]
    fn flash_states_render_the_prg_feedback_banners() {
        let rate_limited = render_bot_state("web-assistant-rate-limited-flash").unwrap();
        assert!(rate_limited.contains("too many questions right now"));
        let error = render_bot_state("web-assistant-error-flash").unwrap();
        assert!(error.contains("temporarily unavailable"));
        let approved = render_bot_state("control-plane-reviews-ai-drafts-approved-flash").unwrap();
        assert!(approved.contains("Draft approved — the reply is queued."));
        let rejected = render_bot_state("control-plane-reviews-ai-drafts-rejected-flash").unwrap();
        assert!(rejected.contains("Draft rejected."));
        let handled =
            render_bot_state("control-plane-reviews-ai-drafts-already-handled-flash").unwrap();
        assert!(handled.contains("already handled"));
    }

    /// Layout fixes pinned at the markup (dogfood 2026-10-06 ui-visual):
    ///   * long unbreakable tokens wrap (`whitespace-pre-wrap break-words`)
    ///     on the transcript turns and the draft reply bodies — without
    ///     `break-words` the long docs URL forced horizontal scroll inside
    ///     the `<pre>`/`<p>`;
    ///   * the approve/reject action rows stack below `lg` — the
    ///     side-by-side row squeezed the note input to 16-30px wide at
    ///     320-768px (the button's intrinsic 167px won the flex row).
    #[test]
    fn bot_state_markup_pins_the_wrap_and_action_row_fixes() {
        let assistant = render_bot_state("web-assistant-populated").unwrap();
        assert!(
            assistant.contains("whitespace-pre-wrap break-words text-sm text-surface-900"),
            "assistant turn content must wrap long tokens"
        );

        let drafts = render_bot_state("control-plane-reviews-ai-drafts-populated").unwrap();
        assert!(
            drafts.contains("whitespace-pre-wrap break-words rounded-"),
            "draft reply bodies must wrap long tokens"
        );
        assert!(
            drafts.contains("flex flex-col gap-2 lg:flex-row lg:items-end"),
            "the action rows must stack below lg"
        );
        assert!(
            drafts.contains("text-xs text-surface-500 break-words"),
            "the row meta line must wrap long sender addresses (live 320 px overflow)"
        );
        assert!(
            !drafts.contains("flex items-end gap-2"),
            "the squeezed side-by-side action row must not return"
        );
    }

    /// The shell header carries a real session identity in the fixtures, so
    /// the layout gates exercise the header at its real width: a long email
    /// must truncate (min-w-0 + truncate) instead of widening the document
    /// (live dogfood 2026-10-06 ui-visual: 19 px overflow at 768 px).
    #[test]
    fn state_fixtures_carry_a_truncating_session_identity() {
        let html = render_bot_state("web-assistant-populated").unwrap();
        assert!(
            html.contains("lena.moreau@northwind-saas.example"),
            "the fixture header must render the session email"
        );
        assert!(
            html.contains("min-w-0") && html.contains("truncate"),
            "the header identity must carry the shrink/ellipsis classes"
        );
    }

    /// The web surface must never leak the operator word "tenant" into
    /// customer-facing copy (terminology gate J); the fixture content is
    /// held to the same bar as product copy.
    #[test]
    fn web_state_fixture_copy_avoids_operator_vocabulary() {
        for fixture in BOT_STATE_FIXTURES.iter().filter(|f| f.surface == "web") {
            let html = render_bot_state(fixture.id).unwrap().to_lowercase();
            assert!(
                !html.contains("tenant"),
                "{} must not use 'tenant' on the web surface",
                fixture.id
            );
        }
    }
}
