//! The demo scripts (plan §5.6): what a screen-share demo actually walks
//! through, in code, with every narration grounded.
//!
//! A script is a named, ordered list of steps. Each step names a REAL
//! capability and the inputs the runtime executes it with; the titles are the
//! presenter's talking points and are deliberately factual ("Render the
//! console dashboard"), never a claim. `docs/demos/demo-script.md` carries
//! the long-form presenter guide and cites this file as the authority.

/// One step of a demo script.
#[derive(Debug, Clone, Copy)]
pub struct ScriptStep {
    /// Step kind the runtime executes (`render_page`, `explorer_exec`,
    /// `grader`, `calculator`, `chat_narrate`).
    pub kind: &'static str,
    /// Presenter-facing title (factual; the guide expands it).
    pub title: &'static str,
    /// Kind-specific inputs.
    pub params: &'static [(&'static str, &'static str)],
}

/// A named demo script.
#[derive(Debug, Clone, Copy)]
pub struct DemoScript {
    pub key: &'static str,
    pub name: &'static str,
    pub steps: &'static [ScriptStep],
}

/// The canonical demo: console → API sandbox (real send) → add a domain →
/// grader → pricing calculator → grounded narration. The order is the story:
/// see the product, do the thing, verify it, price it, ask it.
pub const PLATFORM_TOUR: DemoScript = DemoScript {
    key: "platform-tour",
    name: "ApexMail platform tour",
    steps: &[
        ScriptStep {
            kind: "render_page",
            title: "The console you would use every day",
            params: &[("path", "/dashboard")],
        },
        ScriptStep {
            kind: "render_page",
            title: "Campaigns live in the same console",
            params: &[("path", "/campaigns")],
        },
        ScriptStep {
            kind: "explorer_exec",
            title: "Send a real message through the sandbox API",
            params: &[
                (
                    "body",
                    r#"{"from":"sandbox@example.com","to":["tour@example.com"],"subject":"Demo send","text":"Sent from the live API."}"#,
                ),
                ("lane", "send"),
            ],
        },
        ScriptStep {
            kind: "explorer_exec",
            title: "See the message the platform just accepted",
            params: &[("lane", "messages")],
        },
        ScriptStep {
            kind: "explorer_exec",
            title: "Register a sending domain",
            params: &[
                ("body", r#"{"domain":"tour.example.com"}"#),
                ("lane", "add_domain"),
            ],
        },
        ScriptStep {
            kind: "grader",
            title: "Grade the deliverability of a domain",
            params: &[("domain", "example.com")],
        },
        ScriptStep {
            kind: "calculator",
            title: "Price a volume on the public plan catalog",
            params: &[
                ("volume", "600000"),
                ("billing_cycle", "monthly"),
                ("dedicated_ips", "1"),
            ],
        },
        ScriptStep {
            kind: "chat_narrate",
            title: "Ask the grounded assistant what is included",
            params: &[("question", "What does the Growth plan include?")],
        },
    ],
};

/// Every script, in presenter order.
pub const SCRIPTS: &[DemoScript] = &[PLATFORM_TOUR];

/// Look up a script by key.
pub fn by_key(key: &str) -> Option<&'static DemoScript> {
    SCRIPTS.iter().find(|script| script.key == key.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_step_kind_is_executable_and_every_script_is_addressable() {
        const KINDS: [&str; 5] = [
            "render_page",
            "explorer_exec",
            "grader",
            "calculator",
            "chat_narrate",
        ];
        for script in SCRIPTS {
            assert!(!script.steps.is_empty(), "{} has no steps", script.key);
            assert_eq!(
                by_key(script.key).map(|s| s.key),
                Some(script.key),
                "script keys must round-trip"
            );
            for step in script.steps {
                assert!(
                    KINDS.contains(&step.kind),
                    "{} step '{}' names an unknown kind '{}'",
                    script.key,
                    step.title,
                    step.kind
                );
                assert!(
                    !step.title.trim().is_empty(),
                    "every step carries a presenter title"
                );
            }
        }
        assert!(by_key("nope").is_none());
    }

    #[test]
    fn the_tour_exercises_every_kind_so_a_demo_cannot_regress_silently() {
        let kinds: Vec<&str> = PLATFORM_TOUR.steps.iter().map(|s| s.kind).collect();
        for kind in [
            "render_page",
            "explorer_exec",
            "grader",
            "calculator",
            "chat_narrate",
        ] {
            assert!(kinds.contains(&kind), "the tour must exercise {kind}");
        }
    }
}
