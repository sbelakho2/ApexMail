//! Content scoring via pattern-based analysis
//!
//! Uses Aho-Corasick multi-pattern matching to detect://! - Spam phrases (urgency, financial lures, pharma)
//! - Obfuscation patterns (zero-width characters, homoglyphs)
//! - Suspicious formatting (ALL CAPS ratio, HTML-to-text ratio)

use aho_corasick::AhoCorasick;
use std::sync::OnceLock;

/// Result of content scoring
#[derive(Debug, Clone)]
pub struct ContentScore {
    /// Total penalty from content analysis
    pub score: f64,
    /// Individual content findings
    pub findings: Vec<ContentFinding>,
}

/// A single content finding
#[derive(Debug, Clone)]
pub struct ContentFinding {
    /// Finding identifier
    pub id: &'static str,
    /// Description
    pub description: String,
    /// Penalty
    pub penalty: f64,
}

/// Spam phrase categories with per-match penalty
struct SpamPhraseSet {
    automaton: AhoCorasick,
    penalties: Vec<f64>,
    ids: Vec<&'static str>,
    descriptions: Vec<&'static str>,
    /// Whether the pattern is a single common word (no whitespace). Such
    /// patterns ("urgent", "expire", "winner", …) fire on huge amounts of
    /// legitimate mail, so their standalone weight is halved — multi-word
    /// phrases keep full weight because the combination is far more specific.
    single_word: Vec<bool>,
}

fn spam_phrase_set() -> Option<&'static SpamPhraseSet> {
    static INSTANCE: OnceLock<Option<SpamPhraseSet>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            let patterns: Vec<(&str, f64, &str, &str)> = vec![
                // ═══ Urgency / pressure (30 patterns) ═══
                ("act now", 1.5, "URGENCY_ACT_NOW", "Urgency phrase: act now"),
                (
                    "limited time",
                    1.5,
                    "URGENCY_LIMITED_TIME",
                    "Urgency phrase: limited time",
                ),
                ("expire", 1.0, "URGENCY_EXPIRE", "Urgency: expiration"),
                (
                    "immediate action",
                    2.0,
                    "URGENCY_IMMEDIATE",
                    "Urgency: immediate action required",
                ),
                ("urgent", 1.5, "URGENCY_GENERIC", "Urgency: urgent"),
                ("don't delay", 1.5, "URGENCY_DELAY", "Urgency: don't delay"),
                (
                    "time is running out",
                    2.0,
                    "URGENCY_RUNNING_OUT",
                    "Urgency: time running out",
                ),
                (
                    "last chance",
                    1.5,
                    "URGENCY_LAST_CHANCE",
                    "Urgency: last chance",
                ),
                (
                    "final warning",
                    2.0,
                    "URGENCY_FINAL_WARNING",
                    "Urgency: final warning",
                ),
                ("hurry", 1.0, "URGENCY_HURRY", "Urgency: hurry"),
                (
                    "act immediately",
                    2.0,
                    "URGENCY_ACT_IMMEDIATELY",
                    "Urgency: act immediately",
                ),
                ("deadline", 0.8, "URGENCY_DEADLINE", "Urgency: deadline"),
                (
                    "only today",
                    1.5,
                    "URGENCY_ONLY_TODAY",
                    "Urgency: only today",
                ),
                ("24 hours", 1.0, "URGENCY_24H", "Urgency: 24 hours"),
                (
                    "respond now",
                    1.5,
                    "URGENCY_RESPOND",
                    "Urgency: respond now",
                ),
                (
                    "take action now",
                    1.5,
                    "URGENCY_TAKE_ACTION",
                    "Urgency: take action now",
                ),
                (
                    "while supplies last",
                    1.5,
                    "URGENCY_SUPPLIES",
                    "Urgency: while supplies last",
                ),
                (
                    "offer expires",
                    1.5,
                    "URGENCY_OFFER_EXPIRES",
                    "Urgency: offer expires",
                ),
                (
                    "don't miss out",
                    1.5,
                    "URGENCY_MISS_OUT",
                    "Urgency: don't miss out",
                ),
                (
                    "time-sensitive",
                    1.5,
                    "URGENCY_TIME_SENSITIVE",
                    "Urgency: time-sensitive",
                ),
                (
                    "must respond",
                    1.5,
                    "URGENCY_MUST_RESPOND",
                    "Urgency: must respond",
                ),
                (
                    "before it's too late",
                    1.5,
                    "URGENCY_TOO_LATE",
                    "Urgency: before too late",
                ),
                ("apply now", 1.0, "URGENCY_APPLY_NOW", "Urgency: apply now"),
                (
                    "limited availability",
                    1.5,
                    "URGENCY_LIMITED_AVAIL",
                    "Urgency: limited availability",
                ),
                (
                    "exclusive offer",
                    1.0,
                    "URGENCY_EXCLUSIVE",
                    "Urgency: exclusive offer",
                ),
                (
                    "one-time offer",
                    2.0,
                    "URGENCY_ONE_TIME",
                    "Urgency: one-time offer",
                ),
                ("risk free", 1.5, "URGENCY_RISK_FREE", "Urgency: risk free"),
                (
                    "no obligation",
                    1.0,
                    "URGENCY_NO_OBLIGATION",
                    "Urgency: no obligation",
                ),
                (
                    "supplies are limited",
                    1.5,
                    "URGENCY_SUPPLIES_LTD",
                    "Urgency: supplies limited",
                ),
                (
                    "this won't last",
                    1.5,
                    "URGENCY_WONT_LAST",
                    "Urgency: this won't last",
                ),
                // ═══ Financial lures (35 patterns) ═══
                (
                    "you have won",
                    3.0,
                    "FINANCIAL_WON",
                    "Financial lure: you have won",
                ),
                (
                    "congratulations",
                    1.0,
                    "FINANCIAL_CONGRATS",
                    "Financial lure: congratulations",
                ),
                (
                    "million dollars",
                    3.0,
                    "FINANCIAL_MILLION",
                    "Financial lure: million dollars",
                ),
                (
                    "wire transfer",
                    2.0,
                    "FINANCIAL_WIRE",
                    "Financial: wire transfer",
                ),
                (
                    "nigerian prince",
                    5.0,
                    "FINANCIAL_419",
                    "419 scam indicator",
                ),
                (
                    "inheritance",
                    2.0,
                    "FINANCIAL_INHERIT",
                    "Financial lure: inheritance",
                ),
                (
                    "lottery",
                    2.5,
                    "FINANCIAL_LOTTERY",
                    "Financial lure: lottery",
                ),
                (
                    "free money",
                    3.0,
                    "FINANCIAL_FREE",
                    "Financial lure: free money",
                ),
                (
                    "cash prize",
                    2.5,
                    "FINANCIAL_CASH_PRIZE",
                    "Financial: cash prize",
                ),
                (
                    "bank account",
                    1.5,
                    "FINANCIAL_BANK_ACCT",
                    "Financial: bank account",
                ),
                (
                    "unclaimed funds",
                    3.0,
                    "FINANCIAL_UNCLAIMED",
                    "Financial: unclaimed funds",
                ),
                (
                    "beneficiary",
                    2.0,
                    "FINANCIAL_BENEFICIARY",
                    "Financial: beneficiary",
                ),
                (
                    "investment opportunity",
                    2.0,
                    "FINANCIAL_INVEST_OPP",
                    "Financial: investment opportunity",
                ),
                (
                    "guaranteed income",
                    2.5,
                    "FINANCIAL_GUARANTEED",
                    "Financial: guaranteed income",
                ),
                (
                    "make money fast",
                    3.0,
                    "FINANCIAL_MAKE_FAST",
                    "Financial: make money fast",
                ),
                (
                    "earn money from home",
                    2.0,
                    "FINANCIAL_FROM_HOME",
                    "Financial: earn money from home",
                ),
                (
                    "double your money",
                    3.0,
                    "FINANCIAL_DOUBLE",
                    "Financial: double your money",
                ),
                ("no fees", 1.0, "FINANCIAL_NO_FEES", "Financial: no fees"),
                (
                    "tax refund",
                    1.5,
                    "FINANCIAL_TAX_REFUND",
                    "Financial: tax refund",
                ),
                (
                    "credit card offer",
                    1.5,
                    "FINANCIAL_CC_OFFER",
                    "Financial: credit card offer",
                ),
                (
                    "pre-approved",
                    1.5,
                    "FINANCIAL_PREAPPROVED",
                    "Financial: pre-approved",
                ),
                (
                    "debt consolidation",
                    1.0,
                    "FINANCIAL_DEBT_CONSOL",
                    "Financial: debt consolidation",
                ),
                (
                    "low interest rate",
                    1.0,
                    "FINANCIAL_LOW_INTEREST",
                    "Financial: low interest rate",
                ),
                (
                    "financial freedom",
                    1.5,
                    "FINANCIAL_FREEDOM",
                    "Financial: financial freedom",
                ),
                (
                    "quick loan",
                    2.0,
                    "FINANCIAL_QUICK_LOAN",
                    "Financial: quick loan",
                ),
                (
                    "100% free",
                    2.0,
                    "FINANCIAL_100_FREE",
                    "Financial: 100% free",
                ),
                (
                    "money back guarantee",
                    1.0,
                    "FINANCIAL_MONEY_BACK",
                    "Financial: money back guarantee",
                ),
                (
                    "no credit check",
                    2.0,
                    "FINANCIAL_NO_CREDIT",
                    "Financial: no credit check",
                ),
                (
                    "cash bonus",
                    2.0,
                    "FINANCIAL_CASH_BONUS",
                    "Financial: cash bonus",
                ),
                (
                    "government grant",
                    2.5,
                    "FINANCIAL_GOV_GRANT",
                    "Financial: government grant",
                ),
                (
                    "secret method",
                    2.5,
                    "FINANCIAL_SECRET",
                    "Financial: secret method",
                ),
                (
                    "work from home",
                    1.5,
                    "FINANCIAL_WFH",
                    "Financial: work from home",
                ),
                (
                    "be your own boss",
                    1.5,
                    "FINANCIAL_OWN_BOSS",
                    "Financial: be your own boss",
                ),
                (
                    "residual income",
                    1.5,
                    "FINANCIAL_RESIDUAL",
                    "Financial: residual income",
                ),
                (
                    "bitcoin profit",
                    2.5,
                    "FINANCIAL_BITCOIN",
                    "Financial: bitcoin profit",
                ),
                // ═══ Pharma / health spam (25 patterns) ═══
                ("viagra", 2.0, "PHARMA_VIAGRA", "Pharma spam: viagra"),
                ("cialis", 2.0, "PHARMA_CIALIS", "Pharma spam: cialis"),
                ("pharmacy", 1.0, "PHARMA_GENERIC", "Pharma spam indicator"),
                ("weight loss", 1.5, "PHARMA_WEIGHT", "Pharma: weight loss"),
                ("diet pill", 2.0, "PHARMA_DIET", "Pharma: diet pill"),
                (
                    "lose weight fast",
                    2.0,
                    "PHARMA_LOSE_FAST",
                    "Pharma: lose weight fast",
                ),
                ("fat burner", 2.0, "PHARMA_FAT_BURNER", "Pharma: fat burner"),
                (
                    "appetite suppressant",
                    1.5,
                    "PHARMA_APPETITE",
                    "Pharma: appetite suppressant",
                ),
                (
                    "muscle growth",
                    1.5,
                    "PHARMA_MUSCLE",
                    "Pharma: muscle growth",
                ),
                (
                    "testosterone boost",
                    2.0,
                    "PHARMA_TESTOSTERONE",
                    "Pharma: testosterone boost",
                ),
                (
                    "erectile dysfunction",
                    2.0,
                    "PHARMA_ED",
                    "Pharma: erectile dysfunction",
                ),
                (
                    "cheap medication",
                    2.0,
                    "PHARMA_CHEAP_MED",
                    "Pharma: cheap medication",
                ),
                (
                    "online pharmacy",
                    2.0,
                    "PHARMA_ONLINE",
                    "Pharma: online pharmacy",
                ),
                (
                    "no prescription",
                    2.5,
                    "PHARMA_NO_RX",
                    "Pharma: no prescription",
                ),
                (
                    "canadian pharmacy",
                    2.0,
                    "PHARMA_CANADIAN",
                    "Pharma: canadian pharmacy",
                ),
                (
                    "generic pills",
                    1.5,
                    "PHARMA_GENERIC_PILLS",
                    "Pharma: generic pills",
                ),
                ("order now", 1.0, "PHARMA_ORDER_NOW", "Pharma: order now"),
                (
                    "herbal supplement",
                    1.0,
                    "PHARMA_HERBAL",
                    "Pharma: herbal supplement",
                ),
                (
                    "miracle cure",
                    3.0,
                    "PHARMA_MIRACLE",
                    "Pharma: miracle cure",
                ),
                ("anti-aging", 1.0, "PHARMA_ANTI_AGING", "Pharma: anti-aging"),
                ("cbd oil", 1.0, "PHARMA_CBD", "Pharma: cbd oil"),
                ("detox", 1.0, "PHARMA_DETOX", "Pharma: detox"),
                (
                    "natural remedy",
                    0.8,
                    "PHARMA_NATURAL",
                    "Pharma: natural remedy",
                ),
                ("pain relief", 0.8, "PHARMA_PAIN", "Pharma: pain relief"),
                ("sleep aid", 0.5, "PHARMA_SLEEP", "Pharma: sleep aid"),
                // ═══ Credential phishing (40 patterns) ═══
                (
                    "verify your account",
                    2.5,
                    "PHISH_VERIFY",
                    "Phishing: verify your account",
                ),
                (
                    "confirm your identity",
                    2.5,
                    "PHISH_CONFIRM",
                    "Phishing: confirm identity",
                ),
                (
                    "click here to login",
                    2.5,
                    "PHISH_LOGIN",
                    "Phishing: click here to login",
                ),
                (
                    "update your payment",
                    2.5,
                    "PHISH_PAYMENT",
                    "Phishing: update payment",
                ),
                (
                    "suspended",
                    1.5,
                    "PHISH_SUSPENDED",
                    "Phishing: account suspended",
                ),
                (
                    "your account has been",
                    2.0,
                    "PHISH_ACCT_HAS_BEEN",
                    "Phishing: your account has been",
                ),
                (
                    "unusual activity",
                    2.0,
                    "PHISH_UNUSUAL",
                    "Phishing: unusual activity",
                ),
                (
                    "unauthorized access",
                    2.0,
                    "PHISH_UNAUTHORIZED",
                    "Phishing: unauthorized access",
                ),
                (
                    "reset your password",
                    1.5,
                    "PHISH_RESET_PW",
                    "Phishing: reset your password",
                ),
                (
                    "secure your account",
                    2.0,
                    "PHISH_SECURE",
                    "Phishing: secure your account",
                ),
                (
                    "verify your email",
                    1.5,
                    "PHISH_VERIFY_EMAIL",
                    "Phishing: verify your email",
                ),
                (
                    "sign in immediately",
                    2.0,
                    "PHISH_SIGN_IN",
                    "Phishing: sign in immediately",
                ),
                (
                    "security alert",
                    2.0,
                    "PHISH_SECURITY_ALERT",
                    "Phishing: security alert",
                ),
                (
                    "confirm your email",
                    1.5,
                    "PHISH_CONFIRM_EMAIL",
                    "Phishing: confirm your email",
                ),
                (
                    "update your information",
                    2.0,
                    "PHISH_UPDATE_INFO",
                    "Phishing: update your information",
                ),
                (
                    "account will be closed",
                    2.5,
                    "PHISH_ACCT_CLOSED",
                    "Phishing: account will be closed",
                ),
                (
                    "billing problem",
                    2.0,
                    "PHISH_BILLING",
                    "Phishing: billing problem",
                ),
                (
                    "invoice attached",
                    1.5,
                    "PHISH_INVOICE",
                    "Phishing: invoice attached",
                ),
                (
                    "document shared",
                    1.0,
                    "PHISH_DOC_SHARED",
                    "Phishing: document shared",
                ),
                (
                    "shared a file with you",
                    1.0,
                    "PHISH_FILE_SHARED",
                    "Phishing: file shared with you",
                ),
                (
                    "sign in to view",
                    1.5,
                    "PHISH_SIGN_VIEW",
                    "Phishing: sign in to view",
                ),
                (
                    "click below to confirm",
                    2.0,
                    "PHISH_CLICK_CONFIRM",
                    "Phishing: click to confirm",
                ),
                (
                    "validate your account",
                    2.0,
                    "PHISH_VALIDATE",
                    "Phishing: validate your account",
                ),
                (
                    "unable to process",
                    1.5,
                    "PHISH_UNABLE_PROCESS",
                    "Phishing: unable to process",
                ),
                (
                    "payment declined",
                    2.0,
                    "PHISH_PAYMENT_DECLINED",
                    "Phishing: payment declined",
                ),
                (
                    "suspicious login",
                    2.0,
                    "PHISH_SUSPICIOUS_LOGIN",
                    "Phishing: suspicious login",
                ),
                (
                    "password expired",
                    1.5,
                    "PHISH_PW_EXPIRED",
                    "Phishing: password expired",
                ),
                (
                    "account locked",
                    2.0,
                    "PHISH_ACCT_LOCKED",
                    "Phishing: account locked",
                ),
                (
                    "failed delivery",
                    1.5,
                    "PHISH_FAILED_DELIVERY",
                    "Phishing: failed delivery",
                ),
                (
                    "package notification",
                    1.5,
                    "PHISH_PACKAGE",
                    "Phishing: package notification",
                ),
                (
                    "shipment tracking",
                    1.0,
                    "PHISH_SHIPMENT",
                    "Phishing: shipment tracking",
                ),
                (
                    "you have a new message",
                    1.0,
                    "PHISH_NEW_MSG",
                    "Phishing: you have a new message",
                ),
                (
                    "voicemail notification",
                    1.5,
                    "PHISH_VOICEMAIL",
                    "Phishing: voicemail notification",
                ),
                (
                    "action required",
                    2.0,
                    "PHISH_ACTION_REQ",
                    "Phishing: action required",
                ),
                ("re-verify", 2.0, "PHISH_REVERIFY", "Phishing: re-verify"),
                (
                    "unlock your account",
                    2.0,
                    "PHISH_UNLOCK",
                    "Phishing: unlock your account",
                ),
                (
                    "update credit card",
                    2.5,
                    "PHISH_UPDATE_CC",
                    "Phishing: update credit card",
                ),
                (
                    "paypal security",
                    2.0,
                    "PHISH_PAYPAL",
                    "Phishing: paypal security",
                ),
                ("apple id", 1.5, "PHISH_APPLE_ID", "Phishing: apple id"),
                (
                    "microsoft account",
                    1.0,
                    "PHISH_MICROSOFT",
                    "Phishing: microsoft account",
                ),
                // ═══ Advance-fee / 419 scams (20 patterns) ═══
                (
                    "dear friend",
                    2.0,
                    "AFF_DEAR_FRIEND",
                    "AFF scam: dear friend",
                ),
                (
                    "please help",
                    1.0,
                    "AFF_PLEASE_HELP",
                    "AFF scam: please help",
                ),
                (
                    "confidential transaction",
                    3.0,
                    "AFF_CONFIDENTIAL",
                    "AFF scam: confidential transaction",
                ),
                (
                    "next of kin",
                    3.0,
                    "AFF_NEXT_OF_KIN",
                    "AFF scam: next of kin",
                ),
                (
                    "business proposal",
                    2.0,
                    "AFF_BUSINESS",
                    "AFF scam: business proposal",
                ),
                ("barrister", 2.5, "AFF_BARRISTER", "AFF scam: barrister"),
                (
                    "diplomatic courier",
                    3.0,
                    "AFF_DIPLOMATIC",
                    "AFF scam: diplomatic courier",
                ),
                (
                    "consignment box",
                    3.0,
                    "AFF_CONSIGNMENT",
                    "AFF scam: consignment box",
                ),
                ("trunk box", 3.0, "AFF_TRUNK_BOX", "AFF scam: trunk box"),
                (
                    "compensation fund",
                    2.5,
                    "AFF_COMPENSATION",
                    "AFF scam: compensation fund",
                ),
                (
                    "deceased client",
                    3.0,
                    "AFF_DECEASED",
                    "AFF scam: deceased client",
                ),
                (
                    "release the fund",
                    3.0,
                    "AFF_RELEASE_FUND",
                    "AFF scam: release the fund",
                ),
                (
                    "central bank",
                    2.0,
                    "AFF_CENTRAL_BANK",
                    "AFF scam: central bank",
                ),
                (
                    "foreign minister",
                    2.5,
                    "AFF_FOREIGN_MIN",
                    "AFF scam: foreign minister",
                ),
                ("atm card", 2.5, "AFF_ATM_CARD", "AFF scam: atm card"),
                (
                    "consulate general",
                    2.0,
                    "AFF_CONSULATE",
                    "AFF scam: consulate general",
                ),
                (
                    "fund transfer",
                    2.0,
                    "AFF_FUND_TRANSFER",
                    "AFF scam: fund transfer",
                ),
                (
                    "western union",
                    2.0,
                    "AFF_WESTERN_UNION",
                    "AFF scam: western union",
                ),
                ("moneygram", 2.0, "AFF_MONEYGRAM", "AFF scam: moneygram"),
                (
                    "bitcoin wallet",
                    2.0,
                    "AFF_BITCOIN_WALLET",
                    "AFF scam: bitcoin wallet",
                ),
                // ═══ Adult / dating spam (15 patterns) ═══
                (
                    "hot singles",
                    2.5,
                    "ADULT_SINGLES",
                    "Adult spam: hot singles",
                ),
                (
                    "meet singles",
                    2.0,
                    "ADULT_MEET",
                    "Adult spam: meet singles",
                ),
                (
                    "adult friend",
                    2.0,
                    "ADULT_FRIEND",
                    "Adult spam: adult friend",
                ),
                ("hookup", 2.0, "ADULT_HOOKUP", "Adult spam: hookup"),
                (
                    "lonely wife",
                    2.5,
                    "ADULT_LONELY",
                    "Adult spam: lonely wife",
                ),
                (
                    "dating match",
                    1.5,
                    "ADULT_DATING",
                    "Adult spam: dating match",
                ),
                (
                    "mature women",
                    2.0,
                    "ADULT_MATURE",
                    "Adult spam: mature women",
                ),
                (
                    "discreet affair",
                    2.5,
                    "ADULT_AFFAIR",
                    "Adult spam: discreet affair",
                ),
                (
                    "singles in your area",
                    2.0,
                    "ADULT_AREA",
                    "Adult spam: singles in your area",
                ),
                (
                    "no strings attached",
                    1.5,
                    "ADULT_NO_STRINGS",
                    "Adult spam: no strings",
                ),
                ("cam girl", 2.5, "ADULT_CAM", "Adult spam: cam girl"),
                ("chat now", 1.0, "ADULT_CHAT", "Adult spam: chat now"),
                (
                    "sexual enhancement",
                    2.5,
                    "ADULT_ENHANCEMENT",
                    "Adult spam: sexual enhancement",
                ),
                (
                    "married but looking",
                    2.5,
                    "ADULT_MARRIED",
                    "Adult spam: married but looking",
                ),
                (
                    "secret lover",
                    2.0,
                    "ADULT_SECRET",
                    "Adult spam: secret lover",
                ),
                // ═══ Sextortion / blackmail (12 patterns) ═══
                (
                    "i know your password",
                    5.0,
                    "SEXTORT_PASSWORD",
                    "Sextortion: i know your password",
                ),
                (
                    "browsing habits",
                    3.0,
                    "SEXTORT_BROWSING",
                    "Sextortion: browsing habits",
                ),
                (
                    "your webcam",
                    3.0,
                    "SEXTORT_WEBCAM",
                    "Sextortion: your webcam",
                ),
                (
                    "video of you",
                    3.0,
                    "SEXTORT_VIDEO",
                    "Sextortion: video of you",
                ),
                (
                    "send bitcoin",
                    3.0,
                    "SEXTORT_BITCOIN",
                    "Sextortion: send bitcoin",
                ),
                (
                    "embarrassing video",
                    3.5,
                    "SEXTORT_EMBARRASS",
                    "Sextortion: embarrassing video",
                ),
                (
                    "recorded you",
                    3.0,
                    "SEXTORT_RECORDED",
                    "Sextortion: recorded you",
                ),
                (
                    "shared with contacts",
                    3.0,
                    "SEXTORT_SHARED",
                    "Sextortion: shared with contacts",
                ),
                (
                    "compromising material",
                    3.5,
                    "SEXTORT_COMPROMISE",
                    "Sextortion: compromising material",
                ),
                (
                    "adult website",
                    2.5,
                    "SEXTORT_ADULT_SITE",
                    "Sextortion: adult website",
                ),
                (
                    "if you don't pay",
                    3.0,
                    "SEXTORT_DONT_PAY",
                    "Sextortion: if you don't pay",
                ),
                (
                    "proof of payment",
                    2.5,
                    "SEXTORT_PROOF",
                    "Sextortion: proof of payment",
                ),
                // ═══ Unsubscribe tricks (5 patterns) ═══
                (
                    "click below to unsubscribe",
                    0.5,
                    "UNSUB_BELOW",
                    "Suspicious unsubscribe",
                ),
                (
                    "to stop receiving",
                    0.3,
                    "UNSUB_STOP",
                    "Generic unsubscribe language",
                ),
                ("opt out", 0.3, "UNSUB_OPT_OUT", "Unsubscribe: opt out"),
                ("remove me from", 0.3, "UNSUB_REMOVE", "Unsubscribe: remove"),
                (
                    "email preferences",
                    0.2,
                    "UNSUB_PREFS",
                    "Unsubscribe: preferences",
                ),
                // ═══ COVID / health scare (10 patterns) ═══
                ("covid cure", 3.0, "COVID_CURE", "COVID scam: cure"),
                (
                    "vaccine available",
                    1.5,
                    "COVID_VACCINE",
                    "COVID scam: vaccine",
                ),
                (
                    "pandemic relief",
                    2.0,
                    "COVID_RELIEF",
                    "COVID scam: pandemic relief",
                ),
                (
                    "stimulus check",
                    2.0,
                    "COVID_STIMULUS",
                    "COVID scam: stimulus check",
                ),
                (
                    "health alert",
                    1.0,
                    "COVID_HEALTH_ALERT",
                    "COVID: health alert",
                ),
                (
                    "quarantine order",
                    1.5,
                    "COVID_QUARANTINE",
                    "COVID scam: quarantine order",
                ),
                (
                    "covid test results",
                    1.5,
                    "COVID_TEST",
                    "COVID scam: test results",
                ),
                (
                    "face mask offer",
                    1.5,
                    "COVID_MASK",
                    "COVID scam: face mask",
                ),
                (
                    "sanitizer deal",
                    1.5,
                    "COVID_SANITIZER",
                    "COVID scam: sanitizer",
                ),
                (
                    "exposure notification",
                    1.5,
                    "COVID_EXPOSURE",
                    "COVID scam: exposure notification",
                ),
                // ═══ Tech support / impersonation (15 patterns) ═══
                (
                    "technical support",
                    1.0,
                    "TECHSUP_GENERIC",
                    "Tech support scam",
                ),
                (
                    "computer virus detected",
                    2.5,
                    "TECHSUP_VIRUS",
                    "Tech support: virus detected",
                ),
                (
                    "your computer is infected",
                    2.5,
                    "TECHSUP_INFECTED",
                    "Tech support: infected",
                ),
                (
                    "call this number",
                    1.5,
                    "TECHSUP_CALL",
                    "Tech support: call number",
                ),
                (
                    "remote access",
                    2.0,
                    "TECHSUP_REMOTE",
                    "Tech support: remote access",
                ),
                (
                    "windows alert",
                    2.0,
                    "TECHSUP_WINDOWS",
                    "Tech support: windows alert",
                ),
                (
                    "apple support",
                    1.5,
                    "TECHSUP_APPLE",
                    "Tech support: apple support",
                ),
                (
                    "your device has",
                    1.5,
                    "TECHSUP_DEVICE",
                    "Tech support: your device",
                ),
                (
                    "security breach detected",
                    2.0,
                    "TECHSUP_BREACH",
                    "Tech support: security breach",
                ),
                (
                    "firewall alert",
                    2.0,
                    "TECHSUP_FIREWALL",
                    "Tech support: firewall alert",
                ),
                (
                    "antivirus expired",
                    2.0,
                    "TECHSUP_AV_EXPIRED",
                    "Tech support: antivirus expired",
                ),
                (
                    "subscription renewal",
                    1.5,
                    "TECHSUP_RENEWAL",
                    "Tech support: renewal",
                ),
                (
                    "geek squad",
                    1.5,
                    "TECHSUP_GEEKSQUAD",
                    "Tech support: geek squad",
                ),
                (
                    "norton security",
                    1.0,
                    "TECHSUP_NORTON",
                    "Tech support: norton security",
                ),
                (
                    "mcafee renewal",
                    1.5,
                    "TECHSUP_MCAFEE",
                    "Tech support: mcafee renewal",
                ),
                // ═══ Job / employment scams (10 patterns) ═══
                (
                    "home-based business",
                    2.0,
                    "JOB_HOME_BIZ",
                    "Job scam: home-based business",
                ),
                (
                    "data entry job",
                    1.5,
                    "JOB_DATA_ENTRY",
                    "Job scam: data entry",
                ),
                (
                    "earn per click",
                    2.0,
                    "JOB_PER_CLICK",
                    "Job scam: earn per click",
                ),
                (
                    "stuffing envelopes",
                    2.5,
                    "JOB_ENVELOPES",
                    "Job scam: stuffing envelopes",
                ),
                (
                    "secret shopper",
                    2.0,
                    "JOB_SECRET_SHOPPER",
                    "Job scam: secret shopper",
                ),
                (
                    "mystery shopper",
                    2.0,
                    "JOB_MYSTERY_SHOPPER",
                    "Job scam: mystery shopper",
                ),
                (
                    "part-time income",
                    1.0,
                    "JOB_PART_TIME",
                    "Job scam: part-time income",
                ),
                (
                    "no experience needed",
                    1.5,
                    "JOB_NO_EXP",
                    "Job scam: no experience",
                ),
                (
                    "unlimited earning",
                    2.0,
                    "JOB_UNLIMITED",
                    "Job scam: unlimited earning",
                ),
                (
                    "mlm opportunity",
                    2.0,
                    "JOB_MLM",
                    "Job scam: MLM opportunity",
                ),
                // ═══ Legal / threats (8 patterns) ═══
                (
                    "legal action",
                    1.5,
                    "LEGAL_ACTION",
                    "Legal threat: legal action",
                ),
                ("lawsuit", 1.5, "LEGAL_LAWSUIT", "Legal threat: lawsuit"),
                ("subpoena", 2.0, "LEGAL_SUBPOENA", "Legal threat: subpoena"),
                (
                    "warrant for arrest",
                    3.0,
                    "LEGAL_WARRANT",
                    "Legal threat: warrant for arrest",
                ),
                (
                    "court summons",
                    2.5,
                    "LEGAL_SUMMONS",
                    "Legal threat: court summons",
                ),
                (
                    "irs notification",
                    2.0,
                    "LEGAL_IRS",
                    "Legal threat: IRS notification",
                ),
                (
                    "tax fraud",
                    2.0,
                    "LEGAL_TAX_FRAUD",
                    "Legal threat: tax fraud",
                ),
                (
                    "debt collection",
                    1.5,
                    "LEGAL_DEBT",
                    "Legal threat: debt collection",
                ),
            ];

            let (pats, penalties, ids, descs): (Vec<_>, Vec<_>, Vec<_>, Vec<_>) =
                patterns.into_iter().multiunzip();
            let single_word: Vec<bool> = pats
                .iter()
                .map(|p: &&str| !p.chars().any(char::is_whitespace))
                .collect();

            let automaton = AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&pats)
                .ok()?;

            Some(SpamPhraseSet {
                automaton,
                penalties,
                ids,
                descriptions: descs,
                single_word,
            })
        })
        .as_ref()
}

trait MultiUnzip {
    type Output;
    fn multiunzip(self) -> Self::Output;
}

impl<I, A, B, C, D> MultiUnzip for I
where
    I: Iterator<Item = (A, B, C, D)>,
{
    type Output = (Vec<A>, Vec<B>, Vec<C>, Vec<D>);
    fn multiunzip(self) -> Self::Output {
        let mut va = Vec::new();
        let mut vb = Vec::new();
        let mut vc = Vec::new();
        let mut vd = Vec::new();
        for (a, b, c, d) in self {
            va.push(a);
            vb.push(b);
            vc.push(c);
            vd.push(d);
        }
        (va, vb, vc, vd)
    }
}

/// Whether a character is invisible/zero-width and must be stripped before
/// tokenization or phrase matching (such characters silently split or join
/// words without any visual trace).
pub fn is_invisible_char(c: char) -> bool {
    matches!(
        c,
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{00AD}'
    )
}

/// Normalize leet-speak and common character substitutions.
/// Maps common obfuscation characters to their ASCII equivalents so that
/// phrases like "V1@gr@" are matched against "viagra" by the Aho-Corasick
/// automaton. Runs in a single pass over the input string.
pub fn normalize_leet_speak(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for c in text.chars() {
        if is_invisible_char(c) {
            // Strip zero-width characters
            continue;
        }
        // Digit and homoglyph substitutions only. Deliberately NOT
        // mapped: 'q'→'g' (not a leet convention — it rewrote every
        // "quick" into "guick" and broke phrase matching), and the global
        // '!'→'i' / '|'→'l' rewrites, which mangled ordinary prose
        // ("act now!" → "act nowi") far more often than they decoded
        // obfuscation ('1' already covers the leet-i shape).
        let replacement = match c {
            '0' | 'Ø' | 'ø' => 'o',
            '1' | 'ℓ' => 'l',
            '3' | 'є' | 'ε' => 'e',
            '4' | '@' | 'Λ' => 'a',
            '5' | '$' => 's',
            '6' | 'б' => 'g',
            '7' | '+' => 't',
            '8' | 'ß' => 'b',
            '9' => 'g',
            'í' | 'ì' | 'ï' => 'i',
            'Ρ' | 'ρ' => 'p', // Greek rho
            'Ν' | 'ν' => 'n', // Greek nu
            'Κ' | 'κ' => 'k', // Greek kappa
            'Α' | 'α' => 'a', // Greek alpha
            'Ε' => 'e',       // Greek capital epsilon (lowercase already covered above)
            'Ο' | 'ο' => 'o', // Greek omicron
            'а' => 'a',       // Cyrillic а
            'е' => 'e',       // Cyrillic е
            'о' => 'o',       // Cyrillic о
            'р' => 'p',       // Cyrillic р
            'с' => 'c',       // Cyrillic с
            'х' => 'x',       // Cyrillic х
            other => other,
        };
        result.push(replacement);
    }
    result
}

/// Decode HTML entities (numeric decimal/hex plus the common named ones)
/// so "vi&#103;ra"-style obfuscation is matched against its plain form.
///
/// Bounded:the pass is skipped entirely when the text contains no `&`, an
/// entity candidate must terminate within a 12-byte window (real entities
/// are at most ~10 bytes), and the output can only shrink relative to the
/// input — never expand.
pub fn decode_html_entities(text: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;

    if !text.contains('&') {
        return Cow::Borrowed(text);
    }

    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < text.len() {
        if !text[i..].starts_with('&') {
            // Copy the run up to the next '&' wholesale.
            let next_amp = text[i..].find('&').map_or(text.len(), |rel| i + rel);
            out.push_str(&text[i..next_amp]);
            i = next_amp;
            continue;
        }

        // Entity candidates must end with ';' close by; anything else is
        // literal text.
        let window_end = text.floor_char_boundary((i + 12).min(text.len()));
        let Some(semi_rel) = text[i..window_end].find(';') else {
            out.push('&');
            i += 1;
            continue;
        };
        let entity = &text[i + 1..i + semi_rel];
        let decoded = if let Some(hex) = entity
            .strip_prefix("#x")
            .or_else(|| entity.strip_prefix("#X"))
        {
            u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
        } else if let Some(dec) = entity.strip_prefix('#') {
            dec.parse::<u32>().ok().and_then(char::from_u32)
        } else {
            match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some('\u{00A0}'),
                _ => None,
            }
        };

        match decoded {
            Some(c) => {
                out.push(c);
                i += semi_rel + 1;
            }
            None => {
                out.push('&');
                i += 1;
            }
        }
    }
    Cow::Owned(out)
}

/// Analyze message content (body text) for spam indicators
pub fn score_content(body: &str) -> ContentScore {
    let mut findings = Vec::new();

    // ONE lowercased copy shared by every check that needs case-insensitive
    // matching — previously the HTML-tag checks alone each allocated their
    // own `to_lowercase()` copy of the full body.
    let lower_body = body.to_lowercase();

    // 1. Aho-Corasick phrase matching (raw + obfuscation-normalized)
    if let Some(phrases) = spam_phrase_set() {
        let mut matched = vec![false; phrases.ids.len()];

        // Pass 1:match against the raw body (the automaton is already
        // ASCII-case-insensitive — no lowercase copy needed here).
        for mat in phrases.automaton.find_iter(body) {
            let idx = mat.pattern().as_usize();
            matched[idx] = true;
        }

        // Pass 2:match against HTML-entity-decoded + leet-speak–normalized
        // text ("vi&#97;gr&#97;" and "v1@gr@" both resolve to "viagra").
        let normalized = normalize_leet_speak(&decode_html_entities(body));
        if normalized != body {
            for mat in phrases.automaton.find_iter(&normalized) {
                let idx = mat.pattern().as_usize();
                matched[idx] = true;
            }
        }

        // Collect deduplicated findings. Single common words ("urgent",
        // "expire", …) contribute only HALF their base penalty:alone they
        // are strong false-positive sources on legitimate mail (a message
        // saying "this is urgent" is not spam by that fact alone). Multi-
        // word phrases retain the full penalty.
        for (idx, &hit) in matched.iter().enumerate() {
            if hit {
                let base = phrases.penalties[idx];
                let penalty = if phrases.single_word[idx] {
                    base * 0.5
                } else {
                    base
                };
                findings.push(ContentFinding {
                    id: phrases.ids[idx],
                    description: phrases.descriptions[idx].to_string(),
                    penalty,
                });
            }
        }
    }

    // 2. ALL-CAPS ratio — single pass over the chars, no intermediate
    // Vec<char> copy of every alphabetic character.
    let mut alpha_count = 0usize;
    let mut upper_count = 0usize;
    for c in body.chars().filter(|c| c.is_alphabetic()) {
        alpha_count += 1;
        if c.is_uppercase() {
            upper_count += 1;
        }
    }
    if alpha_count > 20 {
        let ratio = upper_count as f64 / alpha_count as f64;
        if ratio > 0.7 {
            findings.push(ContentFinding {
                id: "CAPS_HEAVY",
                description: format!("High uppercase ratio: {:.0}%", ratio * 100.0),
                penalty: 2.0,
            });
        } else if ratio > 0.5 {
            findings.push(ContentFinding {
                id: "CAPS_MODERATE",
                description: format!("Moderate uppercase ratio: {:.0}%", ratio * 100.0),
                penalty: 1.0,
            });
        }
    }

    // 3. Excessive exclamation marks
    let exclamation_count = body.matches('!').count();
    if exclamation_count > 5 {
        let penalty = (exclamation_count as f64 * 0.2).min(3.0);
        findings.push(ContentFinding {
            id: "EXCESSIVE_EXCLAMATION",
            description: format!("{} exclamation marks", exclamation_count),
            penalty,
        });
    }

    // 4. Zero-width / invisible character obfuscation
    let invisible_count = body.chars().filter(|c| is_invisible_char(*c)).count();
    if invisible_count > 0 {
        findings.push(ContentFinding {
            id: "INVISIBLE_CHARS",
            description: format!(
                "{} invisible/zero-width characters detected",
                invisible_count
            ),
            penalty: (invisible_count as f64 * 0.5).min(5.0),
        });
    }

    // 5. HTML heavy (img tags, excessive links) — reuses the single
    // lowercased copy from above.
    let img_count = lower_body.matches("<img").count();
    if img_count > 3 {
        findings.push(ContentFinding {
            id: "EXCESSIVE_IMAGES",
            description: format!("{} embedded images", img_count),
            penalty: 1.5,
        });
    }
    let link_count = lower_body.matches("<a ").count() + lower_body.matches("<a\t").count();
    if link_count > 10 {
        findings.push(ContentFinding {
            id: "EXCESSIVE_LINKS",
            description: format!("{} links in message", link_count),
            penalty: 2.0,
        });
    }

    // 6. Very short body (often spam/phish with just a link)
    let text_len = body.trim().len();
    if text_len > 0 && text_len < 20 {
        findings.push(ContentFinding {
            id: "VERY_SHORT_BODY",
            description: "Message body is very short".into(),
            penalty: 1.0,
        });
    }

    let total_score: f64 = findings.iter().map(|f| f.penalty).sum();
    ContentScore {
        score: total_score,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leet_speak_no_prose_mangling() {
        // Fail-first: 'q'→'g' is not a leet convention and the global
        // '!'→'i' / '|'→'l' rewrites mangled ordinary prose ("quick loan"
        // became "guick loan" and stopped matching the spam phrase).
        assert_eq!(normalize_leet_speak("quick"), "quick");
        assert_eq!(normalize_leet_speak("quick!"), "quick!");
        assert_eq!(normalize_leet_speak("a|b"), "a|b");
        // Digit/homoglyph mappings are kept.
        assert_eq!(normalize_leet_speak("qu1ck l0an"), "qulck loan");
        assert_eq!(normalize_leet_speak("v1@gr4"), "vlagra");
    }

    #[test]
    fn test_quick_loan_phrase_matches_after_normalization() {
        // Fail-first: with 'q'→'g' active, "quick l0an approval" only ever
        // normalized to "guick loan approval" and the FINANCIAL_QUICK_LOAN
        // phrase never matched via the normalized pass.
        let result = score_content("quick l0an approval guaranteed!");
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.id == "FINANCIAL_QUICK_LOAN"),
            "quick loan phrase must match through leet normalization: {:?}",
            result.findings
        );
    }

    #[test]
    fn test_spam_phrase_detection() {
        let body = "Congratulations! You have won a million dollars! Act now to claim your prize!";
        let result = score_content(body);
        assert!(result.findings.iter().any(|f| f.id == "FINANCIAL_WON"));
        assert!(result.findings.iter().any(|f| f.id == "FINANCIAL_MILLION"));
        assert!(result.findings.iter().any(|f| f.id == "URGENCY_ACT_NOW"));
        assert!(result.score > 5.0);
    }

    #[test]
    fn test_all_caps() {
        let body = "THIS IS A COMPLETELY UPPERCASE MESSAGE WITH LOTS OF SHOUTING";
        let result = score_content(body);
        assert!(result.findings.iter().any(|f| f.id == "CAPS_HEAVY"));
    }

    #[test]
    fn test_invisible_characters() {
        let body = "Hello\u{200B}World\u{200C}Test\u{200D}Check";
        let result = score_content(body);
        assert!(result.findings.iter().any(|f| f.id == "INVISIBLE_CHARS"));
    }

    #[test]
    fn test_clean_content() {
        let body = "Hi John, just wanted to follow up on our meeting from Tuesday. \
                     Could you send me the quarterly report when you get a chance? Thanks, Alice.";
        let result = score_content(body);
        assert!(result.score < 1.0, "Clean email scored {}", result.score);
    }

    #[test]
    fn test_phishing_content() {
        let body = "Your account has been suspended. Please verify your account \
                     immediately. Click here to login. Update your payment information.";
        let result = score_content(body);
        assert!(result.findings.iter().any(|f| f.id == "PHISH_VERIFY"));
        assert!(result.findings.iter().any(|f| f.id == "PHISH_LOGIN"));
        assert!(result.score > 4.0);
    }

    // ── F10:HTML entity decoding in the normalization pass ─────────────

    #[test]
    fn test_decode_html_entities_numeric_and_named() {
        // Decimal numeric entities.
        assert_eq!(decode_html_entities("vi&#97;gr&#97;"), "viagra");
        // Hex numeric entities (both cases of the x prefix).
        assert_eq!(decode_html_entities("&#x76;iagra"), "viagra");
        assert_eq!(decode_html_entities("&#X76;iagra"), "viagra");
        // Common named entities.
        assert_eq!(decode_html_entities("a &amp; b &lt;c&gt;"), "a & b <c>");
        assert_eq!(
            decode_html_entities("&quot;q&quot; &apos;a&apos;"),
            "\"q\" 'a'"
        );
        // No '&' at all — borrowed, zero-copy.
        let plain = "no entities here";
        assert!(matches!(
            decode_html_entities(plain),
            std::borrow::Cow::Borrowed(_)
        ));
        // Unterminated / unknown candidates stay literal.
        assert_eq!(
            decode_html_entities("AT&T &unknown; &# ;"),
            "AT&T &unknown; &# ;"
        );
    }

    #[test]
    fn test_entity_obfuscated_spam_phrase_detected() {
        // Fail-first:"vi&#97;gr&#97;" (viagra) previously slipped past both
        // the raw and the leet-normalization passes.
        let result = score_content("cheap vi&#97;gr&#97; online pharmacy deal");
        assert!(
            result.findings.iter().any(|f| f.id == "PHARMA_VIAGRA"),
            "entity-obfuscated 'viagra' must match: {:?}",
            result.findings
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.id == "PHARMA_ONLINE" || f.id == "PHARMA_GENERIC"),
            "phrases around the entities must still match: {:?}",
            result.findings
        );
    }

    #[test]
    fn test_entity_decode_does_not_overreach() {
        // Ordinary ampersand prose must not be mangled into matches.
        let result = score_content("Q3 plans &amp; budgets — see attached report");
        assert!(
            result.score < 1.0,
            "clean prose with a named entity must stay clean, got {} ({:?})",
            result.score,
            result.findings
        );
    }

    #[test]
    fn test_html_tag_counts_still_fire() {
        // Regression for the shared-lowercase-copy refactor:the tag counts
        // must still detect heavy HTML.
        let mut body = String::new();
        for i in 0..15 {
            body.push_str(&format!("<IMG src=\"x{i}.png\"> "));
        }
        for i in 0..12 {
            body.push_str(&format!("<a href=\"l{i}\">link</a> "));
        }
        let result = score_content(&body);
        assert!(result.findings.iter().any(|f| f.id == "EXCESSIVE_IMAGES"));
        assert!(result.findings.iter().any(|f| f.id == "EXCESSIVE_LINKS"));
    }
}
