"""
ApexMail Customer Profiles — 50+ realistic simulated customers.

Each profile precisely mirrors what the system prompt context template expects.
Built from actual repo database schemas, billing plans, feature flags,
webhook event types, domain states, and real-world customer scenarios.

Industries: SaaS, E-commerce, EdTech, FinTech, Healthcare, Legal, Real Estate,
Non-profit, Agency, Logistics, Media, Gaming, Travel, Food/Restaurant,
Crypto/Web3, HR/Recruitment, Insurance, IoT/Hardware, Government

Problem types: DKIM failures, SPF issues, bounce spikes, complaint spikes,
webhook failures, IP blocklisting, quota exhaustion, deliverability drops,
account suspension, pending verification, API authentication issues,
template rendering, greylist delays, warmup struggles, dunning/billing issues,
GDPR requests, SSO misconfiguration, subaccount management
"""

# ═══════════════════════════════════════════════════════════════════════
# 50 CUSTOMER PROFILES — organized by plan tier + scenario
# ═══════════════════════════════════════════════════════════════════════

PROFILES = {

    # ══════════════════════════════════════════════════════════════════
    # FREE PLAN (4 profiles)
    # ══════════════════════════════════════════════════════════════════

    "free_hitting_limits": {
        "account_id": "acct_2n5v8q",
        "plan_name": "Free",
        "plan_price": "0",
        "emails_sent": "980",
        "email_limit": "1,000",
        "api_calls": "8,900",
        "api_call_limit": "10,000",
        "team_count": "1",
        "team_limit": "1",
        "created_at": "2026-01-28",
        "domain_count": "1",
        "domain_details": "- myshop.com: Verified (SPF: pass, DKIM: pass, DMARC: none — no DMARC record)",
        "recent_events": "- 980 sent, 960 delivered (98.0%), 8 bounced (0.8%), 0 complaints",
        "open_issues": "- Approaching email limit: 980/1,000 (98% used)",
        "billing_cycle_date": "Free plan (no billing cycle)",
        "team_members": "- owner@myshop.com (Admin, owner)",
        "api_keys": "- 'My Key' (am_live_2n5v...) — scopes: send — last used: today",
        "webhooks_summary": "- No webhooks (not available on Free plan)",
        "template_count": "1",
        "templates_summary": "- 'Order Receipt' (tmpl_rcpt01)",
        "contact_count": "312",
    },

    "free_brand_new": {
        "account_id": "acct_qw3r7t",
        "plan_name": "Free",
        "plan_price": "0",
        "emails_sent": "0",
        "email_limit": "1,000",
        "api_calls": "23",
        "api_call_limit": "10,000",
        "team_count": "1",
        "team_limit": "1",
        "created_at": "2026-02-17",
        "domain_count": "0",
        "domain_details": "- No domains configured yet",
        "recent_events": "- No sending activity",
        "open_issues": "- No domains added — cannot send until a domain is verified",
        "billing_cycle_date": "Free plan (no billing cycle)",
        "team_members": "- maria@mariastudio.com (Admin, owner)",
        "api_keys": "- 'Default Key' (am_live_qw3r...) — scopes: send, read — last used: 30 minutes ago",
        "webhooks_summary": "- No webhooks (not available on Free plan)",
        "template_count": "0",
        "templates_summary": "- No templates created",
        "contact_count": "0",
    },

    "free_hobby_blogger": {
        "account_id": "acct_hb4m2k",
        "plan_name": "Free",
        "plan_price": "0",
        "emails_sent": "340",
        "email_limit": "1,000",
        "api_calls": "1,200",
        "api_call_limit": "10,000",
        "team_count": "1",
        "team_limit": "1",
        "created_at": "2025-10-05",
        "domain_count": "1",
        "domain_details": "- craftyblog.net: Verified (SPF: pass, DKIM: pass, DMARC: none)",
        "recent_events": "- 340 sent, 335 delivered (98.5%), 3 bounced (0.9%), 0 complaints",
        "open_issues": "None",
        "billing_cycle_date": "Free plan (no billing cycle)",
        "team_members": "- jenny@craftyblog.net (Admin, owner)",
        "api_keys": "- 'Blog Notifications' (am_live_hb4m...) — scopes: send — last used: 2 days ago",
        "webhooks_summary": "- No webhooks (not available on Free plan)",
        "template_count": "1",
        "templates_summary": "- 'New Post Alert' (tmpl_npa01)",
        "contact_count": "178",
    },

    "free_spf_broken": {
        "account_id": "acct_sp2f8z",
        "plan_name": "Free",
        "plan_price": "0",
        "emails_sent": "450",
        "email_limit": "1,000",
        "api_calls": "3,200",
        "api_call_limit": "10,000",
        "team_count": "1",
        "team_limit": "1",
        "created_at": "2025-12-01",
        "domain_count": "1",
        "domain_details": "- petgrooming.co: Verified (SPF: fail — multiple SPF records, DKIM: pass, DMARC: none)",
        "recent_events": "- 450 sent, 380 delivered (84.4%), 25 bounced (5.6%), 0 complaints\n- Deliverability dropped after adding Mailchimp SPF record 5 days ago",
        "open_issues": "- SPF failure: 2 SPF TXT records found (ApexMail + Mailchimp). Only 1 SPF record per domain allowed.",
        "billing_cycle_date": "Free plan (no billing cycle)",
        "team_members": "- sam@petgrooming.co (Admin, owner)",
        "api_keys": "- 'Appointment Reminders' (am_live_sp2f...) — scopes: send — last used: today",
        "webhooks_summary": "- No webhooks (not available on Free plan)",
        "template_count": "1",
        "templates_summary": "- 'Appointment Reminder' (tmpl_apt01)",
        "contact_count": "520",
    },

    # ══════════════════════════════════════════════════════════════════
    # STARTER PLAN (6 profiles)
    # ══════════════════════════════════════════════════════════════════

    "starter_healthy": {
        "account_id": "acct_8f3k2j",
        "plan_name": "Starter",
        "plan_price": "29",
        "emails_sent": "18,240",
        "email_limit": "25,000",
        "api_calls": "142,000",
        "api_call_limit": "250,000",
        "team_count": "2",
        "team_limit": "3",
        "created_at": "2025-06-15",
        "domain_count": "1",
        "domain_details": "- acmecorp.com: Verified (SPF: pass, DKIM: pass, DMARC: pass)",
        "recent_events": "- 18,240 sent, 17,890 delivered (98.1%), 52 bounced (0.3%), 3 complaints (0.02%)",
        "open_issues": "None",
        "billing_cycle_date": "Renews on the 15th of each month",
        "team_members": "- alice@acmecorp.com (Admin, owner)\n- bob@acmecorp.com (Editor)",
        "api_keys": "- 'Production Key' (am_live_8f3k...) — scopes: send, read — last used: 2h ago\n- 'Test Key' (am_test_2j1m...) — scopes: all — last used: 5 days ago",
        "webhooks_summary": "- wh_3k2j1m: https://acmecorp.com/webhook — Events: delivered, bounced — Status: failing (12 consecutive failures, HTTP 404)",
        "template_count": "3",
        "templates_summary": "- 'Welcome Email' (tmpl_welc01)\n- 'Order Confirmation' (tmpl_ordr01)\n- 'old-newsletter-v1' (tmpl_news01)",
        "contact_count": "4,230",
    },

    "starter_webhook_dead": {
        "account_id": "acct_wh7d3k",
        "plan_name": "Starter",
        "plan_price": "29",
        "emails_sent": "12,400",
        "email_limit": "25,000",
        "api_calls": "89,000",
        "api_call_limit": "250,000",
        "team_count": "2",
        "team_limit": "3",
        "created_at": "2025-08-22",
        "domain_count": "2",
        "domain_details": "- bakerydelight.com: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)\n- orders.bakerydelight.com: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)",
        "recent_events": "- 12,400 sent, 12,150 delivered (98.0%), 38 bounced (0.3%), 1 complaint (0.01%)",
        "open_issues": "- Webhook wh_bd01 auto-disabled after 8 consecutive failures (HTTP 500) over 24 hours",
        "billing_cycle_date": "Renews on the 22nd of each month",
        "team_members": "- claire@bakerydelight.com (Admin, owner)\n- paul@bakerydelight.com (Viewer)",
        "api_keys": "- 'Order System' (am_live_wh7d...) — scopes: send, read — last used: 1 hour ago",
        "webhooks_summary": "- wh_bd01: https://api.bakerydelight.com/email-events — Events: delivered, bounced, opened — Status: auto-disabled (8 consecutive failures, last error: HTTP 500)",
        "template_count": "4",
        "templates_summary": "- 'Order Placed' (tmpl_op01)\n- 'Order Ready' (tmpl_or01)\n- 'Loyalty Reward' (tmpl_lr01)\n- 'Weekly Specials' (tmpl_ws01)",
        "contact_count": "2,100",
    },

    "starter_over_limit": {
        "account_id": "acct_ol5n2p",
        "plan_name": "Starter",
        "plan_price": "29",
        "emails_sent": "27,800",
        "email_limit": "25,000",
        "api_calls": "198,000",
        "api_call_limit": "250,000",
        "team_count": "3",
        "team_limit": "3",
        "created_at": "2025-04-01",
        "domain_count": "2",
        "domain_details": "- fitnesshub.io: Verified (SPF: pass, DKIM: pass, DMARC: pass)\n- mail.fitnesshub.io: Verified (SPF: pass, DKIM: pass, DMARC: pass)",
        "recent_events": "- 27,800 sent (2,800 overage), 27,200 delivered (97.8%), 112 bounced (0.4%), 8 complaints (0.03%)",
        "open_issues": "- Email overage: 2,800 emails over 25,000 limit (billed at $0.50/1,000 = $1.40 overage)",
        "billing_cycle_date": "Renews on the 1st of each month",
        "team_members": "- coach@fitnesshub.io (Admin, owner)\n- sarah@fitnesshub.io (Editor)\n- mike@fitnesshub.io (Viewer)",
        "api_keys": "- 'App Backend' (am_live_ol5n...) — scopes: send, read, contacts — last used: today",
        "webhooks_summary": "- wh_fh01: https://api.fitnesshub.io/hooks — Events: delivered, bounced — Status: active",
        "template_count": "6",
        "templates_summary": "- 'Workout Reminder' (tmpl_wr01)\n- 'Class Booking' (tmpl_cb01)\n- 'Progress Report' (tmpl_pr01)\n- (3 more)",
        "contact_count": "8,900",
    },

    "starter_restaurant": {
        "account_id": "acct_rs4t7m",
        "plan_name": "Starter",
        "plan_price": "29",
        "emails_sent": "6,200",
        "email_limit": "25,000",
        "api_calls": "45,000",
        "api_call_limit": "250,000",
        "team_count": "2",
        "team_limit": "3",
        "created_at": "2025-11-10",
        "domain_count": "1",
        "domain_details": "- sushimaster.jp: Verified (SPF: pass, DKIM: pass, DMARC: pass)",
        "recent_events": "- 6,200 sent, 6,100 delivered (98.4%), 15 bounced (0.2%), 2 complaints (0.03%)",
        "open_issues": "None",
        "billing_cycle_date": "Renews on the 10th of each month",
        "team_members": "- yuki@sushimaster.jp (Admin, owner)\n- kenji@sushimaster.jp (Editor)",
        "api_keys": "- 'Reservation System' (am_live_rs4t...) — scopes: send — last used: 3 hours ago",
        "webhooks_summary": "- wh_sm01: https://app.sushimaster.jp/webhooks — Events: delivered, bounced — Status: active",
        "template_count": "3",
        "templates_summary": "- 'Reservation Confirmed' (tmpl_rc01)\n- 'Order Pickup Ready' (tmpl_opr01)\n- 'Weekly Menu' (tmpl_wm01)",
        "contact_count": "3,400",
    },

    "starter_nonprofit": {
        "account_id": "acct_np8g1d",
        "plan_name": "Starter",
        "plan_price": "29",
        "emails_sent": "15,600",
        "email_limit": "25,000",
        "api_calls": "72,000",
        "api_call_limit": "250,000",
        "team_count": "3",
        "team_limit": "3",
        "created_at": "2025-03-20",
        "domain_count": "1",
        "domain_details": "- cleanocean.org: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)",
        "recent_events": "- 15,600 sent, 14,800 delivered (94.9%), 340 bounced (2.2%), 45 complaints (0.29%)\n- Bounce rate crossed 2% threshold 4 days ago after annual donor list blast",
        "open_issues": "- Bounce rate 2.2% (threshold: 2%) — stale donor email list\n- Complaint rate 0.29% (threshold: 0.3%) — approaching danger zone",
        "billing_cycle_date": "Renews on the 20th of each month",
        "team_members": "- director@cleanocean.org (Admin, owner)\n- volunteer1@cleanocean.org (Editor)\n- volunteer2@cleanocean.org (Editor)",
        "api_keys": "- 'Newsletter Key' (am_live_np8g...) — scopes: send, contacts — last used: yesterday",
        "webhooks_summary": "- wh_co01: https://crm.cleanocean.org/hooks — Events: bounced, unsubscribed, complained — Status: active",
        "template_count": "5",
        "templates_summary": "- 'Donation Thank You' (tmpl_dt01)\n- 'Monthly Newsletter' (tmpl_mn01)\n- 'Event Invitation' (tmpl_ei01)\n- 'Volunteer Welcome' (tmpl_vw01)\n- 'Annual Report' (tmpl_ar01)",
        "contact_count": "12,500",
    },

    "starter_bounce_spike": {
        "account_id": "acct_bs6q3r",
        "plan_name": "Starter",
        "plan_price": "29",
        "emails_sent": "22,100",
        "email_limit": "25,000",
        "api_calls": "165,000",
        "api_call_limit": "250,000",
        "team_count": "2",
        "team_limit": "3",
        "created_at": "2025-07-03",
        "domain_count": "1",
        "domain_details": "- tutorzone.co: Verified (SPF: pass, DKIM: pass, DMARC: pass)",
        "recent_events": "- 22,100 sent, 19,600 delivered (88.7%), 2,430 bounced (11.0%), 12 complaints (0.05%)\n- Bounce spike: imported purchased contact list 2 days ago, 2,200 hard bounces",
        "open_issues": "- Bounce rate 11.0% (threshold: 2%) — CRITICAL, sending at risk of suspension\n- 2,200 hard-bounced addresses auto-added to suppression list",
        "billing_cycle_date": "Renews on the 3rd of each month",
        "team_members": "- admin@tutorzone.co (Admin, owner)\n- marketing@tutorzone.co (Editor)",
        "api_keys": "- 'Main Key' (am_live_bs6q...) — scopes: send, read — last used: today",
        "webhooks_summary": "- wh_tz01: https://api.tutorzone.co/hook — Events: bounced — Status: active",
        "template_count": "2",
        "templates_summary": "- 'Course Enrollment' (tmpl_ce01)\n- 'Lesson Reminder' (tmpl_lr01)",
        "contact_count": "15,200",
    },

    # ══════════════════════════════════════════════════════════════════
    # PRO PLAN (6 profiles)
    # ══════════════════════════════════════════════════════════════════

    "pro_new_user": {
        "account_id": "acct_6j2t9m",
        "plan_name": "Pro",
        "plan_price": "59",
        "emails_sent": "320",
        "email_limit": "50,000",
        "api_calls": "1,200",
        "api_call_limit": "500,000",
        "team_count": "3",
        "team_limit": "5",
        "created_at": "2026-02-10",
        "domain_count": "2",
        "domain_details": (
            "- newsletter.startupxyz.com: Pending verification (SPF: not checked, DKIM: not checked, DMARC: not checked)\n"
            "- startupxyz.com: Verified (SPF: pass, DKIM: pass, DMARC: none)"
        ),
        "recent_events": "- 320 sent (all from startupxyz.com), 315 delivered (98.4%), 2 bounced (0.6%), 0 complaints",
        "open_issues": "- newsletter.startupxyz.com pending domain verification",
        "billing_cycle_date": "Renews on the 10th of each month",
        "team_members": "- founder@startupxyz.com (Admin, owner)\n- dev@startupxyz.com (Editor)\n- designer@startupxyz.com (Viewer)",
        "api_keys": "- 'Main Key' (am_live_6j2t...) — scopes: send, read — last used: yesterday",
        "webhooks_summary": "- No webhooks configured",
        "template_count": "0",
        "templates_summary": "- No templates created yet",
        "contact_count": "85",
    },

    "pro_agency_multi_domain": {
        "account_id": "acct_ag3m8p",
        "plan_name": "Pro",
        "plan_price": "59",
        "emails_sent": "38,500",
        "email_limit": "50,000",
        "api_calls": "312,000",
        "api_call_limit": "500,000",
        "team_count": "5",
        "team_limit": "5",
        "created_at": "2025-05-12",
        "domain_count": "5",
        "domain_details": (
            "- pixelcraft.agency: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- mail.clientA.com: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)\n"
            "- mail.clientB.io: Verified (SPF: pass, DKIM: pass, DMARC: none)\n"
            "- news.clientC.co: Verified (SPF: pass, DKIM: fail — record not found, DMARC: fail)\n"
            "- mail.clientD.net: Pending verification"
        ),
        "recent_events": (
            "- 38,500 sent, 37,100 delivered (96.4%), 520 bounced (1.4%), 18 complaints (0.05%)\n"
            "- news.clientC.co: 2,100 sent, 1,400 delivered (66.7%) — DKIM failure causing bounces"
        ),
        "open_issues": "- DKIM failure on news.clientC.co — client changed DNS provider, CNAME record lost\n- mail.clientD.net pending verification for 2 days",
        "billing_cycle_date": "Renews on the 12th of each month",
        "team_members": "- owner@pixelcraft.agency (Admin, owner)\n- dev@pixelcraft.agency (Editor)\n- designer@pixelcraft.agency (Viewer)\n- clientA@pixelcraft.agency (Editor)\n- clientB@pixelcraft.agency (Editor)",
        "api_keys": "- 'Production' (am_live_ag3m...) — scopes: all — last used: 30 min ago\n- 'Staging' (am_test_9q2w...) — scopes: all — last used: 2 days ago",
        "webhooks_summary": "- wh_pc01: https://api.pixelcraft.agency/hooks — Events: all — Status: active",
        "template_count": "12",
        "templates_summary": "- 'ClientA Welcome' (tmpl_ca01)\n- 'ClientB Newsletter' (tmpl_cb01)\n- 'ClientC Promo' (tmpl_cc01)\n- (9 more client templates)",
        "contact_count": "18,700",
    },

    "pro_edtech": {
        "account_id": "acct_ed5t3k",
        "plan_name": "Pro",
        "plan_price": "59",
        "emails_sent": "28,900",
        "email_limit": "50,000",
        "api_calls": "210,000",
        "api_call_limit": "500,000",
        "team_count": "4",
        "team_limit": "5",
        "created_at": "2025-09-01",
        "domain_count": "2",
        "domain_details": (
            "- learnfast.edu: Verified (SPF: pass, DKIM: pass, DMARC: pass)\n"
            "- notifications.learnfast.edu: Verified (SPF: pass, DKIM: pass, DMARC: pass)"
        ),
        "recent_events": "- 28,900 sent, 28,400 delivered (98.3%), 85 bounced (0.3%), 5 complaints (0.02%)",
        "open_issues": "None",
        "billing_cycle_date": "Renews on the 1st of each month",
        "team_members": "- admin@learnfast.edu (Admin, owner)\n- eng@learnfast.edu (Editor)\n- support@learnfast.edu (Editor)\n- marketing@learnfast.edu (Editor)",
        "api_keys": "- 'Backend' (am_live_ed5t...) — scopes: send, read, contacts — last used: 5 min ago\n- 'Test' (am_test_lf3k...) — scopes: all — last used: 1 week ago",
        "webhooks_summary": "- wh_lf01: https://api.learnfast.edu/email-events — Events: delivered, bounced, opened, clicked — Status: active",
        "template_count": "8",
        "templates_summary": "- 'Course Enrolled' (tmpl_ce01)\n- 'Assignment Due' (tmpl_ad01)\n- 'Grade Posted' (tmpl_gp01)\n- 'Certificate Ready' (tmpl_cr01)\n- (4 more)",
        "contact_count": "45,200",
    },

    "pro_realtor": {
        "account_id": "acct_rl7b2n",
        "plan_name": "Pro",
        "plan_price": "59",
        "emails_sent": "8,200",
        "email_limit": "50,000",
        "api_calls": "42,000",
        "api_call_limit": "500,000",
        "team_count": "4",
        "team_limit": "5",
        "created_at": "2025-10-15",
        "domain_count": "3",
        "domain_details": (
            "- premiumhomes.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- listings.premiumhomes.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- track.premiumhomes.com: Custom tracking domain — Verified (SSL active)"
        ),
        "recent_events": "- 8,200 sent, 8,100 delivered (98.8%), 12 bounced (0.1%), 1 complaint (0.01%)",
        "open_issues": "None",
        "billing_cycle_date": "Renews on the 15th of each month",
        "team_members": "- alex@premiumhomes.com (Admin, owner)\n- lisa@premiumhomes.com (Editor)\n- broker1@premiumhomes.com (Editor)\n- broker2@premiumhomes.com (Viewer)",
        "api_keys": "- 'CRM Integration' (am_live_rl7b...) — scopes: send, contacts, read — last used: today",
        "webhooks_summary": "- wh_ph01: https://crm.premiumhomes.com/apexmail — Events: delivered, opened, clicked — Status: active",
        "template_count": "5",
        "templates_summary": "- 'New Listing Alert' (tmpl_nla01)\n- 'Open House Invite' (tmpl_ohi01)\n- 'Price Drop' (tmpl_pd01)\n- 'Market Report' (tmpl_mr01)\n- 'Buyer Welcome' (tmpl_bw01)",
        "contact_count": "6,800",
    },

    "pro_dmarc_none": {
        "account_id": "acct_dm4c1q",
        "plan_name": "Pro",
        "plan_price": "59",
        "emails_sent": "42,300",
        "email_limit": "50,000",
        "api_calls": "380,000",
        "api_call_limit": "500,000",
        "team_count": "3",
        "team_limit": "5",
        "created_at": "2025-02-28",
        "domain_count": "2",
        "domain_details": (
            "- gadgetreview.com: Verified (SPF: pass, DKIM: pass, DMARC: none — no DMARC record)\n"
            "- alerts.gadgetreview.com: Verified (SPF: pass, DKIM: pass, DMARC: none)"
        ),
        "recent_events": (
            "- 42,300 sent, 39,800 delivered (94.1%), 890 bounced (2.1%), 42 complaints (0.10%)\n"
            "- Several phishing attempts spoofing gadgetreview.com detected by recipients"
        ),
        "open_issues": "- No DMARC policy on either domain — vulnerable to spoofing\n- Bounce rate 2.1% (threshold: 2%) — likely caused by spoofed mail hurting reputation",
        "billing_cycle_date": "Renews on the 28th of each month",
        "team_members": "- editor@gadgetreview.com (Admin, owner)\n- writer1@gadgetreview.com (Editor)\n- writer2@gadgetreview.com (Editor)",
        "api_keys": "- 'Newsletter' (am_live_dm4c...) — scopes: send, read — last used: today",
        "webhooks_summary": "- wh_gr01: https://api.gadgetreview.com/email — Events: delivered, bounced, complained — Status: active",
        "template_count": "4",
        "templates_summary": "- 'Review Alert' (tmpl_ra01)\n- 'Deal Digest' (tmpl_dd01)\n- 'Breaking News' (tmpl_bn01)\n- 'Subscriber Welcome' (tmpl_sw01)",
        "contact_count": "32,100",
    },

    "pro_template_issue": {
        "account_id": "acct_ti9k3w",
        "plan_name": "Pro",
        "plan_price": "59",
        "emails_sent": "15,600",
        "email_limit": "50,000",
        "api_calls": "95,000",
        "api_call_limit": "500,000",
        "team_count": "2",
        "team_limit": "5",
        "created_at": "2025-07-20",
        "domain_count": "1",
        "domain_details": "- vineyardtours.wine: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)",
        "recent_events": (
            "- 15,600 sent, 15,200 delivered (97.4%), 48 bounced (0.3%), 85 complaints (0.54%)\n"
            "- Complaint spike: 82 of 85 complaints came from last campaign 'Summer Wine Sale'\n"
            "- Complaints report: recipients say they never signed up"
        ),
        "open_issues": "- Complaint rate 0.54% (threshold: 0.3%) — CRITICAL, sending may be suspended\n- Campaign 'Summer Wine Sale' sent to purchased list — AUP violation risk",
        "billing_cycle_date": "Renews on the 20th of each month",
        "team_members": "- owner@vineyardtours.wine (Admin, owner)\n- marketing@vineyardtours.wine (Editor)",
        "api_keys": "- 'Main' (am_live_ti9k...) — scopes: send, campaigns, templates — last used: yesterday",
        "webhooks_summary": "- wh_vt01: https://vineyardtours.wine/hooks — Events: complained, unsubscribed — Status: active",
        "template_count": "3",
        "templates_summary": "- 'Tour Booking Confirmation' (tmpl_tbc01)\n- 'Summer Wine Sale' (tmpl_sws01)\n- 'Seasonal Menu' (tmpl_sm01)",
        "contact_count": "9,500",
    },

    # ══════════════════════════════════════════════════════════════════
    # GROWTH PLAN (8 profiles)
    # ══════════════════════════════════════════════════════════════════

    "growth_dkim_fail": {
        "account_id": "acct_9x7m4p",
        "plan_name": "Growth",
        "plan_price": "129",
        "emails_sent": "67,500",
        "email_limit": "100,000",
        "api_calls": "523,000",
        "api_call_limit": "1,000,000",
        "team_count": "6",
        "team_limit": "10",
        "created_at": "2024-11-20",
        "domain_count": "3",
        "domain_details": (
            "- notifications.techflow.io: Verified (SPF: pass, DKIM: pass, DMARC: pass)\n"
            "- marketing.techflow.io: DKIM FAILING (SPF: pass, DKIM: fail — record not found, DMARC: fail)\n"
            "- techflow.io: Verified (SPF: pass, DKIM: pass, DMARC: pass)"
        ),
        "recent_events": (
            "- 67,500 sent, 62,100 delivered (92.0%), 3,200 bounced (4.7%), 89 complaints (0.13%)\n"
            "- marketing.techflow.io: 4,200 sent, 2,800 delivered (66.7%), 1,100 bounced (26.2%)\n"
            "- Bounce spike started 3 days ago after DNS change"
        ),
        "open_issues": "- High bounce rate on marketing.techflow.io (26.2%) — threshold: 2%",
        "billing_cycle_date": "Renews on the 20th of each month",
        "team_members": "- cto@techflow.io (Admin, owner)\n- dev1@techflow.io (Editor)\n- dev2@techflow.io (Editor)\n- marketing@techflow.io (Editor)\n- support@techflow.io (Viewer)\n- intern@techflow.io (Viewer)",
        "api_keys": "- 'Backend API' (am_live_9x7m...) — scopes: send, read, contacts — last used: 1 min ago\n- 'Marketing Tool' (am_live_4p2q...) — scopes: send, campaigns — last used: 3 days ago",
        "webhooks_summary": "- wh_tf01: https://api.techflow.io/hooks/email — Events: all — Status: active\n- wh_tf02: https://marketing.techflow.io/events — Events: opened, clicked — Status: active",
        "template_count": "8",
        "templates_summary": "- 'Welcome Series - Day 1' (tmpl_ws01)\n- 'Welcome Series - Day 3' (tmpl_ws03)\n- 'Product Update' (tmpl_pu01)\n- 'February Newsletter' (tmpl_fn02)\n- (4 more templates)",
        "contact_count": "23,450",
    },

    "growth_saas_healthy": {
        "account_id": "acct_gs5h2r",
        "plan_name": "Growth",
        "plan_price": "129",
        "emails_sent": "78,200",
        "email_limit": "100,000",
        "api_calls": "890,000",
        "api_call_limit": "1,000,000",
        "team_count": "8",
        "team_limit": "10",
        "created_at": "2024-08-15",
        "domain_count": "4",
        "domain_details": (
            "- mail.projecthub.dev: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- alerts.projecthub.dev: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- marketing.projecthub.dev: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- track.projecthub.dev: Custom tracking domain — Verified (SSL active)"
        ),
        "recent_events": "- 78,200 sent, 77,400 delivered (99.0%), 196 bounced (0.3%), 8 complaints (0.01%)",
        "open_issues": "None",
        "billing_cycle_date": "Renews on the 15th of each month",
        "team_members": "- ceo@projecthub.dev (Admin, owner)\n- cto@projecthub.dev (Admin)\n- eng1@projecthub.dev (Editor)\n- eng2@projecthub.dev (Editor)\n- eng3@projecthub.dev (Editor)\n- marketing@projecthub.dev (Editor)\n- cs1@projecthub.dev (Viewer)\n- cs2@projecthub.dev (Viewer)",
        "api_keys": "- 'Production Transactional' (am_live_gs5h...) — scopes: send, read — last used: just now\n- 'Marketing' (am_live_mk2p...) — scopes: send, campaigns, templates — last used: 1 hour ago\n- 'Analytics' (am_live_an3q...) — scopes: read — last used: 10 min ago",
        "webhooks_summary": "- wh_ph01: https://api.projecthub.dev/email-events — Events: all — Status: active",
        "template_count": "15",
        "templates_summary": "- 'Welcome Email' (tmpl_we01)\n- 'Password Reset' (tmpl_pr01)\n- 'Invoice' (tmpl_inv01)\n- 'Trial Ending' (tmpl_te01)\n- (11 more)",
        "contact_count": "52,000",
    },

    "growth_ip_warmup": {
        "account_id": "acct_iw6p4q",
        "plan_name": "Growth",
        "plan_price": "129",
        "emails_sent": "12,000",
        "email_limit": "100,000",
        "api_calls": "180,000",
        "api_call_limit": "1,000,000",
        "team_count": "5",
        "team_limit": "10",
        "created_at": "2026-01-15",
        "domain_count": "2",
        "domain_details": (
            "- shoptrend.com: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)\n"
            "- promo.shoptrend.com: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)"
        ),
        "recent_events": (
            "- 12,000 sent, 10,800 delivered (90.0%), 480 bounced (4.0%), 24 complaints (0.2%)\n"
            "- Dedicated IP 203.0.113.50 — warming phase, reputation score: 45/100\n"
            "- Gmail deliverability: 72% (emails landing in spam during warmup)"
        ),
        "open_issues": "- Dedicated IP warming: only 35% through warmup schedule\n- Gmail spam placement during reputation building\n- Bounce rate 4.0% — expected during warmup but needs monitoring",
        "billing_cycle_date": "Renews on the 15th of each month",
        "team_members": "- ops@shoptrend.com (Admin, owner)\n- dev@shoptrend.com (Editor)\n- mktg@shoptrend.com (Editor)\n- cs@shoptrend.com (Viewer)\n- intern@shoptrend.com (Viewer)",
        "api_keys": "- 'Ecommerce Backend' (am_live_iw6p...) — scopes: send, read, contacts — last used: 5 min ago",
        "webhooks_summary": "- wh_st01: https://api.shoptrend.com/email — Events: all — Status: active",
        "template_count": "7",
        "templates_summary": "- 'Order Confirmation' (tmpl_oc01)\n- 'Shipping Update' (tmpl_su01)\n- 'Cart Abandoned' (tmpl_ca01)\n- 'Flash Sale' (tmpl_fs01)\n- (3 more)",
        "contact_count": "35,000",
    },

    "growth_gaming": {
        "account_id": "acct_gm8v3n",
        "plan_name": "Growth",
        "plan_price": "129",
        "emails_sent": "92,300",
        "email_limit": "100,000",
        "api_calls": "950,000",
        "api_call_limit": "1,000,000",
        "team_count": "7",
        "team_limit": "10",
        "created_at": "2024-12-01",
        "domain_count": "3",
        "domain_details": (
            "- accounts.pixelquest.gg: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- news.pixelquest.gg: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- pixelquest.gg: Verified (SPF: pass, DKIM: pass, DMARC: reject)"
        ),
        "recent_events": (
            "- 92,300 sent, 91,400 delivered (99.0%), 184 bounced (0.2%), 28 complaints (0.03%)\n"
            "- Approaching email limit: 92,300/100,000 (92.3% used) with 12 days remaining"
        ),
        "open_issues": "- Near email limit: 92.3% used with 12 days left in cycle\n- Near API limit: 95% used",
        "billing_cycle_date": "Renews on the 1st of each month",
        "team_members": "- admin@pixelquest.gg (Admin, owner)\n- backend@pixelquest.gg (Editor)\n- community@pixelquest.gg (Editor)\n- (4 more Viewers)",
        "api_keys": "- 'Game Server' (am_live_gm8v...) — scopes: send — last used: just now\n- 'Dashboard' (am_live_dk3x...) — scopes: read — last used: 1 hour ago",
        "webhooks_summary": "- wh_pq01: https://api.pixelquest.gg/email — Events: delivered, bounced — Status: active",
        "template_count": "6",
        "templates_summary": "- 'Account Verification' (tmpl_av01)\n- 'Password Reset' (tmpl_pr01)\n- 'Login Alert' (tmpl_la01)\n- 'Season Launch' (tmpl_sl01)\n- 'Tournament Invite' (tmpl_ti01)\n- 'Patch Notes' (tmpl_pn01)",
        "contact_count": "280,000",
    },

    "growth_logistics": {
        "account_id": "acct_lg4t8k",
        "plan_name": "Growth",
        "plan_price": "129",
        "emails_sent": "85,600",
        "email_limit": "100,000",
        "api_calls": "720,000",
        "api_call_limit": "1,000,000",
        "team_count": "9",
        "team_limit": "10",
        "created_at": "2024-06-20",
        "domain_count": "4",
        "domain_details": (
            "- notify.swiftship.co: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- tracking.swiftship.co: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- swiftship.co: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- track.swiftship.co: Custom tracking domain — Verified (SSL active)"
        ),
        "recent_events": "- 85,600 sent, 85,000 delivered (99.3%), 128 bounced (0.1%), 3 complaints (0.004%)",
        "open_issues": "None",
        "billing_cycle_date": "Renews on the 20th of each month",
        "team_members": "- ops@swiftship.co (Admin, owner)\n- (8 more team members: 5 Editors, 3 Viewers)",
        "api_keys": "- 'Tracking System' (am_live_lg4t...) — scopes: send, read — last used: just now\n- 'Admin' (am_live_ad2k...) — scopes: all — last used: 1 hour ago",
        "webhooks_summary": "- wh_ss01: https://api.swiftship.co/apexmail — Events: delivered, bounced, opened, clicked — Status: active",
        "template_count": "10",
        "templates_summary": "- 'Shipment Created' (tmpl_sc01)\n- 'In Transit' (tmpl_it01)\n- 'Out for Delivery' (tmpl_ofd01)\n- 'Delivered' (tmpl_del01)\n- 'Delay Notification' (tmpl_dn01)\n- (5 more)",
        "contact_count": "120,000",
    },

    "growth_complaint_suspended": {
        "account_id": "acct_cs3r7b",
        "plan_name": "Growth",
        "plan_price": "129",
        "emails_sent": "45,000",
        "email_limit": "100,000",
        "api_calls": "350,000",
        "api_call_limit": "1,000,000",
        "team_count": "4",
        "team_limit": "10",
        "created_at": "2025-01-10",
        "domain_count": "2",
        "domain_details": (
            "- dailydeals.shop: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)\n"
            "- promo.dailydeals.shop: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)"
        ),
        "recent_events": (
            "- 45,000 sent, 41,800 delivered (92.9%), 900 bounced (2.0%), 450 complaints (1.0%)\n"
            "- Account sending SUSPENDED at 2026-02-16 03:22 UTC — complaint rate exceeded 0.3%\n"
            "- All subsequent API send calls returning 403 Forbidden"
        ),
        "open_issues": "- ⚠️ SENDING SUSPENDED — Complaint rate 1.0% (threshold: 0.3%)\n- 450 complaints from last 3 campaigns sent to unsubscribed users\n- Must contact support to appeal suspension",
        "billing_cycle_date": "Renews on the 10th of each month",
        "team_members": "- boss@dailydeals.shop (Admin, owner)\n- marketing@dailydeals.shop (Editor)\n- dev@dailydeals.shop (Editor)\n- cs@dailydeals.shop (Viewer)",
        "api_keys": "- 'Main Key' (am_live_cs3r...) — scopes: send, read — last used: 2 days ago (before suspension)",
        "webhooks_summary": "- wh_dd01: https://api.dailydeals.shop/hooks — Events: all — Status: active",
        "template_count": "5",
        "templates_summary": "- 'Flash Deal' (tmpl_fd01)\n- 'Coupon Code' (tmpl_cc01)\n- 'Clearance Alert' (tmpl_cla01)\n- (2 more)",
        "contact_count": "65,000",
    },

    "growth_travel": {
        "account_id": "acct_tv2m9k",
        "plan_name": "Growth",
        "plan_price": "129",
        "emails_sent": "55,400",
        "email_limit": "100,000",
        "api_calls": "680,000",
        "api_call_limit": "1,000,000",
        "team_count": "6",
        "team_limit": "10",
        "created_at": "2025-03-01",
        "domain_count": "3",
        "domain_details": (
            "- bookings.wanderlux.travel: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- deals.wanderlux.travel: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)\n"
            "- wanderlux.travel: Verified (SPF: pass, DKIM: pass, DMARC: reject)"
        ),
        "recent_events": "- 55,400 sent, 54,600 delivered (98.6%), 165 bounced (0.3%), 22 complaints (0.04%)",
        "open_issues": "None",
        "billing_cycle_date": "Renews on the 1st of each month",
        "team_members": "- ops@wanderlux.travel (Admin, owner)\n- marketing@wanderlux.travel (Editor)\n- (4 more)",
        "api_keys": "- 'Booking Engine' (am_live_tv2m...) — scopes: send — last used: just now\n- 'Marketing' (am_live_mk5q...) — scopes: send, campaigns — last used: 3 hours ago",
        "webhooks_summary": "- wh_wl01: https://api.wanderlux.travel/email-events — Events: all — Status: active",
        "template_count": "9",
        "templates_summary": "- 'Booking Confirmation' (tmpl_bc01)\n- 'Itinerary Update' (tmpl_iu01)\n- 'Flight Reminder' (tmpl_fr01)\n- 'Deal Alert' (tmpl_da01)\n- (5 more)",
        "contact_count": "42,000",
    },

    "growth_crypto": {
        "account_id": "acct_cr7x4n",
        "plan_name": "Growth",
        "plan_price": "129",
        "emails_sent": "71,200",
        "email_limit": "100,000",
        "api_calls": "845,000",
        "api_call_limit": "1,000,000",
        "team_count": "5",
        "team_limit": "10",
        "created_at": "2025-04-15",
        "domain_count": "3",
        "domain_details": (
            "- auth.chainvault.io: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- alerts.chainvault.io: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- chainvault.io: Verified (SPF: pass, DKIM: pass, DMARC: reject)"
        ),
        "recent_events": "- 71,200 sent, 70,500 delivered (99.0%), 142 bounced (0.2%), 7 complaints (0.01%)",
        "open_issues": "None",
        "billing_cycle_date": "Renews on the 15th of each month",
        "team_members": "- security@chainvault.io (Admin, owner)\n- devops@chainvault.io (Admin)\n- backend1@chainvault.io (Editor)\n- backend2@chainvault.io (Editor)\n- support@chainvault.io (Viewer)",
        "api_keys": "- 'Auth Service' (am_live_cr7x...) — scopes: send — last used: just now, IP-restricted to 10.0.0.0/24\n- 'Alert Service' (am_live_al3k...) — scopes: send, read — last used: 2 min ago",
        "webhooks_summary": "- wh_cv01: https://api.chainvault.io/webhooks/email — Events: delivered, bounced — Status: active",
        "template_count": "6",
        "templates_summary": "- '2FA Verification' (tmpl_2fa01)\n- 'Login Alert' (tmpl_la01)\n- 'Withdrawal Confirmation' (tmpl_wc01)\n- 'Security Alert' (tmpl_sa01)\n- 'Price Alert' (tmpl_pa01)\n- 'Monthly Statement' (tmpl_ms01)",
        "contact_count": "89,000",
    },

    # ══════════════════════════════════════════════════════════════════
    # SCALE PLAN (7 profiles)
    # ══════════════════════════════════════════════════════════════════

    "scale_deliverability": {
        "account_id": "acct_4k8r1w",
        "plan_name": "Scale",
        "plan_price": "399",
        "emails_sent": "425,000",
        "email_limit": "500,000",
        "api_calls": "3,200,000",
        "api_call_limit": "5,000,000",
        "team_count": "18",
        "team_limit": "25",
        "created_at": "2024-03-10",
        "domain_count": "8",
        "domain_details": (
            "- mail.bigretail.com: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)\n"
            "- promo.bigretail.com: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)\n"
            "- alerts.bigretail.com: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)\n"
            "- (5 more domains, all verified)"
        ),
        "recent_events": (
            "- 425,000 sent, 391,000 delivered (92.0%), 12,750 bounced (3.0%), 850 complaints (0.2%)\n"
            "- Gmail deliverability dropped from 96% to 78% over past 2 weeks\n"
            "- IP 198.51.100.12 listed on Spamhaus SBL since Feb 14"
        ),
        "open_issues": (
            "- Bounce rate 3.0% (threshold: 2%)\n"
            "- Complaint rate 0.2% (threshold: 0.1%)\n"
            "- IP 198.51.100.12 blocklisted on Spamhaus"
        ),
        "billing_cycle_date": "Renews on the 10th of each month",
        "team_members": "- ceo@bigretail.com (Admin, owner)\n- cto@bigretail.com (Admin)\n- (16 more team members: 8 Editors, 8 Viewers)",
        "api_keys": "- 'Production Sending' (am_live_4k8r...) — scopes: all — last used: 1 min ago\n- 'Analytics Read' (am_live_7m2n...) — scopes: read — last used: 10 min ago\n- 'Staging' (am_test_9p3q...) — scopes: all — last used: 2 days ago",
        "webhooks_summary": "- wh_br01: https://api.bigretail.com/webhooks/email — Events: all — Status: active\n- wh_br02: https://analytics.bigretail.com/ingest — Events: delivered, bounced, opened, clicked — Status: active",
        "template_count": "24",
        "templates_summary": "- 'Order Confirmation' (tmpl_oc01)\n- 'Shipping Notification' (tmpl_ship01)\n- 'Black Friday 2025' (tmpl_bf25)\n- 'Weekly Promo' (tmpl_wp01)\n- (20 more templates)",
        "contact_count": "189,000",
    },

    "scale_insurance": {
        "account_id": "acct_in5s2p",
        "plan_name": "Scale",
        "plan_price": "399",
        "emails_sent": "380,000",
        "email_limit": "500,000",
        "api_calls": "4,100,000",
        "api_call_limit": "5,000,000",
        "team_count": "22",
        "team_limit": "25",
        "created_at": "2024-01-15",
        "domain_count": "6",
        "domain_details": (
            "- mail.shieldinsure.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- claims.shieldinsure.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- renewals.shieldinsure.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- marketing.shieldinsure.com: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)\n"
            "- (2 more verified domains)"
        ),
        "recent_events": "- 380,000 sent, 376,200 delivered (99.0%), 760 bounced (0.2%), 38 complaints (0.01%)",
        "open_issues": "None",
        "billing_cycle_date": "Renews on the 15th of each month",
        "team_members": "- it-director@shieldinsure.com (Admin, owner)\n- sysadmin@shieldinsure.com (Admin)\n- (20 more: 12 Editors, 8 Viewers)",
        "api_keys": "- 'Claims System' (am_live_in5s...) — scopes: send, read — last used: just now\n- 'Renewals' (am_live_rn3k...) — scopes: send — last used: 5 min ago\n- 'Marketing' (am_live_mk7q...) — scopes: send, campaigns — last used: 2 hours ago\n- 'Staging' (am_test_st4p...) — scopes: all — last used: 1 day ago",
        "webhooks_summary": "- wh_si01: https://api.shieldinsure.com/email-events — Events: all — Status: active\n- wh_si02: https://compliance.shieldinsure.com/audit — Events: bounced, complained — Status: active",
        "template_count": "18",
        "templates_summary": "- 'Policy Issued' (tmpl_pi01)\n- 'Claim Filed' (tmpl_cf01)\n- 'Renewal Reminder' (tmpl_rr01)\n- (15 more)",
        "contact_count": "340,000",
    },

    "scale_sso_issue": {
        "account_id": "acct_ss7o3d",
        "plan_name": "Scale",
        "plan_price": "399",
        "emails_sent": "290,000",
        "email_limit": "500,000",
        "api_calls": "2,800,000",
        "api_call_limit": "5,000,000",
        "team_count": "20",
        "team_limit": "25",
        "created_at": "2024-05-01",
        "domain_count": "5",
        "domain_details": (
            "- mail.legalpartners.law: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- docs.legalpartners.law: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- (3 more verified domains)"
        ),
        "recent_events": "- 290,000 sent, 287,100 delivered (99.0%), 580 bounced (0.2%), 29 complaints (0.01%)",
        "open_issues": "- SAML SSO integration returning 'Invalid SAML Response' — metadata certificate expired yesterday\n- 5 team members unable to log in via SSO since this morning",
        "billing_cycle_date": "Renews on the 1st of each month",
        "team_members": "- it@legalpartners.law (Admin, owner)\n- managing-partner@legalpartners.law (Admin)\n- (18 more: 10 Editors, 8 Viewers — 5 currently locked out due to SSO issue)",
        "api_keys": "- 'Document Delivery' (am_live_ss7o...) — scopes: send, read — last used: just now\n- 'Case Updates' (am_live_cu2k...) — scopes: send — last used: 10 min ago",
        "webhooks_summary": "- wh_lp01: https://api.legalpartners.law/email — Events: delivered, bounced, opened — Status: active",
        "template_count": "8",
        "templates_summary": "- 'Document Sent' (tmpl_ds01)\n- 'Case Update' (tmpl_cu01)\n- 'Meeting Scheduled' (tmpl_ms01)\n- (5 more)",
        "contact_count": "45,000",
    },

    "scale_media": {
        "account_id": "acct_md9k5w",
        "plan_name": "Scale",
        "plan_price": "399",
        "emails_sent": "470,000",
        "email_limit": "500,000",
        "api_calls": "4,800,000",
        "api_call_limit": "5,000,000",
        "team_count": "24",
        "team_limit": "25",
        "created_at": "2024-02-01",
        "domain_count": "12",
        "domain_details": (
            "- breaking.newshub.media: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- sports.newshub.media: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- tech.newshub.media: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- (9 more verified domains, one per news vertical)"
        ),
        "recent_events": (
            "- 470,000 sent, 462,600 delivered (98.4%), 2,350 bounced (0.5%), 940 complaints (0.2%)\n"
            "- 94% email limit used, 96% API limit used — will exceed before renewal"
        ),
        "open_issues": "- Approaching email limit: 470K/500K (94%) with 8 days left\n- Approaching API limit: 4.8M/5M (96%)\n- Complaint rate 0.2% creeping up (threshold: 0.3%)",
        "billing_cycle_date": "Renews on the 1st of each month",
        "team_members": "- editor-in-chief@newshub.media (Admin, owner)\n- (23 more across 12 editorial verticals)",
        "api_keys": "- 'Breaking News' (am_live_md9k...) — scopes: send — last used: just now\n- 'Newsletter Platform' (am_live_nl5q...) — scopes: send, campaigns, templates — last used: 30 min ago\n- 'Analytics' (am_live_an8r...) — scopes: read — last used: 5 min ago",
        "webhooks_summary": "- wh_nh01: https://api.newshub.media/email — Events: all — Status: active",
        "template_count": "35",
        "templates_summary": "- 'Breaking News Alert' (tmpl_bna01)\n- 'Morning Digest' (tmpl_md01)\n- 'Sports Roundup' (tmpl_sr01)\n- (32 more)",
        "contact_count": "890,000",
    },

    "scale_healthcare": {
        "account_id": "acct_hc2m7k",
        "plan_name": "Scale",
        "plan_price": "399",
        "emails_sent": "310,000",
        "email_limit": "500,000",
        "api_calls": "2,900,000",
        "api_call_limit": "5,000,000",
        "team_count": "15",
        "team_limit": "25",
        "created_at": "2024-06-01",
        "domain_count": "4",
        "domain_details": (
            "- appointments.medconnect.health: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- results.medconnect.health: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- billing.medconnect.health: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- medconnect.health: Verified (SPF: pass, DKIM: pass, DMARC: reject)"
        ),
        "recent_events": "- 310,000 sent, 307,900 delivered (99.3%), 620 bounced (0.2%), 6 complaints (0.002%)",
        "open_issues": "- Requesting HIPAA BAA — need Enterprise plan for HIPAA compliance\n- Cannot use HIPAA features on Scale plan",
        "billing_cycle_date": "Renews on the 1st of each month",
        "team_members": "- cto@medconnect.health (Admin, owner)\n- compliance@medconnect.health (Admin)\n- (13 more)",
        "api_keys": "- 'Appointment System' (am_live_hc2m...) — scopes: send, read — last used: just now\n- 'Patient Portal' (am_live_pp4k...) — scopes: send — last used: 5 min ago",
        "webhooks_summary": "- wh_mc01: https://api.medconnect.health/email — Events: delivered, bounced — Status: active",
        "template_count": "12",
        "templates_summary": "- 'Appointment Reminder' (tmpl_ar01)\n- 'Lab Results Ready' (tmpl_lrr01)\n- 'Prescription Update' (tmpl_pu01)\n- (9 more)",
        "contact_count": "250,000",
    },

    "scale_subaccounts": {
        "account_id": "acct_sa3b9k",
        "plan_name": "Scale",
        "plan_price": "399",
        "emails_sent": "420,000",
        "email_limit": "500,000",
        "api_calls": "3,900,000",
        "api_call_limit": "5,000,000",
        "team_count": "25",
        "team_limit": "25",
        "created_at": "2024-04-15",
        "domain_count": "15",
        "domain_details": (
            "- mail.digitalforge.agency: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- Subaccount 'ClientAlpha': alpha.digitalforge.agency (Verified)\n"
            "- Subaccount 'ClientBeta': beta-corp.com (Verified)\n"
            "- Subaccount 'ClientGamma': gamma.shop (Verified), returns.gamma.shop (Verified)\n"
            "- (10 more subaccount domains)"
        ),
        "recent_events": (
            "- 420,000 sent across all subaccounts\n"
            "- Parent: 85,000 sent\n"
            "- ClientAlpha: 120,000 sent (near 150K allocation)\n"
            "- ClientBeta: 95,000 sent\n"
            "- ClientGamma: 120,000 sent"
        ),
        "open_issues": "- Subaccount 'ClientAlpha' approaching allocated quota (120K/150K = 80%)\n- Need to add a new subaccount 'ClientDelta' — current 8/10 subaccount limit",
        "billing_cycle_date": "Renews on the 15th of each month",
        "team_members": "- ceo@digitalforge.agency (Admin, owner)\n- (24 more across parent + subaccounts)",
        "api_keys": "- 'Parent Admin' (am_live_sa3b...) — scopes: all — last used: 1 hour ago\n- 'ClientAlpha API' (am_live_ca2k...) — scopes: send, read — last used: 5 min ago\n- 'ClientBeta API' (am_live_cb7m...) — scopes: send, read — last used: 10 min ago\n- (3 more subaccount keys)",
        "webhooks_summary": "- wh_df01: https://api.digitalforge.agency/master-hook — Events: all — Status: active\n- Per-subaccount webhooks configured",
        "template_count": "40",
        "templates_summary": "- Parent and subaccount templates combined\n- (40 templates across all accounts)",
        "contact_count": "450,000",
    },

    "scale_greylist": {
        "account_id": "acct_gl8k5n",
        "plan_name": "Scale",
        "plan_price": "399",
        "emails_sent": "350,000",
        "email_limit": "500,000",
        "api_calls": "3,100,000",
        "api_call_limit": "5,000,000",
        "team_count": "16",
        "team_limit": "25",
        "created_at": "2024-07-01",
        "domain_count": "5",
        "domain_details": (
            "- mail.govcontract.us: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- bids.govcontract.us: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- (3 more verified domains)"
        ),
        "recent_events": (
            "- 350,000 sent, 340,000 delivered (97.1%), 3,500 bounced (1.0%), 35 complaints (0.01%)\n"
            "- 12,000 emails in 'deferred' state — target domains (*.gov, *.mil) applying greylisting\n"
            "- Many government recipients experiencing 15-30 min delivery delays"
        ),
        "open_issues": "- 12,000 deferred emails to government domains (.gov, .mil) — greylisting delays\n- Some .gov recipients reporting non-receipt (emails in deferred queue)",
        "billing_cycle_date": "Renews on the 1st of each month",
        "team_members": "- admin@govcontract.us (Admin, owner)\n- (15 more)",
        "api_keys": "- 'Bid Notifications' (am_live_gl8k...) — scopes: send, read — last used: just now\n- 'Reports' (am_live_rp2m...) — scopes: send, read — last used: 1 hour ago",
        "webhooks_summary": "- wh_gc01: https://api.govcontract.us/email — Events: all — Status: active",
        "template_count": "8",
        "templates_summary": "- 'Bid Alert' (tmpl_ba01)\n- 'Award Notification' (tmpl_an01)\n- 'Document Submission' (tmpl_ds01)\n- (5 more)",
        "contact_count": "78,000",
    },

    # ══════════════════════════════════════════════════════════════════
    # ENTERPRISE PLAN (7 profiles)
    # ══════════════════════════════════════════════════════════════════

    "enterprise_compliance": {
        "account_id": "acct_1a3b5c",
        "plan_name": "Enterprise",
        "plan_price": "1,299",
        "emails_sent": "1,450,000",
        "email_limit": "2,000,000",
        "api_calls": "12,300,000",
        "api_call_limit": "20,000,000",
        "team_count": "45",
        "team_limit": "Unlimited",
        "created_at": "2023-09-01",
        "domain_count": "15",
        "domain_details": (
            "- mail.globalbank.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- alerts.globalbank.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- (13 more domains, all verified with DMARC reject policy)"
        ),
        "recent_events": (
            "- 1,450,000 sent, 1,435,500 delivered (99.0%), 7,250 bounced (0.5%), 145 complaints (0.01%)\n"
            "- All metrics within healthy thresholds"
        ),
        "open_issues": "None",
        "billing_cycle_date": "Renews on the 1st of each month",
        "team_members": "- ciso@globalbank.com (Admin, owner)\n- it-admin@globalbank.com (Admin)\n- (43 more team members across multiple departments)",
        "api_keys": "- 'Transactional' (am_live_1a3b...) — scopes: send, read — last used: 1 min ago\n- 'Marketing Platform' (am_live_5c7d...) — scopes: all — last used: 5 min ago\n- 'Compliance Audit' (am_live_8e9f...) — scopes: read — last used: 1 hour ago\n- 'Staging' (am_test_2g4h...) — scopes: all — last used: 3 days ago",
        "webhooks_summary": "- wh_gb01: https://integrations.globalbank.com/apexmail — Events: all — Status: active\n- wh_gb02: https://compliance.globalbank.com/audit — Events: complained, bounced, unsubscribed — Status: active",
        "template_count": "42",
        "templates_summary": "- 'Account Alert' (tmpl_aa01)\n- 'Transaction Receipt' (tmpl_tr01)\n- 'Security Notice' (tmpl_sn01)\n- (39 more templates)",
        "contact_count": "1,250,000",
    },

    "enterprise_ecommerce": {
        "account_id": "acct_ec8m3q",
        "plan_name": "Enterprise",
        "plan_price": "1,299",
        "emails_sent": "1,820,000",
        "email_limit": "2,000,000",
        "api_calls": "18,500,000",
        "api_call_limit": "20,000,000",
        "team_count": "60",
        "team_limit": "Unlimited",
        "created_at": "2023-06-15",
        "domain_count": "20",
        "domain_details": (
            "- orders.megamarket.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- shipping.megamarket.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- promo.megamarket.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- returns.megamarket.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- (16 more domains including regional subdomains)"
        ),
        "recent_events": (
            "- 1,820,000 sent, 1,801,800 delivered (99.0%), 5,460 bounced (0.3%), 364 complaints (0.02%)\n"
            "- 91% email limit used — may need overage capacity for spring sale"
        ),
        "open_issues": "- Approaching email limit: 1.82M/2M (91%) with spring sale starting in 5 days\n- Need to discuss volume increase or overage pricing",
        "billing_cycle_date": "Renews on the 15th of each month",
        "team_members": "- vp-eng@megamarket.com (Admin, owner)\n- devops@megamarket.com (Admin)\n- (58 more across engineering, marketing, CS, operations)",
        "api_keys": "- 'Order System' (am_live_ec8m...) — scopes: send — last used: just now\n- 'Marketing Platform' (am_live_mp5k...) — scopes: all — last used: 10 min ago\n- 'Analytics' (am_live_an6r...) — scopes: read — last used: 5 min ago\n- (5 more keys for different services)",
        "webhooks_summary": "- wh_mm01: https://platform.megamarket.com/email-events — Events: all — Status: active\n- wh_mm02: https://analytics.megamarket.com/ingest — Events: opened, clicked — Status: active\n- wh_mm03: https://fraud.megamarket.com/check — Events: bounced, complained — Status: active",
        "template_count": "85",
        "templates_summary": "- 'Order Confirmation' (tmpl_oc01)\n- 'Shipping Notification' (tmpl_sn01)\n- 'Delivery Confirmation' (tmpl_dc01)\n- 'Return Accepted' (tmpl_ra01)\n- (81 more including 12 regional variants)",
        "contact_count": "4,200,000",
    },

    "enterprise_fintech": {
        "account_id": "acct_ft6n2w",
        "plan_name": "Enterprise",
        "plan_price": "1,299",
        "emails_sent": "980,000",
        "email_limit": "2,000,000",
        "api_calls": "8,900,000",
        "api_call_limit": "20,000,000",
        "team_count": "35",
        "team_limit": "Unlimited",
        "created_at": "2024-01-10",
        "domain_count": "8",
        "domain_details": (
            "- noreply.paynexus.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- alerts.paynexus.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- auth.paynexus.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- compliance.paynexus.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- (4 more regional domains)"
        ),
        "recent_events": "- 980,000 sent, 975,100 delivered (99.5%), 1,960 bounced (0.2%), 10 complaints (0.001%)",
        "open_issues": "None",
        "billing_cycle_date": "Renews on the 10th of each month",
        "team_members": "- cto@paynexus.com (Admin, owner)\n- security-lead@paynexus.com (Admin)\n- (33 more across engineering, compliance, operations)",
        "api_keys": "- 'Auth Service' (am_live_ft6n...) — scopes: send — last used: just now, IP-restricted\n- 'Transaction Alerts' (am_live_ta3k...) — scopes: send — last used: just now\n- 'Compliance Reports' (am_live_cr8m...) — scopes: read — last used: 1 hour ago\n- (3 more keys)",
        "webhooks_summary": "- wh_pn01: https://api.paynexus.com/email-events — Events: all — Status: active\n- wh_pn02: https://compliance.paynexus.com/audit — Events: all — Status: active",
        "template_count": "22",
        "templates_summary": "- 'Transaction Alert' (tmpl_ta01)\n- 'Login Verification' (tmpl_lv01)\n- 'Payment Received' (tmpl_pr01)\n- (19 more)",
        "contact_count": "2,800,000",
    },

    "enterprise_government": {
        "account_id": "acct_gv4m8s",
        "plan_name": "Enterprise",
        "plan_price": "1,299",
        "emails_sent": "650,000",
        "email_limit": "2,000,000",
        "api_calls": "5,200,000",
        "api_call_limit": "20,000,000",
        "team_count": "80",
        "team_limit": "Unlimited",
        "created_at": "2023-12-01",
        "domain_count": "12",
        "domain_details": (
            "- notifications.cityportal.gov: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- permits.cityportal.gov: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- taxes.cityportal.gov: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- (9 more department domains, all verified)"
        ),
        "recent_events": "- 650,000 sent, 643,500 delivered (99.0%), 1,300 bounced (0.2%), 13 complaints (0.002%)",
        "open_issues": "- GDPR data deletion request from EU citizen — needs processing within 72 hours\n- Requesting FedRAMP compliance documentation",
        "billing_cycle_date": "Renews on the 1st of each month",
        "team_members": "- it-director@cityportal.gov (Admin, owner)\n- (79 more across 12 departments)",
        "api_keys": "- 'Main System' (am_live_gv4m...) — scopes: send, read — last used: just now\n- (5 more departmental keys)",
        "webhooks_summary": "- wh_cp01: https://api.cityportal.gov/email — Events: all — Status: active",
        "template_count": "30",
        "templates_summary": "- 'Permit Approved' (tmpl_pa01)\n- 'Tax Notice' (tmpl_tn01)\n- 'Emergency Alert' (tmpl_ea01)\n- (27 more)",
        "contact_count": "1,500,000",
    },

    "enterprise_hipaa": {
        "account_id": "acct_hp3c6t",
        "plan_name": "Enterprise",
        "plan_price": "1,299",
        "emails_sent": "420,000",
        "email_limit": "2,000,000",
        "api_calls": "3,500,000",
        "api_call_limit": "20,000,000",
        "team_count": "40",
        "team_limit": "Unlimited",
        "created_at": "2024-03-01",
        "domain_count": "6",
        "domain_details": (
            "- secure.healthnet.care: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- appointments.healthnet.care: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- labs.healthnet.care: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- (3 more verified domains)"
        ),
        "recent_events": "- 420,000 sent, 417,900 delivered (99.5%), 420 bounced (0.1%), 4 complaints (0.001%)",
        "open_issues": "None — HIPAA BAA signed, SOC 2 Type II report on file",
        "billing_cycle_date": "Renews on the 1st of each month",
        "team_members": "- ciso@healthnet.care (Admin, owner)\n- hipaa-officer@healthnet.care (Admin)\n- (38 more)",
        "api_keys": "- 'Patient Comms' (am_live_hp3c...) — scopes: send, read — last used: just now, IP-restricted\n- 'Lab Results' (am_live_lr5k...) — scopes: send — last used: 2 min ago\n- 'Audit' (am_live_au9m...) — scopes: read — last used: 1 hour ago",
        "webhooks_summary": "- wh_hn01: https://api.healthnet.care/email-events — Events: delivered, bounced — Status: active\n- wh_hn02: https://audit.healthnet.care/compliance — Events: all — Status: active",
        "template_count": "15",
        "templates_summary": "- 'Appointment Reminder' (tmpl_ar01)\n- 'Lab Results' (tmpl_lr01)\n- 'Prescription Update' (tmpl_pu01)\n- 'Bill Statement' (tmpl_bs01)\n- (11 more)",
        "contact_count": "890,000",
    },

    "enterprise_whitelabel": {
        "account_id": "acct_wl2k8p",
        "plan_name": "Enterprise",
        "plan_price": "1,299",
        "emails_sent": "1,100,000",
        "email_limit": "2,000,000",
        "api_calls": "9,500,000",
        "api_call_limit": "20,000,000",
        "team_count": "30",
        "team_limit": "Unlimited",
        "created_at": "2024-02-15",
        "domain_count": "25",
        "domain_details": (
            "- platform.emailpro.com: Verified (white-label sending domain)\n"
            "- track.emailpro.com: Verified (white-label tracking domain)\n"
            "- app.emailpro.com: Verified (white-label dashboard domain)\n"
            "- unsub.emailpro.com: Verified (white-label unsubscribe domain)\n"
            "- (21 more customer-branded white-label domains)"
        ),
        "recent_events": "- 1,100,000 sent across all white-label customers, 1,089,000 delivered (99.0%)",
        "open_issues": "- White-label customer 'QuickSend' reporting their branded unsubscribe page showing ApexMail branding\n- Need to update white-label CSS for unsub.quicksend.io",
        "billing_cycle_date": "Renews on the 15th of each month",
        "team_members": "- founder@emailpro.com (Admin, owner)\n- (29 more across platform engineering and support)",
        "api_keys": "- 'Platform Core' (am_live_wl2k...) — scopes: all — last used: just now\n- (8 more customer-facing keys)",
        "webhooks_summary": "- wh_ep01: https://api.emailpro.com/apexmail-events — Events: all — Status: active\n- (Per white-label customer webhooks)",
        "template_count": "100+",
        "templates_summary": "- White-label platform templates managed per customer",
        "contact_count": "3,500,000",
    },

    "enterprise_dunning": {
        "account_id": "acct_dn7g4m",
        "plan_name": "Enterprise",
        "plan_price": "1,299",
        "emails_sent": "890,000",
        "email_limit": "2,000,000",
        "api_calls": "7,200,000",
        "api_call_limit": "20,000,000",
        "team_count": "25",
        "team_limit": "Unlimited",
        "created_at": "2024-04-01",
        "domain_count": "10",
        "domain_details": (
            "- mail.retailchain.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- (9 more verified domains)"
        ),
        "recent_events": (
            "- 890,000 sent, 881,100 delivered (99.0%), 1,780 bounced (0.2%), 89 complaints (0.01%)\n"
            "- ⚠️ Payment failed 3 days ago — account in soft-suspended state\n"
            "- Grace period ends in 4 days — sending will be disabled"
        ),
        "open_issues": "- ⚠️ SOFT SUSPENDED — Payment failed on Feb 15 (expired credit card)\n- Grace period: 7 days (ends Feb 22)\n- Invoice #INV-2026-1847 — $1,299 past due\n- Sending still active during grace period but will stop if not resolved",
        "billing_cycle_date": "Renews on the 1st of each month",
        "team_members": "- cfo@retailchain.com (Admin, owner)\n- (24 more)",
        "api_keys": "- 'Production' (am_live_dn7g...) — scopes: all — last used: just now",
        "webhooks_summary": "- wh_rc01: https://api.retailchain.com/email — Events: all — Status: active",
        "template_count": "50",
        "templates_summary": "- (50 templates across transactional and marketing)",
        "contact_count": "2,100,000",
    },

    # ══════════════════════════════════════════════════════════════════
    # PAY-AS-YOU-GO (5 profiles)
    # ══════════════════════════════════════════════════════════════════

    "payg_active": {
        "account_id": "acct_7w3x5y",
        "plan_name": "Pay-As-You-Go",
        "plan_price": "0 base",
        "emails_sent": "74,200",
        "email_limit": "Unlimited (usage-based billing)",
        "api_calls": "52,000",
        "api_call_limit": "First 100K free, then $0.10/1,000",
        "team_count": "1",
        "team_limit": "3",
        "created_at": "2025-09-15",
        "domain_count": "2",
        "domain_details": (
            "- invoices.freelancer.dev: Verified (SPF: pass, DKIM: pass, DMARC: pass)\n"
            "- freelancer.dev: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)"
        ),
        "recent_events": (
            "- 74,200 sent, 73,100 delivered (98.5%), 410 bounced (0.6%), 12 complaints (0.02%)\n"
            "- Steady growth: 52K last month → 74K this month"
        ),
        "open_issues": "None",
        "billing_cycle_date": "Usage billed on the 1st of each month",
        "team_members": "- me@freelancer.dev (Admin, owner)",
        "api_keys": "- 'Invoicing' (am_live_7w3x...) — scopes: send — last used: 2 hours ago",
        "webhooks_summary": "- wh_fl01: https://freelancer.dev/hooks/email — Events: delivered, bounced — Status: active",
        "template_count": "2",
        "templates_summary": "- 'Invoice' (tmpl_inv01)\n- 'Payment Receipt' (tmpl_pay01)",
        "contact_count": "1,890",
    },

    "payg_low_volume": {
        "account_id": "acct_lv3r9k",
        "plan_name": "Pay-As-You-Go",
        "plan_price": "0 base",
        "emails_sent": "2,300",
        "email_limit": "Unlimited (usage-based billing)",
        "api_calls": "8,500",
        "api_call_limit": "First 100K free, then $0.10/1,000",
        "team_count": "1",
        "team_limit": "3",
        "created_at": "2025-11-20",
        "domain_count": "1",
        "domain_details": "- portfoliosite.dev: Verified (SPF: pass, DKIM: pass, DMARC: none)",
        "recent_events": "- 2,300 sent, 2,280 delivered (99.1%), 5 bounced (0.2%), 0 complaints",
        "open_issues": "None",
        "billing_cycle_date": "Usage billed on the 1st of each month",
        "team_members": "- developer@portfoliosite.dev (Admin, owner)",
        "api_keys": "- 'Contact Form' (am_live_lv3r...) — scopes: send — last used: today",
        "webhooks_summary": "- wh_ps01: https://portfoliosite.dev/api/email — Events: bounced — Status: active",
        "template_count": "1",
        "templates_summary": "- 'Contact Form Reply' (tmpl_cfr01)",
        "contact_count": "450",
    },

    "payg_high_volume": {
        "account_id": "acct_hv9q2m",
        "plan_name": "Pay-As-You-Go",
        "plan_price": "0 base",
        "emails_sent": "580,000",
        "email_limit": "Unlimited (usage-based billing)",
        "api_calls": "312,000",
        "api_call_limit": "First 100K free, then $0.10/1,000",
        "team_count": "2",
        "team_limit": "3",
        "created_at": "2025-06-01",
        "domain_count": "3",
        "domain_details": (
            "- notify.eventbrite-clone.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- tickets.eventbrite-clone.com: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- eventbrite-clone.com: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)"
        ),
        "recent_events": (
            "- 580,000 sent, 574,200 delivered (99.0%), 1,740 bounced (0.3%), 58 complaints (0.01%)\n"
            "- Estimated bill: $10 + $72 + $240 = $322 for emails + $21.20 for API"
        ),
        "open_issues": "None",
        "billing_cycle_date": "Usage billed on the 1st of each month",
        "team_members": "- cto@eventbrite-clone.com (Admin, owner)\n- dev@eventbrite-clone.com (Editor)",
        "api_keys": "- 'Event Engine' (am_live_hv9q...) — scopes: send, read — last used: just now",
        "webhooks_summary": "- wh_ec01: https://api.eventbrite-clone.com/email — Events: all — Status: active",
        "template_count": "8",
        "templates_summary": "- 'Ticket Confirmation' (tmpl_tc01)\n- 'Event Reminder' (tmpl_er01)\n- 'RSVP Confirmation' (tmpl_rc01)\n- (5 more)",
        "contact_count": "125,000",
    },

    "payg_api_401": {
        "account_id": "acct_a4e1k",
        "plan_name": "Pay-As-You-Go",
        "plan_price": "0 base",
        "emails_sent": "15,800",
        "email_limit": "Unlimited (usage-based billing)",
        "api_calls": "45,000",
        "api_call_limit": "First 100K free, then $0.10/1,000",
        "team_count": "1",
        "team_limit": "3",
        "created_at": "2025-07-10",
        "domain_count": "1",
        "domain_details": "- saaswidget.io: Verified (SPF: pass, DKIM: pass, DMARC: pass)",
        "recent_events": (
            "- 15,800 sent, 15,600 delivered (98.7%), 32 bounced (0.2%), 1 complaint (0.01%)\n"
            "- ⚠️ API key 'Production' was accidentally revoked 3 hours ago by team member\n"
            "- All API calls returning 401 Unauthorized since 1:30 PM UTC"
        ),
        "open_issues": "- API key 'Production' (am_live_a4e1...) revoked — all sends failing with 401\n- 342 queued emails stuck, not sending",
        "billing_cycle_date": "Usage billed on the 1st of each month",
        "team_members": "- founder@saaswidget.io (Admin, owner)",
        "api_keys": "- 'Production' (am_live_a4e1...) — REVOKED 3 hours ago\n- 'Staging' (am_test_b5f2...) — scopes: all — last used: yesterday",
        "webhooks_summary": "- wh_sw01: https://api.saaswidget.io/hooks — Events: delivered, bounced — Status: active",
        "template_count": "3",
        "templates_summary": "- 'Signup Welcome' (tmpl_sw01)\n- 'Password Reset' (tmpl_pr01)\n- 'Usage Report' (tmpl_ur01)",
        "contact_count": "3,200",
    },

    "payg_seasonal": {
        "account_id": "acct_sn8k4q",
        "plan_name": "Pay-As-You-Go",
        "plan_price": "0 base",
        "emails_sent": "145,000",
        "email_limit": "Unlimited (usage-based billing)",
        "api_calls": "98,000",
        "api_call_limit": "First 100K free, then $0.10/1,000",
        "team_count": "2",
        "team_limit": "3",
        "created_at": "2025-05-15",
        "domain_count": "2",
        "domain_details": (
            "- mail.taxseason.app: Verified (SPF: pass, DKIM: pass, DMARC: pass)\n"
            "- taxseason.app: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)"
        ),
        "recent_events": (
            "- 145,000 sent this month (seasonal spike — tax filing deadline approaching)\n"
            "- Last 3 months: 5K, 8K, 145K — 18x volume increase this month\n"
            "- Deliverability holding: 98.2% delivery rate, 0.4% bounce, 0.03% complaints"
        ),
        "open_issues": "- Volume spike flagged for review (145K vs normal 5-8K)\n- Approaching free API call limit (98K/100K = 98%)",
        "billing_cycle_date": "Usage billed on the 1st of each month",
        "team_members": "- founder@taxseason.app (Admin, owner)\n- dev@taxseason.app (Editor)",
        "api_keys": "- 'Main' (am_live_sn8k...) — scopes: send, read — last used: just now",
        "webhooks_summary": "- wh_ts01: https://api.taxseason.app/email — Events: delivered, bounced — Status: active",
        "template_count": "5",
        "templates_summary": "- 'Filing Confirmation' (tmpl_fc01)\n- 'Tax Reminder' (tmpl_tr01)\n- 'Document Ready' (tmpl_dr01)\n- (2 more)",
        "contact_count": "42,000",
    },

    # ══════════════════════════════════════════════════════════════════
    # SPECIAL SCENARIOS (9 profiles)
    # ══════════════════════════════════════════════════════════════════

    "no_context": {
        "account_id": "unknown",
        "plan_name": "Unknown",
        "plan_price": "unknown",
        "emails_sent": "N/A",
        "email_limit": "N/A",
        "api_calls": "N/A",
        "api_call_limit": "N/A",
        "team_count": "N/A",
        "team_limit": "N/A",
        "created_at": "N/A",
        "domain_count": "0",
        "domain_details": "- No account data available (unauthenticated or general inquiry)",
        "recent_events": "N/A",
        "open_issues": "N/A",
        "billing_cycle_date": "N/A",
        "team_members": "- N/A",
        "api_keys": "- N/A",
        "webhooks_summary": "- N/A",
        "template_count": "N/A",
        "templates_summary": "- N/A",
        "contact_count": "N/A",
    },

    "starter_dunning_soft": {
        "account_id": "acct_ds5r2m",
        "plan_name": "Starter",
        "plan_price": "29",
        "emails_sent": "14,200",
        "email_limit": "25,000",
        "api_calls": "105,000",
        "api_call_limit": "250,000",
        "team_count": "2",
        "team_limit": "3",
        "created_at": "2025-09-10",
        "domain_count": "1",
        "domain_details": "- campfire.club: Verified (SPF: pass, DKIM: pass, DMARC: pass)",
        "recent_events": "- 14,200 sent, 13,900 delivered (97.9%), 42 bounced (0.3%), 2 complaints (0.01%)",
        "open_issues": "- ⚠️ Payment failed — Invoice #INV-2026-0892 ($29) past due since Feb 10\n- Account in soft-suspended state — sending still works during 7-day grace period\n- Grace period ends Feb 17 (tomorrow)",
        "billing_cycle_date": "Renews on the 10th of each month",
        "team_members": "- owner@campfire.club (Admin, owner)\n- helper@campfire.club (Editor)",
        "api_keys": "- 'Main' (am_live_ds5r...) — scopes: send, read — last used: 1 hour ago",
        "webhooks_summary": "- wh_cc01: https://campfire.club/api/email — Events: delivered, bounced — Status: active",
        "template_count": "2",
        "templates_summary": "- 'Event Invite' (tmpl_ei01)\n- 'Membership Renewal' (tmpl_mr01)",
        "contact_count": "5,600",
    },

    "growth_rate_limited": {
        "account_id": "acct_rl4k7n",
        "plan_name": "Growth",
        "plan_price": "129",
        "emails_sent": "48,000",
        "email_limit": "100,000",
        "api_calls": "980,000",
        "api_call_limit": "1,000,000",
        "team_count": "7",
        "team_limit": "10",
        "created_at": "2025-02-20",
        "domain_count": "3",
        "domain_details": (
            "- mail.devtools.run: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- alerts.devtools.run: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- devtools.run: Verified (SPF: pass, DKIM: pass, DMARC: reject)"
        ),
        "recent_events": (
            "- 48,000 sent, 47,500 delivered (99.0%), 96 bounced (0.2%), 5 complaints (0.01%)\n"
            "- ⚠️ 429 Rate Limit errors: 342 occurrences in last 24 hours\n"
            "- Growth plan limit: 300 req/min — burst traffic during product launch exceeded this"
        ),
        "open_issues": "- 342 rate-limit (429) errors in past 24 hours — exceeding 300 req/min limit\n- API call usage: 980K/1M (98%) — will hit limit within 2 days",
        "billing_cycle_date": "Renews on the 20th of each month",
        "team_members": "- cto@devtools.run (Admin, owner)\n- (6 more)",
        "api_keys": "- 'Main Backend' (am_live_rl4k...) — scopes: all — last used: just now\n- 'Worker Service' (am_live_wk8m...) — scopes: send — last used: just now",
        "webhooks_summary": "- wh_dt01: https://api.devtools.run/email — Events: all — Status: active",
        "template_count": "10",
        "templates_summary": "- 'Build Notification' (tmpl_bn01)\n- 'Alert' (tmpl_al01)\n- (8 more)",
        "contact_count": "28,000",
    },

    "pro_outlook_rendering": {
        "account_id": "acct_or6m3w",
        "plan_name": "Pro",
        "plan_price": "59",
        "emails_sent": "22,000",
        "email_limit": "50,000",
        "api_calls": "180,000",
        "api_call_limit": "500,000",
        "team_count": "3",
        "team_limit": "5",
        "created_at": "2025-08-01",
        "domain_count": "2",
        "domain_details": (
            "- mail.modernoffice.co: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)\n"
            "- modernoffice.co: Verified (SPF: pass, DKIM: pass, DMARC: quarantine)"
        ),
        "recent_events": (
            "- 22,000 sent, 21,600 delivered (98.2%), 66 bounced (0.3%), 4 complaints (0.02%)\n"
            "- Support tickets from Outlook users: emails look broken (CSS grid not rendering)"
        ),
        "open_issues": "- Template 'Product Launch' renders incorrectly in Outlook 2019/2021 — CSS grid and flexbox not supported\n- 30% of recipients use Outlook (B2B audience)",
        "billing_cycle_date": "Renews on the 1st of each month",
        "team_members": "- design@modernoffice.co (Admin, owner)\n- dev@modernoffice.co (Editor)\n- marketing@modernoffice.co (Editor)",
        "api_keys": "- 'Backend' (am_live_or6m...) — scopes: send, templates — last used: today",
        "webhooks_summary": "- wh_mo01: https://api.modernoffice.co/hooks — Events: delivered, opened, clicked — Status: active",
        "template_count": "6",
        "templates_summary": "- 'Product Launch' (tmpl_pl01) — ⚠️ Outlook rendering issues\n- 'Monthly Newsletter' (tmpl_mn01)\n- 'Feature Update' (tmpl_fu01)\n- (3 more)",
        "contact_count": "12,000",
    },

    "growth_gmail_promo_tab": {
        "account_id": "acct_gp5t8k",
        "plan_name": "Growth",
        "plan_price": "129",
        "emails_sent": "62,000",
        "email_limit": "100,000",
        "api_calls": "540,000",
        "api_call_limit": "1,000,000",
        "team_count": "5",
        "team_limit": "10",
        "created_at": "2025-04-01",
        "domain_count": "3",
        "domain_details": (
            "- mail.fashionbrand.style: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- promos.fashionbrand.style: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- track.fashionbrand.style: Custom tracking domain — Verified (SSL active)"
        ),
        "recent_events": (
            "- 62,000 sent, 61,400 delivered (99.0%), 124 bounced (0.2%), 31 complaints (0.05%)\n"
            "- Open rate dropped from 35% to 12% over past 2 weeks\n"
            "- 85% of Gmail recipients seeing emails in Promotions tab (was Primary)"
        ),
        "open_issues": "- Gmail Promotions tab placement: open rate dropped 35% → 12%\n- Marketing campaigns being classified as promotional despite transactional content mix",
        "billing_cycle_date": "Renews on the 1st of each month",
        "team_members": "- marketing@fashionbrand.style (Admin, owner)\n- (4 more)",
        "api_keys": "- 'Platform' (am_live_gp5t...) — scopes: all — last used: 2 hours ago",
        "webhooks_summary": "- wh_fb01: https://api.fashionbrand.style/email — Events: all — Status: active",
        "template_count": "14",
        "templates_summary": "- 'New Arrivals' (tmpl_na01)\n- 'Sale Alert' (tmpl_sa01)\n- 'Lookbook' (tmpl_lb01)\n- (11 more)",
        "contact_count": "65,000",
    },

    "starter_gdpr_deletion": {
        "account_id": "acct_gd2r8m",
        "plan_name": "Starter",
        "plan_price": "29",
        "emails_sent": "9,800",
        "email_limit": "25,000",
        "api_calls": "62,000",
        "api_call_limit": "250,000",
        "team_count": "2",
        "team_limit": "3",
        "created_at": "2025-05-01",
        "domain_count": "1",
        "domain_details": "- euroservice.eu: Verified (SPF: pass, DKIM: pass, DMARC: pass)",
        "recent_events": "- 9,800 sent, 9,650 delivered (98.5%), 20 bounced (0.2%), 1 complaint (0.01%)",
        "open_issues": "- GDPR data deletion request received from subscriber jan.muller@example.de\n- Must process within 30 days (72-hour processing after confirmation)\n- Need to delete: contact record, all email events, analytics data, any templates with personal data",
        "billing_cycle_date": "Renews on the 1st of each month",
        "team_members": "- owner@euroservice.eu (Admin, owner)\n- staff@euroservice.eu (Editor)",
        "api_keys": "- 'Main' (am_live_gd2r...) — scopes: send, read, contacts — last used: today",
        "webhooks_summary": "- wh_es01: https://euroservice.eu/webhooks — Events: delivered, bounced, unsubscribed — Status: active",
        "template_count": "3",
        "templates_summary": "- 'Service Update' (tmpl_su01)\n- 'Invoice' (tmpl_inv01)\n- 'Welcome' (tmpl_wel01)",
        "contact_count": "2,800",
    },

    "scale_key_rotation": {
        "account_id": "acct_kr5n8t",
        "plan_name": "Scale",
        "plan_price": "399",
        "emails_sent": "345,000",
        "email_limit": "500,000",
        "api_calls": "3,800,000",
        "api_call_limit": "5,000,000",
        "team_count": "20",
        "team_limit": "25",
        "created_at": "2024-08-01",
        "domain_count": "7",
        "domain_details": (
            "- mail.cybershield.tech: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- alerts.cybershield.tech: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- (5 more verified domains)"
        ),
        "recent_events": "- 345,000 sent, 341,550 delivered (99.0%), 690 bounced (0.2%), 34 complaints (0.01%)",
        "open_issues": "- Security audit requires API key rotation — need to rotate all 4 production keys without downtime\n- Webhook signing secret also needs rotation as part of quarterly security review",
        "billing_cycle_date": "Renews on the 1st of each month",
        "team_members": "- ciso@cybershield.tech (Admin, owner)\n- (19 more)",
        "api_keys": "- 'Production Send' (am_live_kr5n...) — scopes: send — last used: just now, needs rotation\n- 'Production Read' (am_live_rd2k...) — scopes: read — last used: 2 min ago, needs rotation\n- 'Integration' (am_live_ig8m...) — scopes: send, read, contacts — last used: 5 min ago, needs rotation\n- 'Staging' (am_test_st4q...) — scopes: all — last used: 1 day ago",
        "webhooks_summary": "- wh_cs01: https://api.cybershield.tech/email — Events: all — Status: active — Secret needs rotation\n- wh_cs02: https://siem.cybershield.tech/ingest — Events: all — Status: active",
        "template_count": "9",
        "templates_summary": "- 'Threat Alert' (tmpl_ta01)\n- 'Incident Report' (tmpl_ir01)\n- (7 more)",
        "contact_count": "160,000",
    },

    "enterprise_mfa_lockout": {
        "account_id": "acct_ml3k7q",
        "plan_name": "Enterprise",
        "plan_price": "1,299",
        "emails_sent": "750,000",
        "email_limit": "2,000,000",
        "api_calls": "6,100,000",
        "api_call_limit": "20,000,000",
        "team_count": "50",
        "team_limit": "Unlimited",
        "created_at": "2024-05-15",
        "domain_count": "8",
        "domain_details": (
            "- mail.cloudmatrix.io: Verified (SPF: pass, DKIM: pass, DMARC: reject)\n"
            "- (7 more verified domains)"
        ),
        "recent_events": "- 750,000 sent, 742,500 delivered (99.0%), 1,500 bounced (0.2%), 75 complaints (0.01%)",
        "open_issues": "- Admin user cto@cloudmatrix.io locked out — 5 failed MFA attempts, account locked for 30 minutes\n- CTO lost MFA device (phone replaced) and cannot access backup codes\n- Need to recover admin access",
        "billing_cycle_date": "Renews on the 15th of each month",
        "team_members": "- cto@cloudmatrix.io (Admin, owner) — ⚠️ LOCKED OUT\n- devops@cloudmatrix.io (Admin)\n- (48 more)",
        "api_keys": "- 'Production' (am_live_ml3k...) — scopes: all — last used: just now\n- (5 more keys)",
        "webhooks_summary": "- wh_cm01: https://api.cloudmatrix.io/email — Events: all — Status: active",
        "template_count": "25",
        "templates_summary": "- (25 templates)",
        "contact_count": "1,800,000",
    },

    "growth_cloudflare_dkim": {
        "account_id": "acct_cf4d2m",
        "plan_name": "Growth",
        "plan_price": "129",
        "emails_sent": "38,000",
        "email_limit": "100,000",
        "api_calls": "290,000",
        "api_call_limit": "1,000,000",
        "team_count": "4",
        "team_limit": "10",
        "created_at": "2025-06-15",
        "domain_count": "2",
        "domain_details": (
            "- webbuilder.tools: Verified (SPF: pass, DKIM: fail — CNAME flattened by Cloudflare proxy, DMARC: fail)\n"
            "- app.webbuilder.tools: Verified (SPF: pass, DKIM: pass, DMARC: pass)"
        ),
        "recent_events": (
            "- 38,000 sent, 34,200 delivered (90.0%), 1,900 bounced (5.0%), 19 complaints (0.05%)\n"
            "- webbuilder.tools DKIM failing since Cloudflare proxy was enabled 5 days ago"
        ),
        "open_issues": "- DKIM failure on webbuilder.tools — Cloudflare proxy (orange cloud) is flattening the CNAME record\n- Must set DKIM CNAME to DNS-only (grey cloud) in Cloudflare",
        "billing_cycle_date": "Renews on the 15th of each month",
        "team_members": "- admin@webbuilder.tools (Admin, owner)\n- dev@webbuilder.tools (Editor)\n- designer@webbuilder.tools (Editor)\n- support@webbuilder.tools (Viewer)",
        "api_keys": "- 'Backend' (am_live_cf4d...) — scopes: send, read — last used: 10 min ago",
        "webhooks_summary": "- wh_wb01: https://api.webbuilder.tools/email — Events: all — Status: active",
        "template_count": "5",
        "templates_summary": "- 'Site Published' (tmpl_sp01)\n- 'Trial Ending' (tmpl_te01)\n- (3 more)",
        "contact_count": "15,000",
    },
}
