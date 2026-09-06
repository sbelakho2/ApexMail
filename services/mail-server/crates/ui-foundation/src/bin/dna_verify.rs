// completeness verification: rendered output of the gated pages
fn main() {
    let web_dash = ui_foundation::leptos_views::web_dashboard_page();
    let cp_dash = ui_foundation::leptos_views::control_plane_dashboard_page();
    let login = ui_foundation::leptos_views::web_login_page_with_state(None, "t");
    let signup = ui_foundation::leptos_views::web_signup_page("t");
    let mfa = ui_foundation::leptos_views::web_login_mfa_challenge_page("t", "a@b.c", "/dashboard");
    let mut pass = 0;
    let mut total = 0;
    let mut check = |name: &str, cond: bool| {
        total += 1;
        if cond {
            pass += 1;
            println!("✓ {name}");
        } else {
            println!("✗ {name}");
        }
    };

    check(
        "web dashboard · 270° dial present",
        web_dash.contains("apex-dial"),
    );
    check(
        "web dashboard · monoline chart present",
        web_dash.contains("apex-chart-monoline"),
    );
    check(
        "web dashboard · arc on Send Volume",
        web_dash.contains("apex-arc"),
    );
    check(
        "web dashboard · KPI point meters",
        web_dash.contains("apex-meter-point"),
    );
    check(
        "CP dashboard · service ribbon slots",
        cp_dash.contains("bg-success-500 text-white\">all nominal"),
    );
    check(
        "CP dashboard · winding receipt",
        cp_dash.contains("apex-receipt"),
    );
    check(
        "CP dashboard · receipt arcs rotate",
        cp_dash.contains("rotate(24"),
    );
    check(
        "CP dashboard · arc on ribbon label",
        cp_dash.contains("apex-klabel"),
    );
    check(
        "login · arc labels + arch inputs",
        login.contains("apex-klabel") && login.contains("apex-input"),
    );
    check(
        "signup · 4+ arc labels",
        signup.matches("apex-klabel").count() >= 4,
    );
    check("signup · arch inputs", signup.contains("apex-input"));
    check("MFA · arch code input", mfa.contains("apex-input"));
    check(
        "NO old-style labels anywhere (login/signup/mfa)",
        !(login.contains("text-xs font-bold text-surface-900")
            || signup.contains("text-xs font-bold text-surface-900")
            || mfa.contains("text-xs font-bold text-surface-900")),
    );
    println!("\n{pass}/{total} rendered-output checks pass");
}
