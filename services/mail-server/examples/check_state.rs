fn main() {
    let html = ui_foundation::fixture_states::render_bot_state("control-plane-alerts-rules-unavailable").unwrap();
    for needle in ["correlation", "unavailable", "Could not", "Could not be loaded", "rule list"] {
        println!("{needle:24} {}", html.contains(needle));
    }
    let i = html.find("unavailable_note").or(html.find("rule list")).unwrap_or(0);
    println!("{}", &html[i.saturating_sub(200)..(i+400).min(html.len())]);
}
