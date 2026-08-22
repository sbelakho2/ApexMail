//! Pure Rust SSR SVG chart components.
//!
//! Each function returns an inline SVG string that can be embedded
//! directly in SSR HTML without any JavaScript dependency.

/// Truncate a chart axis label to at most `max_chars` Unicode scalar values,
/// appending an ellipsis when something was cut. Char-boundary-safe: slicing
/// `&label[..n]` on multibyte labels (Estonian, Japanese, emoji) would panic.
fn truncate_label(label: &str, max_chars: usize) -> String {
    if label.chars().count() <= max_chars {
        return label.to_string();
    }
    let truncated: String = label.chars().take(max_chars).collect();
    format!("{truncated}\u{2026}")
}

/// Renders a vertical bar chart as inline SVG.
pub fn render_bar_chart(data: &[(String, f64)], width: u32, height: u32) -> String {
    if data.is_empty() {
        return render_empty_chart(width, height, "No bar chart data");
    }

    let n = data.len();
    let max_val = data
        .iter()
        .map(|(_, v)| *v)
        .fold(0.0_f64, f64::max)
        .max(1.0);
    let padding_left = 48.0;
    let padding_top = 24.0;
    let padding_bottom = 36.0;
    let chart_w = f64::from(width) - padding_left - 16.0;
    let chart_h = f64::from(height) - padding_top - padding_bottom;
    let bar_gap = 4.0;
    let bar_w = ((chart_w - bar_gap * (n as f64 - 1.0)) / n as f64).clamp(6.0, 60.0);

    let mut svg = String::from("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"");
    svg.push_str(&width.to_string());
    svg.push_str("\" height=\"");
    svg.push_str(&height.to_string());
    svg.push_str("\" viewBox=\"0 0 ");
    svg.push_str(&width.to_string());
    svg.push(' ');
    svg.push_str(&height.to_string());
    svg.push_str(r##"" role="img" aria-label="Bar chart">"##);

    svg.push_str(&build_svg_rect(width, height));

    // Grid lines
    for i in 0..=3 {
        let y = padding_top + chart_h * (i as f64) / 3.0;
        svg.push_str(&build_svg_line_h(padding_left, padding_left + chart_w, y));
    }

    // Y-axis labels
    for i in 0..=3 {
        let value = max_val * (3.0 - i as f64) / 3.0;
        let y = padding_top + chart_h * (i as f64) / 3.0 + 4.0;
        svg.push_str(&build_svg_y_label(
            padding_left - 8.0,
            y,
            &format_y_axis(value),
        ));
    }

    // Bars
    for (i, (_label, val)) in data.iter().enumerate() {
        let bar_h = (val / max_val * chart_h).max(2.0);
        let x = padding_left + i as f64 * (bar_w + bar_gap);
        let y = padding_top + chart_h - bar_h;
        let color = bar_color(i);
        // `var()` never resolves in SVG presentation attributes — route
        // theme colors through a `style` attribute instead.
        svg.push_str(&format!(
            r##"<rect x="{x:.1}" y="{y:.1}" width="{bar_w:.1}" height="{bar_h:.1}" style="fill: {color}" rx="2" opacity="0.88"><title>{val}</title></rect>"##,
        ));

        // Value label above bar
        let vx = x + bar_w / 2.0;
        let vy = y - 6.0;
        let val_str = format_y_axis(*val);
        svg.push_str(&build_svg_text_center(
            vx,
            vy,
            10,
            &val_str,
            "rgb(var(--muted-foreground))",
            "600",
        ));
    }

    // X-axis line
    svg.push_str(&build_svg_line_h(
        padding_left,
        padding_left + chart_w,
        padding_top + chart_h,
    ));

    // X-axis labels
    for (i, (label, _)) in data.iter().enumerate() {
        let x = padding_left + i as f64 * (bar_w + bar_gap) + bar_w / 2.0;
        let display_label = truncate_label(label, 8);
        let ty = padding_top + chart_h + 18.0;
        svg.push_str(&build_svg_text_center(
            x,
            ty,
            10,
            &html_escape_svg(&display_label),
            "rgb(var(--muted-foreground))",
            "400",
        ));
    }

    svg.push_str("</svg>");
    svg
}

/// Renders a line chart as inline SVG.
pub fn render_line_chart(data: &[(String, f64)], width: u32, height: u32) -> String {
    if data.is_empty() {
        return render_empty_chart(width, height, "No line chart data");
    }

    let padding_left = 48.0;
    let padding_right = 20.0;
    let padding_top = 24.0;
    let padding_bottom = 40.0;
    let chart_w = f64::from(width) - padding_left - padding_right;
    let chart_h = f64::from(height) - padding_top - padding_bottom;

    let n = data.len();
    let max_val = data
        .iter()
        .map(|(_, v)| *v)
        .fold(0.0_f64, f64::max)
        .max(1.0);
    let min_val = data
        .iter()
        .map(|(_, v)| *v)
        .fold(f64::MAX, f64::min)
        .min(0.0);
    let range = (max_val - min_val).max(1.0);

    let mut svg = build_svg_open(width, height, "Line chart");
    svg.push_str(&build_svg_rect(width, height));

    // Grid lines
    for i in 0..=3 {
        let y = padding_top + chart_h * (i as f64) / 3.0;
        svg.push_str(&build_svg_line_h(padding_left, padding_left + chart_w, y));
    }

    // Y-axis labels
    for i in 0..=3 {
        let value = min_val + range * (3.0 - i as f64) / 3.0;
        let y = padding_top + chart_h * (i as f64) / 3.0 + 4.0;
        svg.push_str(&build_svg_y_label(
            padding_left - 8.0,
            y,
            &format_y_axis(value),
        ));
    }

    // Build path
    let mut path_coords = String::new();
    let mut points_coords = String::new();
    for (i, (_label, val)) in data.iter().enumerate() {
        let x = padding_left + chart_w * (i as f64 / (n as f64 - 1.0).max(1.0));
        let y = padding_top + chart_h * (1.0 - (val - min_val) / range);
        if i == 0 {
            path_coords.push_str(&format!("M{x:.1},{y:.1}"));
        } else {
            path_coords.push_str(&format!(" L{x:.1},{y:.1}"));
        }
        // Data point dot
        let dot_color = "rgb(var(--primary))";
        let dot_stroke = "white";
        points_coords.push_str(&format!(
            r##"<circle cx="{x:.1}" cy="{y:.1}" r="3" style="fill: {dot_color}" stroke="{dot_stroke}" stroke-width="1.5" />"##,
        ));
    }

    // Line path
    let line_color = "rgb(var(--primary))";
    svg.push_str(&format!(
        r##"<path d="{path_coords}" fill="none" style="stroke: {line_color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" />"##,
    ));

    // Area fill
    if let Some(_last_val) = data.last().map(|(_, v)| *v) {
        let y_bottom = padding_top + chart_h;
        let x_first = padding_left;
        let area_fill_color = "rgb(var(--primary))";
        svg.push_str(&format!(
            r##"<path d="{path_coords} L{x_first:.1},{y_bottom:.1} Z" style="fill: {area_fill_color}" fill-opacity="0.08" />"##,
        ));
    }

    svg.push_str(&points_coords);

    // X-axis line
    svg.push_str(&build_svg_line_h(
        padding_left,
        padding_left + chart_w,
        padding_top + chart_h,
    ));

    // X-axis labels
    let step = (n as f64 / 7.0).ceil() as usize;
    for (i, (label, _)) in data.iter().enumerate() {
        if i % step.max(1) != 0 && i != n - 1 {
            continue;
        }
        let x = padding_left + chart_w * (i as f64 / (n as f64 - 1.0).max(1.0));
        let display_label = truncate_label(label, 6);
        let ty = padding_top + chart_h + 18.0;
        svg.push_str(&build_svg_text_center(
            x,
            ty,
            10,
            &html_escape_svg(&display_label),
            "rgb(var(--muted-foreground))",
            "400",
        ));
    }

    svg.push_str("</svg>");
    svg
}

/// Renders a sparkline (compact inline trend chart) as inline SVG.
pub fn render_sparkline(values: &[f64], width: u32, height: u32, color: &str) -> String {
    if values.len() < 2 {
        let h2 = height / 2;
        let border_color = "rgb(var(--border))";
        let text_color = "rgb(var(--muted-foreground))";
        return format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-hidden="true"><line x1="0" y1="{h2}" x2="{width}" y2="{h2}" style="stroke: {border_color}" stroke-opacity="0.3" /><text x="50%" y="50%" text-anchor="middle" dominant-baseline="middle" font-size="10" style="fill: {text_color}">—</text></svg>"##,
        );
    }

    let w = f64::from(width);
    let h = f64::from(height);
    let padding = 2.0;
    let chart_w = w - padding * 2.0;
    let chart_h = h - padding * 2.0;

    let min_val = values.iter().fold(f64::MAX, |a, &b| a.min(b));
    let max_val = values.iter().fold(f64::MIN, |a, &b| a.max(b));
    let range = (max_val - min_val).max(0.01);
    let n = values.len();

    let mut path = String::new();
    for (i, &val) in values.iter().enumerate() {
        let x = padding + chart_w * (i as f64 / (n as f64 - 1.0).max(1.0));
        let y = padding + chart_h * (1.0 - (val - min_val) / range);
        if i == 0 {
            path.push_str(&format!("M{x:.1},{y:.1}"));
        } else {
            path.push_str(&format!(" L{x:.1},{y:.1}"));
        }
    }

    let bottom = h - padding;
    let last_x = padding + chart_w;

    let last = values[values.len() - 1];
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="Trend across {n} points, latest value {last:.1}"><path d="{path} L{last_x:.1},{bottom:.1} L{padding:.1},{bottom:.1} Z" style="fill: {color}" fill-opacity="0.12" /><path d="{path}" fill="none" style="stroke: {color}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" /></svg>"##,
    )
}

/// Renders a pie/donut chart as inline SVG.
pub fn render_pie_chart(data: &[(String, f64)], width: u32, height: u32) -> String {
    if data.is_empty() {
        return render_empty_chart(width, height, "No pie chart data");
    }

    let w = f64::from(width);
    let h = f64::from(height);
    let cx = w / 2.0;
    let cy = h / 2.0 + 4.0;
    let outer_r = (w.min(h) / 2.0 - 8.0).max(20.0);
    let inner_r = outer_r * 0.55;

    let total: f64 = data.iter().map(|(_, v)| *v).sum();
    if total <= 0.0 {
        return render_empty_chart(width, height, "No pie chart data");
    }

    let colors: &[&str] = &[
        "rgb(var(--primary))",
        "rgb(var(--success))",
        "rgb(var(--warning))",
        "rgb(var(--destructive))",
        "rgb(var(--info))",
        "var(--cp-violet,#8b5cf6)",
        "var(--cp-pink,#ec4899)",
        "var(--cp-teal,#14b8a6)",
    ];

    let mut svg = build_svg_open(width, height, "Pie chart");
    svg.push_str(&build_svg_rect(width, height));

    let mut angle = -90_f64.to_radians();

    for (i, (_label, val)) in data.iter().enumerate() {
        let slice_angle = (val / total) * 2.0 * std::f64::consts::PI;
        let end_angle = angle + slice_angle;

        let x1 = cx + outer_r * angle.cos();
        let y1 = cy + outer_r * angle.sin();
        let x2 = cx + outer_r * end_angle.cos();
        let y2 = cy + outer_r * end_angle.sin();

        let large_arc = if slice_angle > std::f64::consts::PI {
            1
        } else {
            0
        };
        let color = colors[i % colors.len()];
        let separator_color = "white";

        if slice_angle >= 2.0 * std::f64::consts::PI - 0.001 {
            svg.push_str(&format!(
                r##"<circle cx="{cx}" cy="{cy}" r="{outer_r}" style="fill: {color}" opacity="0.85" />"##,
            ));
            if inner_r > 0.0 {
                svg.push_str(&format!(
                    r##"<circle cx="{cx}" cy="{cy}" r="{inner_r}" style="fill: var(--card-color,white)" />"##,
                ));
            }
        } else {
            let ix1 = cx + inner_r * angle.cos();
            let iy1 = cy + inner_r * angle.sin();
            let ix2 = cx + inner_r * end_angle.cos();
            let iy2 = cy + inner_r * end_angle.sin();

            let d = format!(
                "M{x1:.2},{y1:.2} A{outer_r},{outer_r} 0 {large_arc},1 {x2:.2},{y2:.2} L{ix2:.2},{iy2:.2} A{inner_r},{inner_r} 0 {large_arc},0 {ix1:.2},{iy1:.2} Z",
            );
            svg.push_str(&format!(
                r##"<path d="{d}" style="fill: {color}" opacity="0.86" stroke="{separator_color}" stroke-width="1.5" />"##,
            ));
        }

        angle = end_angle;

        // Center percentage label
        let mid_angle = angle - slice_angle / 2.0;
        let label_r = outer_r * 0.72;
        let lx = cx + label_r * mid_angle.cos();
        let ly = cy + label_r * mid_angle.sin();
        let pct = (val / total * 100.0).round();
        if pct >= 6.0 {
            let pct_str = format!("{pct}%");
            let label_color = "white";
            svg.push_str(&format!(
                r##"<text x="{lx:.1}" y="{ly:.1}" text-anchor="middle" dominant-baseline="central" font-size="10" font-family="system-ui,sans-serif" font-weight="700" fill="{label_color}">{pct_str}</text>"##,
            ));
        }
    }

    svg.push_str("</svg>");
    svg
}

/// Renders a semi-circular gauge chart as inline SVG.
pub fn render_gauge(value: f64, max: f64, width: u32, height: u32) -> String {
    let w = f64::from(width);
    let h = f64::from(height);
    let cx = w / 2.0;
    let cy = h * 0.75;
    let outer_r = (w.min(h * 1.6) / 2.0 - 6.0).max(20.0);
    let inner_r = outer_r * 0.72;

    let pct = (value / max.max(1.0)).clamp(0.0, 1.0);
    let start_angle = -225_f64.to_radians();
    let sweep = 270_f64.to_radians();
    let end_angle = start_angle + sweep;
    let fill_angle = start_angle + sweep * pct;

    let color = if pct >= 0.95 {
        "rgb(var(--success))"
    } else if pct >= 0.85 {
        "rgb(var(--primary))"
    } else if pct >= 0.70 {
        "rgb(var(--warning))"
    } else {
        "rgb(var(--destructive))"
    };

    let bg_color = "rgb(var(--border))";
    let pct_int = (pct * 100.0).round() as u32;

    let mut svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="Gauge showing {pct_int}%">"##,
    );
    svg.push_str(&build_svg_rect(width, height));

    // Background track (simplified: just draw the outer arc thicker)
    fn arc_path(cx: f64, cy: f64, r: f64, start: f64, end: f64) -> String {
        let x1 = cx + start.cos() * r;
        let y1 = cy + start.sin() * r;
        let x2 = cx + end.cos() * r;
        let y2 = cy + end.sin() * r;
        let sweep = end - start;
        let large = if sweep.abs() > std::f64::consts::PI {
            1
        } else {
            0
        };
        format!("M{x1:.2},{y1:.2} A{r:.2},{r:.2} 0 {large},1 {x2:.2},{y2:.2}")
    }

    // Background track rendered as thick stroke
    let bg_d = arc_path(cx, cy, (outer_r + inner_r) / 2.0, start_angle, end_angle);
    let track_w = outer_r - inner_r;
    svg.push_str(&format!(
        r##"<path d="{bg_d}" fill="none" style="stroke: {bg_color}" stroke-opacity="0.25" stroke-width="{track_w:.0}" stroke-linecap="butt" />"##,
    ));

    // Filled portion
    let fill_d = arc_path(cx, cy, (outer_r + inner_r) / 2.0, start_angle, fill_angle);
    svg.push_str(&format!(
        r##"<path d="{fill_d}" fill="none" style="stroke: {color}" stroke-opacity="0.9" stroke-width="{track_w:.0}" stroke-linecap="butt" />"##,
    ));

    // Value text in center
    let pct_str = format!("{:.1}%", pct * 100.0);
    let text_color = "rgb(var(--foreground))";
    svg.push_str(&format!(
        r##"<text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="central" font-size="22" font-family="system-ui,sans-serif" font-weight="800" style="fill: {text_color}">{pct_str}</text>"##,
    ));

    // Tick marks
    let tick_outer = outer_r + 3.0;
    let tick_inner = outer_r - 4.0;
    let tick_color = "rgb(var(--muted-foreground))";
    for i in 0..=5 {
        let a = start_angle + sweep * (i as f64 / 5.0);
        let tx1 = cx + a.cos() * tick_outer;
        let ty1 = cy + a.sin() * tick_outer;
        let tx2 = cx + a.cos() * tick_inner;
        let ty2 = cy + a.sin() * tick_inner;
        svg.push_str(&format!(
            r##"<line x1="{tx1:.1}" y1="{ty1:.1}" x2="{tx2:.1}" y2="{ty2:.1}" style="stroke: {tick_color}" stroke-opacity="0.5" stroke-width="1" />"##,
        ));
    }

    svg.push_str("</svg>");
    svg
}

/// Horizontal bar chart optimized for domain lists etc.
pub fn render_horizontal_bar_chart(data: &[(String, f64)], width: u32, _height: u32) -> String {
    if data.is_empty() {
        return render_empty_chart(width, 40, "No data");
    }

    let max_val = data
        .iter()
        .map(|(_, v)| *v)
        .fold(0.0_f64, f64::max)
        .max(1.0);
    let label_w = 0.38 * f64::from(width);
    let bar_space = f64::from(width) - label_w;
    let bar_h = 22.0;
    let gap = 8.0;
    let total_h = (bar_h + gap) * data.len() as f64 + gap;

    let mut svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{total_h:.0}" viewBox="0 0 {width} {total_h:.0}" role="img" aria-label="Horizontal bar chart">"##,
    );
    svg.push_str(&build_svg_rect(width, total_h.round() as u32));

    for (i, (label, val)) in data.iter().enumerate() {
        let bar_w = (val / max_val * (bar_space - 40.0)).max(3.0);
        let y = gap + i as f64 * (bar_h + gap);
        let color = bar_color(i);

        // Label
        let display_label = truncate_label(label, 16);
        let label_y = y + bar_h * 0.6;
        let label_color = "rgb(var(--foreground))";
        svg.push_str(&format!(
            r##"<text x="8" y="{label_y:.1}" text-anchor="start" font-size="12" font-family="system-ui,sans-serif" font-weight="500" style="fill: {label_color}">{}</text>"##,
            html_escape_svg(&display_label),
        ));

        // Bar
        let lx = label_w + 4.0;
        svg.push_str(&format!(
            r##"<rect x="{lx:.1}" y="{y:.1}" width="{bar_w:.1}" height="{bar_h}" style="fill: {color}" rx="2" opacity="0.85" />"##,
        ));

        // Value label
        let vx = lx + bar_w + 8.0;
        let vy = y + bar_h * 0.6;
        let val_color = "rgb(var(--muted-foreground))";
        svg.push_str(&format!(
            r##"<text x="{vx:.1}" y="{vy:.1}" text-anchor="start" font-size="11" font-family="system-ui,sans-serif" font-weight="600" style="fill: {val_color}">{}</text>"##,
            format_y_axis(*val),
        ));
    }

    svg.push_str("</svg>");
    svg
}

// ── SVG Building Blocks ──────────────────────────────────────

fn build_svg_open(width: u32, height: u32, label: &str) -> String {
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="{label}">"##,
    )
}

fn build_svg_rect(width: u32, height: u32) -> String {
    format!(r##"<rect width="{width}" height="{height}" fill="transparent" />"##)
}

fn build_svg_line_h(x1: f64, x2: f64, y: f64) -> String {
    let border_color = "rgb(var(--border))";
    format!(
        r##"<line x1="{x1:.1}" y1="{y:.1}" x2="{x2:.1}" y2="{y:.1}" style="stroke: {border_color}" stroke-opacity="0.25" stroke-dasharray="3 3" />"##,
    )
}

fn build_svg_y_label(x: f64, y: f64, text: &str) -> String {
    let color = "rgb(var(--muted-foreground))";
    format!(
        r##"<text x="{x:.1}" y="{y:.1}" text-anchor="end" font-size="11" font-family="system-ui,sans-serif" style="fill: {color}">{text}</text>"##,
    )
}

fn build_svg_text_center(
    x: f64,
    y: f64,
    font_size: u8,
    text: &str,
    fill: &str,
    weight: &str,
) -> String {
    format!(
        r##"<text x="{x:.1}" y="{y:.1}" text-anchor="middle" font-size="{font_size}" font-family="system-ui,sans-serif" font-weight="{weight}" style="fill: {fill}">{text}</text>"##,
    )
}

// ── Helpers ──────────────────────────────────────────────────

fn bar_color(i: usize) -> &'static str {
    const COLORS: &[&str] = &[
        "rgb(var(--primary))",
        "rgb(var(--success))",
        "rgb(var(--warning))",
        "rgb(var(--info))",
        "rgb(var(--destructive))",
        "var(--cp-violet,#8b5cf6)",
        "var(--cp-pink,#ec4899)",
        "var(--cp-teal,#14b8a6)",
        "var(--cp-amber,#f59e0b)",
        "var(--cp-blue,#3b82f6)",
    ];
    COLORS[i % COLORS.len()]
}

fn format_y_axis(value: f64) -> String {
    if value >= 1_000_000.0 {
        format!("{:.1}M", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.1}K", value / 1_000.0)
    } else if value.fract() == 0.0 {
        format!("{}", value as i64)
    } else {
        format!("{:.1}", value)
    }
}

fn html_escape_svg(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

fn render_empty_chart(width: u32, height: u32, reason: &str) -> String {
    let text_color = "rgb(var(--muted-foreground))";
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="Empty chart"><rect width="100%" height="100%" fill="transparent" rx="2" /><text x="50%" y="45%" text-anchor="middle" dominant-baseline="central" font-size="13" font-family="system-ui,sans-serif" style="fill: {text_color}" opacity="0.6">{reason}</text></svg>"##,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparkline_empty() {
        let svg = render_sparkline(&[], 100, 32, "blue");
        assert!(svg.contains("<svg"));
        assert!(svg.contains("—"));
    }

    #[test]
    fn sparkline_normal() {
        let svg = render_sparkline(
            &[1.0, 2.0, 1.5, 3.0, 2.5],
            100,
            32,
            "var(--cp-blue,#3b82f6)",
        );
        assert!(svg.contains("<svg"));
        assert!(svg.contains("<path"));
    }

    #[test]
    fn bar_chart_basic() {
        let data = vec![
            ("Jan".to_string(), 10.0),
            ("Feb".to_string(), 25.0),
            ("Mar".to_string(), 15.0),
        ];
        let svg = render_bar_chart(&data, 400, 250);
        assert!(svg.contains("<svg"));
        assert!(svg.contains("rect"));
        assert!(svg.contains("Feb"));
    }

    #[test]
    fn line_chart_basic() {
        let data = vec![
            ("Mon".to_string(), 5.0),
            ("Tue".to_string(), 12.0),
            ("Wed".to_string(), 8.0),
        ];
        let svg = render_line_chart(&data, 400, 250);
        assert!(svg.contains("<svg"));
        assert!(svg.contains("<path"));
    }

    #[test]
    fn pie_chart_basic() {
        let data = vec![("SES".to_string(), 60.0), ("SMTP".to_string(), 40.0)];
        let svg = render_pie_chart(&data, 300, 300);
        assert!(svg.contains("<svg"));
        assert!(svg.contains("<path"));
    }

    #[test]
    fn gauge_basic() {
        let svg = render_gauge(75.0, 100.0, 200, 180);
        assert!(svg.contains("<svg"));
        assert!(svg.contains("75.0%"));
    }

    #[test]
    fn empty_charts_render() {
        assert!(render_bar_chart(&[], 200, 100).contains("No bar chart data"));
        assert!(render_line_chart(&[], 200, 100).contains("No line chart data"));
        assert!(render_pie_chart(&[], 200, 100).contains("No pie chart data"));
    }

    #[test]
    fn format_y_axis_outputs() {
        assert_eq!(format_y_axis(123.0), "123");
        assert_eq!(format_y_axis(1500.0), "1.5K");
        assert_eq!(format_y_axis(2_500_000.0), "2.5M");
        assert_eq!(format_y_axis(42.5), "42.5");
    }

    #[test]
    fn horizontal_bars_render() {
        let data = vec![
            ("domain.com".to_string(), 5000.0),
            ("other.io".to_string(), 3000.0),
        ];
        let svg = render_horizontal_bar_chart(&data, 400, 200);
        assert!(svg.contains("<svg"));
        assert!(svg.contains("domain.com"));
        assert!(svg.contains("5.0K"));
    }

    // ── Multibyte label truncation (char-boundary safety) ────────

    #[test]
    fn multibyte_labels_do_not_panic_and_truncate_on_char_boundaries() {
        // Each of these previously panicked on `&label[..8]` / `&label[..6]`
        // / `&label[..16]` because byte slicing landed mid-codepoint.
        let labels = [
            "Ülemiste järve kampaania",
            "日本語テスト",
            "🎉🚀 emoji campaign labels",
        ];

        for label in labels {
            let bar = render_bar_chart(&[(label.to_string(), 10.0)], 400, 250);
            assert!(
                bar.contains("<svg"),
                "bar chart panicked or empty for {label}"
            );

            let line = render_line_chart(&[(label.to_string(), 5.0)], 400, 250);
            assert!(
                line.contains("<svg"),
                "line chart panicked or empty for {label}"
            );

            let horizontal = render_horizontal_bar_chart(&[(label.to_string(), 7.0)], 400, 200);
            assert!(
                horizontal.contains("<svg"),
                "horizontal chart panicked or empty for {label}"
            );
        }
    }

    #[test]
    fn truncated_labels_end_with_unicode_ellipsis() {
        let svg = render_bar_chart(&[("Ülemiste järve kampaania".to_string(), 1.0)], 400, 250);
        assert!(
            svg.contains("Ülemiste\u{2026}"),
            "expected char-safe truncation with ellipsis, got: {svg}"
        );

        // Short labels pass through untouched.
        let svg = render_bar_chart(&[("Feb".to_string(), 1.0)], 400, 250);
        assert!(svg.contains(">Feb<"));
    }

    // ── Theme colors resolve via style attributes ────────────────

    #[test]
    fn theme_colors_use_style_attributes_not_presentation_attributes() {
        // `var()` in an SVG presentation attribute (fill="...") never
        // resolves — CSS custom properties only work in style attributes.
        let charts = [
            render_bar_chart(&[("Jan".to_string(), 1.0)], 200, 100),
            render_line_chart(&[("Jan".to_string(), 1.0)], 200, 100),
            render_pie_chart(&[("SES".to_string(), 60.0)], 200, 200),
            render_gauge(75.0, 100.0, 200, 180),
            render_horizontal_bar_chart(&[("d.io".to_string(), 3.0)], 200, 100),
            render_sparkline(&[1.0, 2.0], 100, 32, "var(--cp-blue,#3b82f6)"),
            render_empty_chart(200, 100, "No data"),
        ];
        for svg in &charts {
            assert!(
                !svg.contains("fill=\"rgb(var("),
                "fill presentation attribute carries var(): {svg}"
            );
            assert!(
                !svg.contains("stroke=\"rgb(var("),
                "stroke presentation attribute carries var(): {svg}"
            );
            assert!(
                svg.contains("style=\"fill: rgb(var(")
                    || svg.contains("style=\"stroke: rgb(var(")
                    || svg.contains("style=\"fill: var("),
                "expected a style attribute carrying the theme color: {svg}"
            );
        }
    }
}
