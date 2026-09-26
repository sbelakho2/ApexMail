//! Residual-arm tests for the tracking-service config composer: with
//! DATABASE_URL unset, `load` assembles the URL from the DB_* parts.

use tracking_service::config::load;

#[test]
fn compose_database_url_falls_back_to_db_parts() {
    if std::env::var("TRACKING_SECRET_KEY").is_err() {
        std::env::set_var("TRACKING_SECRET_KEY", "01234567890123456789012345678901");
    }
    // `load` runs dotenvy, which walks up to an ancestor `.env` that sets
    // DATABASE_URL: run from a bare temp dir so the composer fallback is
    // actually exercised.
    let cwd = std::env::current_dir().expect("cwd");
    let bare = std::env::temp_dir().join(format!("tracking_res_{}", std::process::id()));
    std::fs::create_dir_all(&bare).expect("bare dir");
    std::env::set_current_dir(&bare).expect("chdir");

    let saved = std::env::var("DATABASE_URL").ok();
    std::env::remove_var("DATABASE_URL");
    std::env::set_var("DB_HOST", "db.internal");
    std::env::set_var("DB_PORT", "5433");
    std::env::set_var("DB_NAME", "apexqa");
    std::env::set_var("DB_USER", "qa");
    std::env::set_var("DB_PASSWORD", "qa-pass");
    // JWT_PUBLIC_KEY_PEM is also required by load; the ancestor .env usually
    // supplies it — provide a minimal placeholder for the bare dir.
    let saved_pem = std::env::var("JWT_PUBLIC_KEY_PEM").ok();
    if saved_pem.is_none() {
        std::env::set_var("JWT_PUBLIC_KEY_PEM", "-----BEGIN PUBLIC KEY-----");
    }

    let config = load();

    match saved {
        Some(v) => std::env::set_var("DATABASE_URL", v),
        None => std::env::remove_var("DATABASE_URL"),
    }
    match saved_pem {
        Some(v) => std::env::set_var("JWT_PUBLIC_KEY_PEM", v),
        None => std::env::remove_var("JWT_PUBLIC_KEY_PEM"),
    }
    std::env::set_current_dir(cwd).ok();
    std::fs::remove_dir_all(&bare).ok();
    let config = config.expect("config loads with the composed URL");
    assert_eq!(
        config.database.url,
        "postgresql://qa:qa-pass@db.internal:5433/apexqa"
    );
}
