//! `dedicated-tenant`, operator CLI for the Dedicated Tenant workflow.
//!
//! Three subcommands, all thin wrappers over `enterprise::dedicated_tenant`
//! (no logic lives here):
//!
//! * `validate`, fail-closed validation of a deployment record against the
//!   plan (exit 1 on any refusal, printing the report JSON);
//! * `bundle`  , render the deterministic deployment bundle for a record
//!   (and write it with `--write`), printing the bundle sha256 + path;
//! * `review`  , generate the per-tenant monthly review packet from repo
//!   data (JSON or the compact markdown render).
//!
//! Usage:
//!   DATABASE_URL=postgres://… dedicated-tenant validate --deployment-id <uuid> --release-sha <sha>
//!   DATABASE_URL=postgres://… dedicated-tenant bundle --deployment-id <uuid> --release-sha <sha> [--write] [--output-dir DIR]
//!   DATABASE_URL=postgres://… dedicated-tenant review --tenant-id <id> [--month YYYY-MM] [--format markdown|json]
//!
//! Exit codes: 0 ok, 1 refused/error, 2 usage.

use std::process::ExitCode;

use enterprise::dedicated_tenant::{
    collect_monthly_review, plan_facts, render_bundle, validate_bundle_request, write_bundle,
    DedicatedBundleRequest, ReviewPeriod,
};
use enterprise::private_deploy::PrivateDeployService;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  \
         dedicated-tenant validate --deployment-id <uuid> --release-sha <sha> [--database-url URL]\n  \
         dedicated-tenant bundle   --deployment-id <uuid> --release-sha <sha> [--write] [--output-dir DIR] [--database-url URL]\n  \
         dedicated-tenant review   --tenant-id <id> [--month YYYY-MM] [--format markdown|json] [--database-url URL]\n\n\
         DATABASE_URL is read from the environment when --database-url is not given."
    );
    ExitCode::from(2)
}

struct Args {
    command: String,
    flags: Vec<(String, Option<String>)>,
}

fn parse_args(raw: Vec<String>) -> Result<Args, String> {
    let mut iter = raw.into_iter();
    let command = iter.next().ok_or("a subcommand is required")?;
    let mut flags = Vec::new();
    while let Some(flag) = iter.next() {
        if !flag.starts_with("--") {
            return Err(format!("unexpected argument {flag:?}"));
        }
        let next = iter.next();
        match next {
            Some(value) if !value.starts_with("--") => flags.push((flag, Some(value))),
            other => {
                if let Some(value) = other {
                    // Put a flag-looking token back by treating both as flags.
                    flags.push((flag, None));
                    flags.push((value, None));
                } else {
                    flags.push((flag, None));
                }
            }
        }
    }
    Ok(Args { command, flags })
}

impl Args {
    fn value(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .find(|(flag, _)| flag == name)
            .and_then(|(_, value)| value.as_deref())
    }

    fn present(&self, name: &str) -> bool {
        self.flags.iter().any(|(flag, _)| flag == name)
    }
}

async fn connect(database_url: &str) -> Result<sqlx::PgPool, String> {
    PgPoolOptions::new()
        .max_connections(2)
        .connect(database_url)
        .await
        .map_err(|error| format!("cannot connect to the database: {error}"))
}

fn main() -> ExitCode {
    // CLI argument parsing for an operator tool; no security decision
    // depends on argv[0].
    let raw: Vec<String> = std::env::args().skip(1).collect(); // nosemgrep: rust.lang.security.args.args
    if raw.iter().any(|arg| arg == "--help" || arg == "-h") || raw.is_empty() {
        return usage();
    }
    let args = match parse_args(raw) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("{error}");
            return usage();
        }
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cannot start the async runtime: {error}");
            return ExitCode::from(1);
        }
    };

    let database_url = args
        .value("--database-url")
        .map(str::to_string)
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .filter(|value| !value.trim().is_empty());

    match args.command.as_str() {
        "validate" | "bundle" => {
            let (Some(deployment_id), Some(release_sha)) = (
                args.value("--deployment-id").map(str::to_string),
                args.value("--release-sha").map(str::to_string),
            ) else {
                return usage();
            };
            let deployment_id = match Uuid::parse_str(&deployment_id) {
                Ok(id) => id,
                Err(_) => {
                    eprintln!("--deployment-id must be a UUID");
                    return ExitCode::from(2);
                }
            };
            let Some(database_url) = database_url else {
                eprintln!("DATABASE_URL or --database-url is required");
                return ExitCode::from(2);
            };
            runtime.block_on(run_validate_or_bundle(
                args,
                &database_url,
                deployment_id,
                &release_sha,
            ))
        }
        "review" => {
            let Some(tenant_id) = args.value("--tenant-id").map(str::to_string) else {
                return usage();
            };
            let Some(database_url) = database_url else {
                eprintln!("DATABASE_URL or --database-url is required");
                return ExitCode::from(2);
            };
            runtime.block_on(run_review(args, &database_url, &tenant_id))
        }
        other => {
            eprintln!("unknown subcommand {other:?}");
            usage()
        }
    }
}

async fn run_validate_or_bundle(
    args: Args,
    database_url: &str,
    deployment_id: Uuid,
    release_sha: &str,
) -> ExitCode {
    let service = match connect(database_url).await {
        Ok(pool) => PrivateDeployService::new(pool),
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let record = match service.get(deployment_id).await {
        Ok(result) => match result.data {
            Some(record) => record,
            None => {
                eprintln!(
                    "deployment {deployment_id} not found: {}",
                    result.error.unwrap_or_default()
                );
                return ExitCode::from(1);
            }
        },
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let request = match DedicatedBundleRequest::from_record(&record, release_sha) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("refused: {error}");
            return ExitCode::from(1);
        }
    };
    let plan = match plan_facts() {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("refused: {error}");
            return ExitCode::from(1);
        }
    };
    let report = validate_bundle_request(&request, &plan);
    let report_json = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string());
    if !report.passed {
        eprintln!(
            "validation REFUSED ({} failed check(s)):",
            report.failed_codes().len()
        );
        println!("{report_json}");
        return ExitCode::from(1);
    }

    let bundle = render_bundle(&request);
    if args.command == "validate" {
        println!("{report_json}");
        eprintln!(
            "validation passed; host group {} would render bundle {}",
            bundle.host_group, bundle.sha256
        );
        return ExitCode::SUCCESS;
    }

    // bundle
    if args.present("--write") {
        let output_dir = args
            .value("--output-dir")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("var/dedicated-tenants"));
        match write_bundle(&output_dir, &request, &bundle) {
            Ok(location) => {
                println!("{}", location.directory.display());
                eprintln!("bundle written: sha256 {}", location.sha256);
            }
            Err(error) => {
                eprintln!("refused: {error}");
                return ExitCode::from(1);
            }
        }
    } else {
        println!("{report_json}");
        eprintln!(
            "bundle rendered (not written; pass --write): host group {}, sha256 {}",
            bundle.host_group, bundle.sha256
        );
    }
    ExitCode::SUCCESS
}

async fn run_review(args: Args, database_url: &str, tenant_id: &str) -> ExitCode {
    let pool = match connect(database_url).await {
        Ok(pool) => pool,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let period = match args.value("--month") {
        Some(label) => match ReviewPeriod::parse(label) {
            Some(period) => period,
            None => {
                eprintln!("--month must be YYYY-MM (e.g. 2026-09)");
                return ExitCode::from(2);
            }
        },
        None => ReviewPeriod::current(chrono::Utc::now()),
    };
    let packet = match collect_monthly_review(&pool, tenant_id, period, chrono::Utc::now()).await {
        Ok(packet) => packet,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    match args.value("--format").unwrap_or("markdown") {
        "markdown" | "md" => print!("{}", packet.render_markdown()),
        "json" => {
            let json = serde_json::to_string_pretty(&packet).unwrap_or_else(|_| "{}".to_string());
            println!("{json}");
        }
        other => {
            eprintln!("--format must be markdown or json (got {other:?})");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}
