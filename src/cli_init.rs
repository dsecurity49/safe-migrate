use anyhow::{Context, Result, anyhow};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Generate, Key},
};
use clap::Subcommand;
use std::fs;
use std::io::{IsTerminal, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Subcommand, Debug)]
pub(crate) enum InitCommands {
    /// Generate a cryptographically random cache-encryption key
    CacheKey {
        /// Store the generated key as SAFE_MIGRATE_CACHE_KEY with GitHub CLI
        #[arg(long = "set-github-secret")]
        set_github_secret_flag: bool,
    },
    /// Create a secure GitHub Actions workflow for migration checks
    GithubActions {
        /// Migration directory checked by the generated workflow
        #[arg(long)]
        path: PathBuf,
        /// Default branch that refreshes the database baseline
        #[arg(long, default_value = "main")]
        branch: String,
        /// Workflow file to create
        #[arg(long, default_value = ".github/workflows/safe-migrate.yml")]
        output: PathBuf,
        /// Replace an existing regular workflow file
        #[arg(long)]
        force: bool,
        /// Add a trusted baseline-refresh job for database-aware analysis
        #[arg(long)]
        with_baseline: bool,
        /// Configure repository secrets with the authenticated GitHub CLI
        #[arg(long)]
        configure_secrets: bool,
    },
}

pub(crate) fn run(command: InitCommands) -> Result<()> {
    match command {
        InitCommands::CacheKey {
            set_github_secret_flag,
        } => run_cache_key(set_github_secret_flag),
        InitCommands::GithubActions {
            path,
            branch,
            output,
            force,
            with_baseline,
            configure_secrets,
        } => run_github_actions(
            &path,
            &branch,
            &output,
            force,
            with_baseline || configure_secrets,
            configure_secrets,
        ),
    }
}

fn yaml_single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn validate_single_line(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.contains(['\r', '\n', '\0']) {
        return Err(anyhow!("{name} must be a non-empty, single-line value"));
    }
    Ok(())
}

fn github_actions_workflow(migration_path: &str, branch: &str, with_baseline: bool) -> String {
    let path = yaml_single_quoted(migration_path);
    let path_filter = yaml_single_quoted(&format!("{migration_path}/**"));
    let branch = yaml_single_quoted(branch);
    let action_ref = format!("v{}", env!("CARGO_PKG_VERSION"));
    if !with_baseline {
        return format!(
            r#"name: Check database migrations

on:
  pull_request:
    paths: [{path_filter}]

permissions:
  contents: read

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: dsecurity49/safe-migrate@{action_ref}
        with:
          path: {path}
"#
        );
    }
    format!(
        r#"name: Check database migrations

on:
  pull_request:
    paths: [{path_filter}]
  push:
    branches: [{branch}]
    paths: [{path_filter}]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  lint:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: dsecurity49/safe-migrate@{action_ref}
        env:
          SAFE_MIGRATE_CACHE_KEY: ${{{{ secrets.SAFE_MIGRATE_CACHE_KEY }}}}
        with:
          path: {path}

  refresh-baseline:
    if: github.event_name != 'pull_request'
    runs-on: ubuntu-latest
    environment: safe-migrate-baseline
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: dsecurity49/safe-migrate@{action_ref}
        env:
          DATABASE_URL: ${{{{ secrets.SAFE_MIGRATE_DATABASE_URL }}}}
          SAFE_MIGRATE_CACHE_KEY: ${{{{ secrets.SAFE_MIGRATE_CACHE_KEY }}}}
        with:
          path: {path}
          sync: 'true'
"#
    )
}

fn set_github_secret(name: &str, value: Option<&str>) -> Result<()> {
    let mut command = Command::new("gh");
    command.args(["secret", "set", name]);
    command.stdin(if value.is_some() {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    let mut child = command
        .spawn()
        .with_context(|| "Could not run `gh`; install and authenticate GitHub CLI first")?;
    if let Some(value) = value {
        child
            .stdin
            .take()
            .context("Could not open GitHub CLI input")?
            .write_all(value.as_bytes())
            .context("Could not provide secret to GitHub CLI")?;
    }
    let status = child.wait().context("Could not wait for GitHub CLI")?;
    if !status.success() {
        return Err(anyhow!("GitHub CLI failed while setting {name}"));
    }
    Ok(())
}

fn generate_cache_key() -> Result<String> {
    let key = Key::<XChaCha20Poly1305>::try_generate()
        .context("Operating system could not generate a cache key")?;
    Ok(key.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn run_cache_key(store_github_secret: bool) -> Result<()> {
    let key = generate_cache_key()?;
    if store_github_secret {
        set_github_secret("SAFE_MIGRATE_CACHE_KEY", Some(&key))?;
        println!("Configured SAFE_MIGRATE_CACHE_KEY for the current GitHub repository.");
    } else {
        println!("{key}");
    }
    Ok(())
}

fn run_github_actions(
    migration_path: &Path,
    branch: &str,
    output: &Path,
    force: bool,
    with_baseline: bool,
    configure_secrets: bool,
) -> Result<()> {
    if configure_secrets && !std::io::stdin().is_terminal() {
        return Err(anyhow!(
            "--configure-secrets requires an interactive terminal; use `gh secret set` directly in automation"
        ));
    }
    if migration_path.is_absolute()
        || migration_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(anyhow!(
            "Migration path must be a relative repository path without dot or parent segments"
        ));
    }
    if !migration_path.is_dir() {
        return Err(anyhow!(
            "Migration path is not a directory: {}",
            migration_path.display()
        ));
    }
    let migration_path = migration_path
        .to_str()
        .context("Migration path must be valid UTF-8")?;
    validate_single_line("migration path", migration_path)?;
    if migration_path
        .chars()
        .any(|character| matches!(character, '\\' | '*' | '?' | '[' | ']'))
    {
        return Err(anyhow!(
            "Migration path contains characters that are ambiguous in a GitHub path filter"
        ));
    }
    validate_single_line("branch", branch)?;

    if output
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.is_symlink())
    {
        return Err(anyhow!(
            "Refusing to write through a symbolic link: {}",
            output.display()
        ));
    }
    if output.exists() && !force {
        return Err(anyhow!(
            "Workflow already exists: {} (use --force to replace it)",
            output.display()
        ));
    }
    if output.exists() && !output.is_file() {
        return Err(anyhow!(
            "Workflow output is not a regular file: {}",
            output.display()
        ));
    }
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    fs::write(
        output,
        github_actions_workflow(migration_path, branch, with_baseline),
    )
    .with_context(|| format!("Could not write {}", output.display()))?;

    println!("Created {}", output.display());
    if configure_secrets {
        println!("Enter SAFE_MIGRATE_DATABASE_URL when GitHub CLI prompts for it.");
        set_github_secret("SAFE_MIGRATE_DATABASE_URL", None)?;
        let key = generate_cache_key()?;
        set_github_secret("SAFE_MIGRATE_CACHE_KEY", Some(&key))?;
        println!("Configured the database URL and a generated cache key as repository secrets.");
    } else if with_baseline {
        println!(
            "Add SAFE_MIGRATE_DATABASE_URL and SAFE_MIGRATE_CACHE_KEY as repository secrets before merging this workflow."
        );
        println!(
            "You can configure both safely with: safe-migrate init github-actions --path {} --force --with-baseline --configure-secrets",
            migration_path
        );
        println!(
            "Before the first refresh, give its runner trusted localhost or Unix-socket access to PostgreSQL."
        );
        println!("Then start the workflow once from GitHub's Actions tab to create the baseline.");
    } else {
        println!(
            "This workflow can lint immediately without database access. Its first report will use Tainted confidence until a baseline is refreshed."
        );
        println!(
            "For database-aware results, rerun with --force --with-baseline --configure-secrets, then start the workflow once from GitHub's Actions tab."
        );
    }
    Ok(())
}
