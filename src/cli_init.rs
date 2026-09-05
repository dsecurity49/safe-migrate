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

const ANALYSIS_WORKFLOW: &str = "safe-migrate.yml";
const BASELINE_WORKFLOW: &str = "safe-migrate-baseline.yml";
const BASELINE_ENVIRONMENT: &str = "safe-migrate-baseline";

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
        /// Override the default branch detected from origin/HEAD
        #[arg(long)]
        branch: Option<String>,
        /// Directory in which to create both workflow files
        #[arg(long, default_value = ".github/workflows")]
        output_dir: PathBuf,
        /// Replace existing regular workflow files
        #[arg(long)]
        force: bool,
        /// Configure the repository cache key and environment database URL with GitHub CLI
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
            output_dir,
            force,
            configure_secrets,
        } => {
            let branch = branch.unwrap_or_else(detect_default_branch);
            run_github_actions(&path, &branch, &output_dir, force, configure_secrets)
        }
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

fn detect_default_branch() -> String {
    Command::new("git")
        .args([
            "symbolic-ref",
            "--quiet",
            "--short",
            "refs/remotes/origin/HEAD",
        ])
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|reference| {
            reference
                .trim()
                .strip_prefix("origin/")
                .filter(|branch| !branch.is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "main".to_string())
}

fn github_actions_workflows(migration_path: &str, branch: &str) -> (String, String) {
    let path = yaml_single_quoted(migration_path);
    let branch_filter = yaml_single_quoted(branch);
    let branch_ref = yaml_single_quoted(&format!("refs/heads/{branch}"));
    let action_ref = format!("v{}", env!("CARGO_PKG_VERSION"));
    let analysis = format!(
        r#"name: Check database migrations

on:
  pull_request:
    branches: [{branch_filter}]
  merge_group:

permissions:
  contents: read

concurrency:
  group: safe-migrate-${{{{ github.workflow }}}}-${{{{ github.event.pull_request.number || github.ref }}}}
  cancel-in-progress: true

jobs:
  lint:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: dsecurity49/safe-migrate@{action_ref}
        env:
          SAFE_MIGRATE_CACHE_KEY: ${{{{ secrets.SAFE_MIGRATE_CACHE_KEY }}}}
        with:
          path: {path}
"#
    );
    let baseline = format!(
        r#"name: Refresh safe-migrate baseline

on:
  workflow_dispatch:
  schedule:
    - cron: '23 3 * * 1,4'

permissions: {{}}

concurrency:
  group: safe-migrate-baseline
  cancel-in-progress: false

jobs:
  refresh:
    if: github.ref == {branch_ref}
    runs-on: ubuntu-latest
    timeout-minutes: 15
    environment:
      name: {BASELINE_ENVIRONMENT}
      deployment: false
    steps:
      - uses: dsecurity49/safe-migrate@{action_ref}
        env:
          DATABASE_URL: ${{{{ secrets.SAFE_MIGRATE_DATABASE_URL }}}}
          SAFE_MIGRATE_CACHE_KEY: ${{{{ secrets.SAFE_MIGRATE_CACHE_KEY }}}}
        with:
          sync: 'true'
"#
    );
    (analysis, baseline)
}

fn github_secret_args(name: &str, environment: Option<&str>) -> Vec<String> {
    let mut args = vec!["secret".to_string(), "set".to_string(), name.to_string()];
    if let Some(environment) = environment {
        args.extend(["--env".to_string(), environment.to_string()]);
    }
    args
}

fn github_environment_api_args(environment: &str) -> Vec<String> {
    vec![
        "api".to_string(),
        format!("repos/{{owner}}/{{repo}}/environments/{environment}"),
    ]
}

fn github_environment_has_access_protection(response: &[u8]) -> Result<bool> {
    let environment: serde_json::Value =
        serde_json::from_slice(response).context("GitHub returned invalid environment metadata")?;
    let protection_rules = environment
        .get("protection_rules")
        .and_then(serde_json::Value::as_array)
        .context("GitHub environment metadata omitted protection_rules")?;
    let has_review_or_branch_rule = protection_rules.iter().any(|rule| {
        matches!(
            rule.get("type").and_then(serde_json::Value::as_str),
            Some("required_reviewers" | "branch_policy")
        )
    });
    let has_deployment_branch_policy =
        environment
            .get("deployment_branch_policy")
            .is_some_and(|policy| {
                policy
                    .get("protected_branches")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
                    || policy
                        .get("custom_branch_policies")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
            });
    Ok(has_review_or_branch_rule || has_deployment_branch_policy)
}

fn warn_if_github_environment_is_unprotected(environment: &str) {
    let output = Command::new("gh")
        .args(github_environment_api_args(environment))
        .output();
    match output {
        Ok(output) if output.status.success() => {
            match github_environment_has_access_protection(&output.stdout) {
                Ok(true) => {}
                Ok(false) => eprintln!(
                    "Warning: GitHub environment `{environment}` has no required reviewers or deployment-branch restriction. Protect it before relying on SAFE_MIGRATE_DATABASE_URL isolation."
                ),
                Err(error) => eprintln!(
                    "Warning: could not verify protection for GitHub environment `{environment}`: {error}. Verify it before relying on SAFE_MIGRATE_DATABASE_URL isolation."
                ),
            }
        }
        Ok(_) => eprintln!(
            "Warning: GitHub environment `{environment}` does not exist or could not be verified. `gh secret set --env` can create it without protection; create it and add required reviewers or a deployment-branch restriction before continuing."
        ),
        Err(error) => eprintln!(
            "Warning: could not run `gh` to verify GitHub environment `{environment}`: {error}. Verify that it exists and is protected before continuing."
        ),
    }
}

fn set_github_secret(name: &str, value: Option<&str>, environment: Option<&str>) -> Result<()> {
    let mut command = Command::new("gh");
    command.args(github_secret_args(name, environment));
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
        set_github_secret("SAFE_MIGRATE_CACHE_KEY", Some(&key), None)?;
        println!("Configured SAFE_MIGRATE_CACHE_KEY for the current GitHub repository.");
    } else {
        println!("{key}");
    }
    Ok(())
}

fn run_github_actions(
    migration_path: &Path,
    branch: &str,
    output_dir: &Path,
    force: bool,
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
    validate_single_line("branch", branch)?;

    if output_dir
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.is_symlink())
    {
        return Err(anyhow!(
            "Refusing to write workflows through a symbolic link: {}",
            output_dir.display()
        ));
    }
    if output_dir.exists() && !output_dir.is_dir() {
        return Err(anyhow!(
            "Workflow output is not a directory: {}",
            output_dir.display()
        ));
    }
    let analysis_output = output_dir.join(ANALYSIS_WORKFLOW);
    let baseline_output = output_dir.join(BASELINE_WORKFLOW);
    for output in [&analysis_output, &baseline_output] {
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
                "Workflow already exists: {} (use --force to replace both workflows)",
                output.display()
            ));
        }
        if output.exists() && !output.is_file() {
            return Err(anyhow!(
                "Workflow output is not a regular file: {}",
                output.display()
            ));
        }
    }
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Could not create {}", output_dir.display()))?;

    let (analysis_workflow, baseline_workflow) = github_actions_workflows(migration_path, branch);
    fs::write(&analysis_output, analysis_workflow)
        .with_context(|| format!("Could not write {}", analysis_output.display()))?;
    fs::write(&baseline_output, baseline_workflow)
        .with_context(|| format!("Could not write {}", baseline_output.display()))?;

    println!("Created {}", analysis_output.display());
    println!("Created {}", baseline_output.display());
    if configure_secrets {
        warn_if_github_environment_is_unprotected(BASELINE_ENVIRONMENT);
        println!(
            "Enter SAFE_MIGRATE_DATABASE_URL for the {BASELINE_ENVIRONMENT} environment when GitHub CLI prompts for it."
        );
        set_github_secret(
            "SAFE_MIGRATE_DATABASE_URL",
            None,
            Some(BASELINE_ENVIRONMENT),
        )?;
        let key = generate_cache_key()?;
        set_github_secret("SAFE_MIGRATE_CACHE_KEY", Some(&key), None)?;
        println!(
            "Configured the database URL as an environment secret and the generated cache key as a repository secret."
        );
    } else {
        println!(
            "Create the {BASELINE_ENVIRONMENT} environment, store SAFE_MIGRATE_DATABASE_URL in it, and store SAFE_MIGRATE_CACHE_KEY as a repository secret."
        );
        println!("Or rerun with --force --configure-secrets after creating the environment.");
    }
    println!(
        "Give the baseline runner trusted localhost or Unix-socket access to PostgreSQL, then run Refresh safe-migrate baseline once before enabling the PR check."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_secret_is_scoped_to_the_baseline_environment() {
        assert_eq!(
            github_secret_args("SAFE_MIGRATE_DATABASE_URL", Some(BASELINE_ENVIRONMENT)),
            [
                "secret",
                "set",
                "SAFE_MIGRATE_DATABASE_URL",
                "--env",
                "safe-migrate-baseline",
            ]
        );
        assert_eq!(
            github_secret_args("SAFE_MIGRATE_CACHE_KEY", None),
            ["secret", "set", "SAFE_MIGRATE_CACHE_KEY"]
        );
    }
    #[test]
    fn environment_protection_requires_an_access_gate() {
        assert_eq!(
            github_environment_api_args(BASELINE_ENVIRONMENT),
            [
                "api",
                "repos/{owner}/{repo}/environments/safe-migrate-baseline"
            ]
        );

        for protected in [
            br#"{"protection_rules":[{"type":"required_reviewers"}],"deployment_branch_policy":null}"#.as_slice(),
            br#"{"protection_rules":[],"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":false}}"#.as_slice(),
            br#"{"protection_rules":[],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}"#.as_slice(),
        ] {
            assert!(github_environment_has_access_protection(protected).unwrap());
        }

        assert!(
            !github_environment_has_access_protection(
                br#"{"protection_rules":[],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":false}}"#
            )
            .unwrap()
        );
        assert!(
            !github_environment_has_access_protection(
                br#"{"protection_rules":[{"type":"wait_timer"}],"deployment_branch_policy":null}"#
            )
            .unwrap()
        );
    }
}
