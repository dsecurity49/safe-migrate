use super::display_path;
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
use zeroize::Zeroizing;

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
            if configure_secrets && !std::io::stdin().is_terminal() {
                return Err(anyhow!(
                    "--configure-secrets requires an interactive terminal; use `gh secret set` directly in automation"
                ));
            }
            let branch = match branch {
                Some(branch) => branch,
                None => detect_default_branch()?,
            };
            run_github_actions(&path, &branch, &output_dir, force, configure_secrets)
        }
    }
}

fn yaml_single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn validate_single_line(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(anyhow!(
            "{name} must be a non-empty, single-line value without control characters"
        ));
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    for component_path in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        if component_path.as_os_str().is_empty() {
            continue;
        }
        match component_path.symlink_metadata() {
            Ok(metadata) if metadata.is_symlink() => {
                return Err(anyhow!(
                    "Refusing to write workflows through a symbolic link: {}",
                    component_path.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "Could not inspect workflow path {}",
                        component_path.display()
                    )
                });
            }
        }
    }
    Ok(())
}

fn detect_default_branch() -> Result<String> {
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
        .ok_or_else(|| {
            anyhow!(
                "Could not detect the default branch from origin/HEAD. Run `git remote set-head origin --auto` or pass --branch explicitly."
            )
        })
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
        id: safe-migrate
        env:
          SAFE_MIGRATE_CACHE_KEY: ${{{{ secrets.SAFE_MIGRATE_CACHE_KEY }}}}
        with:
          path: {path}
      - name: Upload analysis reports
        if: ${{{{ always() }}}}
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: safe-migrate-reports
          path: |
            ${{{{ steps.safe-migrate.outputs.json-report }}}}
            ${{{{ steps.safe-migrate.outputs.markdown-report }}}}
            ${{{{ steps.safe-migrate.outputs.diagnostic-log }}}}
          if-no-files-found: warn
          retention-days: 14
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

fn ensure_github_cli_ready() -> Result<()> {
    let status = Command::new("gh")
        .args(["auth", "status"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Could not run `gh`; install GitHub CLI first")?;
    if !status.success() {
        return Err(anyhow!(
            "GitHub CLI is not authenticated; run `gh auth login` before using --configure-secrets"
        ));
    }
    Ok(())
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

fn generate_cache_key() -> Result<Zeroizing<String>> {
    let key = Key::<XChaCha20Poly1305>::try_generate()
        .context("Operating system could not generate a cache key")?;
    let mut encoded = String::with_capacity(key.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in key.iter() {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(Zeroizing::new(encoded))
}

fn run_cache_key(store_github_secret: bool) -> Result<()> {
    let key = generate_cache_key()?;
    if store_github_secret {
        set_github_secret("SAFE_MIGRATE_CACHE_KEY", Some(key.as_str()), None)?;
        println!("Configured SAFE_MIGRATE_CACHE_KEY for the current GitHub repository.");
    } else {
        println!("{}", key.as_str());
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

    install_github_actions(migration_path, branch, output_dir, force, configure_secrets)
}

fn install_github_actions(
    migration_path: &str,
    branch: &str,
    output_dir: &Path,
    force: bool,
    configure_secrets: bool,
) -> Result<()> {
    reject_symlink_components(output_dir)?;
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
    if configure_secrets {
        ensure_github_cli_ready()?;
    }
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Could not create {}", output_dir.display()))?;

    let (analysis_workflow, baseline_workflow) = github_actions_workflows(migration_path, branch);
    let analysis_temp = prepare_workflow_file(&analysis_output, &analysis_workflow)?;
    let baseline_temp = prepare_workflow_file(&baseline_output, &baseline_workflow)?;
    persist_workflow(analysis_temp, &analysis_output)?;
    persist_workflow(baseline_temp, &baseline_output).with_context(|| {
        format!(
            "Replaced {} but could not replace {}; inspect both files before retrying",
            display_path(&analysis_output),
            display_path(&baseline_output)
        )
    })?;

    println!("Created {}", display_path(&analysis_output));
    println!("Created {}", display_path(&baseline_output));
    if configure_secrets {
        configure_github_secrets()
            .context("Workflow files were created, but secret configuration is incomplete")?;
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

fn prepare_workflow_file(destination: &Path, contents: &str) -> Result<tempfile::NamedTempFile> {
    let output_dir = destination
        .parent()
        .context("Workflow output has no parent directory")?;
    let mut file = tempfile::Builder::new()
        .prefix(".safe-migrate-workflow-")
        .suffix(".tmp")
        .tempfile_in(output_dir)
        .with_context(|| {
            format!(
                "Could not create a temporary workflow file in {}",
                output_dir.display()
            )
        })?;
    file.write_all(contents.as_bytes()).with_context(|| {
        format!(
            "Could not write temporary workflow for {}",
            destination.display()
        )
    })?;
    file.as_file().sync_all().with_context(|| {
        format!(
            "Could not flush temporary workflow for {}",
            destination.display()
        )
    })?;
    Ok(file)
}

fn persist_workflow(temporary: tempfile::NamedTempFile, destination: &Path) -> Result<()> {
    temporary
        .persist(destination)
        .map(|_| ())
        .map_err(|error| error.error)
        .with_context(|| format!("Could not replace {}", destination.display()))
}

fn configure_github_secrets() -> Result<()> {
    warn_if_github_environment_is_unprotected(BASELINE_ENVIRONMENT);
    println!(
        "Enter SAFE_MIGRATE_DATABASE_URL for the {BASELINE_ENVIRONMENT} environment when GitHub CLI prompts for it."
    );
    set_github_secret(
        "SAFE_MIGRATE_DATABASE_URL",
        None,
        Some(BASELINE_ENVIRONMENT),
    )
    .context("No secrets were configured: GitHub CLI could not set SAFE_MIGRATE_DATABASE_URL")?;
    let key = generate_cache_key().context(
        "SAFE_MIGRATE_DATABASE_URL was configured, but the cache key could not be generated; run `safe-migrate init cache-key --set-github-secret`",
    )?;
    set_github_secret("SAFE_MIGRATE_CACHE_KEY", Some(key.as_str()), None).context(
        "SAFE_MIGRATE_DATABASE_URL was configured, but SAFE_MIGRATE_CACHE_KEY was not; run `safe-migrate init cache-key --set-github-secret`",
    )?;
    println!(
        "Configured the database URL as an environment secret and the generated cache key as a repository secret."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_analysis_workflow_uploads_reports_from_one_action_run() {
        let (analysis, _) = github_actions_workflows("migrations", "main");
        assert_eq!(analysis.matches("dsecurity49/safe-migrate@").count(), 1);
        assert!(analysis.contains("id: safe-migrate"));
        assert!(
            analysis.contains("actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9")
        );
        assert!(analysis.contains("if: ${{ always() }}"));
        assert!(analysis.contains("steps.safe-migrate.outputs.json-report"));
        assert!(analysis.contains("steps.safe-migrate.outputs.markdown-report"));
        assert!(analysis.contains("steps.safe-migrate.outputs.diagnostic-log"));
    }

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

    #[cfg(unix)]
    #[test]
    fn github_actions_rejects_a_symlinked_output_ancestor() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let workflow_target = workspace.path().join("workflow-target");
        let workflow_link = workspace.path().join("workflow-link");
        fs::create_dir_all(&workflow_target).unwrap();
        symlink(&workflow_target, &workflow_link).unwrap();

        let error = reject_symlink_components(&workflow_link.join("nested")).unwrap_err();

        assert!(
            error.to_string().contains("symbolic link"),
            "unexpected error: {error:#}"
        );
        assert!(!workflow_target.join("nested").exists());
    }

    #[cfg(unix)]
    struct PathGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        previous: Option<std::ffi::OsString>,
    }

    #[cfg(unix)]
    impl PathGuard {
        fn prepend(directory: &Path) -> Self {
            static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
            let lock = LOCK
                .get_or_init(|| std::sync::Mutex::new(()))
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = std::env::var_os("PATH");
            let mut paths = vec![directory.to_path_buf()];
            if let Some(previous) = &previous {
                paths.extend(std::env::split_paths(previous));
            }
            let path = std::env::join_paths(paths).expect("the test PATH is valid");
            unsafe {
                std::env::set_var("PATH", path);
            }
            Self {
                _lock: lock,
                previous,
            }
        }
    }

    #[cfg(unix)]
    impl Drop for PathGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.previous {
                    Some(value) => std::env::set_var("PATH", value),
                    None => std::env::remove_var("PATH"),
                }
            }
        }
    }

    #[cfg(unix)]
    fn fake_github_cli(directory: &Path, script: &str) -> PathGuard {
        use std::os::unix::fs::PermissionsExt;

        let gh = directory.join("gh");
        fs::write(&gh, script).unwrap();
        let mut permissions = fs::metadata(&gh).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&gh, permissions).unwrap();
        PathGuard::prepend(directory)
    }

    #[cfg(unix)]
    #[test]
    fn github_actions_preflights_github_authentication_before_writing_workflows() {
        let workspace = tempfile::tempdir().unwrap();
        let output_dir = workspace.path().join("workflows");
        let _gh = fake_github_cli(
            workspace.path(),
            "#!/bin/sh\nif [ \"$1\" = auth ]; then exit 1; fi\nexit 1\n",
        );

        let error = install_github_actions("migrations", "main", &output_dir, false, true)
            .expect_err("unauthenticated GitHub CLI must fail setup");
        assert!(
            format!("{error:#}").contains("not authenticated"),
            "unexpected error: {error:#}"
        );
        assert!(!output_dir.join(ANALYSIS_WORKFLOW).exists());
        assert!(!output_dir.join(BASELINE_WORKFLOW).exists());
    }

    #[cfg(unix)]
    #[test]
    fn github_actions_reports_completed_secret_when_cache_key_fails() {
        let workspace = tempfile::tempdir().unwrap();
        let output_dir = workspace.path().join("workflows");
        let _gh = fake_github_cli(
            workspace.path(),
            r#"#!/bin/sh
set -eu
case "$1" in
  auth) exit 0 ;;
  api) printf '%s\n' '{"protection_rules":[{"type":"required_reviewers"}]}'; exit 0 ;;
  secret)
    case "$2" in
      set)
        case "$3" in
          SAFE_MIGRATE_DATABASE_URL) exit 0 ;;
          SAFE_MIGRATE_CACHE_KEY) exit 1 ;;
        esac
        ;;
    esac
    ;;
esac
exit 1
"#,
        );

        let error = install_github_actions("migrations", "main", &output_dir, false, true)
            .expect_err("failed cache-key configuration must fail setup");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("SAFE_MIGRATE_DATABASE_URL was configured"),
            "unexpected error: {rendered}"
        );
        assert!(
            rendered.contains("SAFE_MIGRATE_CACHE_KEY"),
            "unexpected error: {rendered}"
        );
        assert!(output_dir.join(ANALYSIS_WORKFLOW).exists());
        assert!(output_dir.join(BASELINE_WORKFLOW).exists());
    }

    #[cfg(unix)]
    #[test]
    fn workflow_write_failure_leaves_existing_files_untouched() {
        use std::os::unix::fs::PermissionsExt;

        let workspace = tempfile::tempdir().unwrap();
        let output_dir = workspace.path().join("workflows");
        fs::create_dir(&output_dir).unwrap();
        let analysis_output = output_dir.join(ANALYSIS_WORKFLOW);
        let baseline_output = output_dir.join(BASELINE_WORKFLOW);
        fs::write(&analysis_output, "old analysis").unwrap();
        fs::write(&baseline_output, "old baseline").unwrap();

        let mut permissions = fs::metadata(&output_dir).unwrap().permissions();
        permissions.set_mode(0o555);
        fs::set_permissions(&output_dir, permissions).unwrap();

        let probe = output_dir.join("probe");
        if fs::write(&probe, b"x").is_ok() {
            let _ = fs::remove_file(&probe);
            permissions = fs::metadata(&output_dir).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&output_dir, permissions).unwrap();
            return;
        }

        let error = install_github_actions("migrations", "main", &output_dir, true, false)
            .expect_err("an unwritable output directory must fail the write");
        permissions = fs::metadata(&output_dir).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&output_dir, permissions).unwrap();

        assert!(
            format!("{error:#}").contains("temporary"),
            "unexpected error: {error:#}"
        );
        assert_eq!(
            fs::read_to_string(&analysis_output).unwrap(),
            "old analysis"
        );
        assert_eq!(
            fs::read_to_string(&baseline_output).unwrap(),
            "old baseline"
        );
        let leftovers = fs::read_dir(&output_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".safe-migrate-")
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn github_actions_input_values_reject_terminal_controls() {
        for value in ["branch\u{1b}[2J", "path\u{7f}", "line\nnext"] {
            assert!(validate_single_line("input", value).is_err());
        }
        assert_eq!(
            display_path(Path::new("workflow\u{1b}[2J_日本")),
            "workflow\\u{1b}[2J_日本"
        );
    }
}
