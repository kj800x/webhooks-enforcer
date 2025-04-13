use clap::{Parser, Subcommand};
use dotenv::dotenv;
use log::{debug, error, info, warn};
use reqwest::{
    blocking::{Client, Response},
    header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, LINK, USER_AGENT},
};
use serde::{Deserialize, Serialize};
use std::env;
use std::process;
use thiserror::Error;

#[derive(Parser)]
#[command(name = "webhooks-enforcer")]
#[command(author = "GitHub Webhook Manager")]
#[command(version = "0.1.0")]
#[command(about = "Manages GitHub webhook configurations across repositories", long_about = None)]
struct Cli {
    /// Perform a dry run without making changes
    #[arg(short, long)]
    dry_run: bool,

    /// Force update of webhook secrets (ignores masked secrets)
    #[arg(short = 'f', long)]
    force_secret: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// List all repositories for a given owner
    List {
        /// Only show repositories with mismatched webhook configs
        #[arg(short, long)]
        mismatched: bool,
    },

    /// Enforce webhook configuration across repositories (default action)
    Enforce,

    /// Remove webhooks with the specified URL from all repositories
    Remove {
        /// Remove all webhooks (not just the one matching WEBHOOK_URL)
        #[arg(short, long)]
        all: bool,
    },
}

#[derive(Error, Debug)]
enum AppError {
    #[error("Environment variable '{0}' not found")]
    MissingEnvVar(String),

    #[error("Environment variable error: {0}")]
    EnvVarError(#[from] env::VarError),

    #[error("HTTP client error: {0}")]
    ReqwestError(#[from] reqwest::Error),

    #[error("JSON serialization/deserialization error: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("URL parsing error: {0}")]
    UrlParsingError(#[from] url::ParseError),

    #[error("API error: {status} - {message}")]
    ApiError { status: u16, message: String },
}

#[derive(Debug, Deserialize)]
struct Repository {
    name: String,
    full_name: String,
    owner: Owner,
    archived: bool,
    private: bool,
}

#[derive(Debug, Deserialize)]
struct Owner {
    login: String,
}

#[derive(Debug, Deserialize)]
struct Webhook {
    id: u64,
    config: WebhookConfig,
    events: Vec<String>,
    active: bool,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
struct WebhookConfig {
    url: String,
    content_type: String,
    secret: Option<String>,
    insecure_ssl: String,
}

#[derive(Debug, Serialize)]
struct WebhookCreate {
    config: WebhookConfig,
    events: Vec<String>,
    active: bool,
}

struct AppConfig {
    github_pat: String,
    webhook_url: String,
    webhook_secret: String,
    repo_owner: String,
    dry_run: bool,
    force_secret: bool,
}

// Add RateLimit struct to track GitHub API rate limits
#[derive(Debug)]
struct RateLimit {
    limit: u32,
    remaining: u32,
    reset: u64,
}

fn main() {
    // Initialize environment
    dotenv().ok();
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Parse command line arguments
    let cli = Cli::parse();

    // Load configuration from environment variables, with CLI overrides
    match load_config_with_cli(&cli) {
        Ok(config) => {
            match &cli.command {
                Some(Commands::List { mismatched }) => {
                    if let Err(err) = list_repositories(&config, *mismatched) {
                        error!("Failed to list repositories: {}", err);
                        process::exit(1);
                    }
                }
                Some(Commands::Enforce) => {
                    // Enforce webhooks
                    if let Err(err) = run(config) {
                        error!("Application error: {}", err);
                        process::exit(1);
                    }
                }
                Some(Commands::Remove { all }) => {
                    // Remove webhooks
                    if let Err(err) = remove_webhooks(&config, *all) {
                        error!("Failed to remove webhooks: {}", err);
                        process::exit(1);
                    }
                }
                None => {
                    // Default action: enforce webhooks (same as Enforce command)
                    if let Err(err) = run(config) {
                        error!("Application error: {}", err);
                        process::exit(1);
                    }
                }
            }
        }
        Err(err) => {
            error!("Failed to load configuration: {}", err);

            // Provide helpful setup information if it's a missing environment variable
            if let AppError::MissingEnvVar(var_name) = &err {
                eprintln!("\nMissing required environment variable: {}", var_name);
                eprintln!("\nPlease set up your environment variables by either:");
                eprintln!("1. Creating a .env file (using .env.example as a template)");
                eprintln!("2. Setting environment variables directly in your shell\n");

                eprintln!("Required environment variables:");
                eprintln!("GITHUB_PAT=your_github_personal_access_token");
                eprintln!("WEBHOOK_URL=https://your-webhook-endpoint.example.com/webhook");
                eprintln!("WEBHOOK_SECRET=your_webhook_secret_key");
                eprintln!("REPO_OWNER=your_github_username_or_organization");
                eprintln!("\nOptional environment variables:");
                eprintln!("DRY_RUN=true|false (default: false)");

                eprintln!("\nCommand line flags:");
                eprintln!("--dry-run (-d): Perform a dry run without making changes");
                eprintln!(
                    "--force-secret (-f): Force update of webhook secrets (ignores masked secrets)"
                );
                eprintln!("\nExample usage:");
                eprintln!("cargo run -- --dry-run");
                eprintln!("cargo run -- --force-secret");
                eprintln!("cargo run -- list --mismatched");
            }

            process::exit(1);
        }
    }
}

fn load_config_with_cli(cli: &Cli) -> Result<AppConfig, AppError> {
    // Read all configuration from environment variables
    let github_pat =
        env::var("GITHUB_PAT").map_err(|_| AppError::MissingEnvVar("GITHUB_PAT".to_string()))?;

    let repo_owner =
        env::var("REPO_OWNER").map_err(|_| AppError::MissingEnvVar("REPO_OWNER".to_string()))?;

    let webhook_url =
        env::var("WEBHOOK_URL").map_err(|_| AppError::MissingEnvVar("WEBHOOK_URL".to_string()))?;

    let webhook_secret = env::var("WEBHOOK_SECRET")
        .map_err(|_| AppError::MissingEnvVar("WEBHOOK_SECRET".to_string()))?;

    // CLI flag takes precedence, then env var
    let dry_run =
        cli.dry_run || env::var("DRY_RUN").unwrap_or_else(|_| "false".to_string()) == "true";

    Ok(AppConfig {
        github_pat,
        webhook_url,
        webhook_secret,
        repo_owner,
        dry_run,
        force_secret: cli.force_secret,
    })
}

fn list_repositories(config: &AppConfig, only_mismatched: bool) -> Result<(), AppError> {
    info!("Listing repositories for owner: {}", config.repo_owner);

    let client = create_github_client(&config.github_pat)?;
    let repositories = get_repositories(&client, &config.repo_owner)?;

    info!("Found {} repositories", repositories.len());

    for repo in repositories {
        // Check if repository is archived
        if repo.archived {
            // For listing, we'll show archived repositories but mark them as such
            println!(
                "{}: {} (archived: true, webhook: not applicable)",
                repo.full_name, repo.name
            );
            continue; // Skip to the next repository
        }

        let hooks = match get_webhooks(&client, &repo.owner.login, &repo.name) {
            Ok(hooks) => hooks,
            Err(err) => {
                // Check if this is a 403 error, which might indicate another issue
                if let AppError::ApiError { status, message } = &err {
                    if *status == 403 {
                        // Print information about permission issues
                        println!(
                            "{}: {} (webhook: {}, error: {})",
                            repo.full_name, repo.name, "unknown", message
                        );
                        continue; // Skip to the next repository
                    }
                }
                return Err(err);
            }
        };

        let matching_hook = hooks.iter().find(|h| h.config.url == config.webhook_url);

        let desired_config = WebhookConfig {
            url: config.webhook_url.clone(),
            content_type: "json".to_string(),
            secret: Some(config.webhook_secret.clone()),
            insecure_ssl: "1".to_string(),
        };

        match matching_hook {
            Some(hook) => {
                // Check if secret is masked (GitHub returns asterisks for security)
                let is_secret_masked = hook
                    .config
                    .secret
                    .as_ref()
                    .map_or(false, |s| s.chars().all(|c| c == '*'));

                // Only count secret as needing update if it's not masked or we're forcing secret updates
                let needs_secret_update = if is_secret_masked && !config.force_secret {
                    debug!(
                        "Webhook for {} has a masked secret ('********'). Assuming it's correct. Use --force-secret to override.",
                        repo.full_name
                    );
                    false // Assume masked secret is correct unless force_secret is true
                } else if is_secret_masked && config.force_secret {
                    info!(
                        "Webhook for {} has a masked secret but --force-secret is enabled. Will update secret.",
                        repo.full_name
                    );
                    true
                } else {
                    hook.config.secret != desired_config.secret
                };

                let needs_update = hook.config.content_type != desired_config.content_type
                    || needs_secret_update
                    || hook.config.insecure_ssl != desired_config.insecure_ssl
                    || hook.events != vec!["*".to_string()]
                    || !hook.active;

                if !only_mismatched || needs_update {
                    println!(
                        "{}: {} (webhook: {}, needs update: {})",
                        repo.full_name, repo.name, "configured", needs_update
                    );
                }
            }
            None => {
                if !only_mismatched || true {
                    // Always show missing webhooks
                    println!("{}: {} (webhook: {})", repo.full_name, repo.name, "missing");
                }
            }
        }
    }

    Ok(())
}

fn run(config: AppConfig) -> Result<(), AppError> {
    info!("Starting GitHub webhook enforcer");
    if config.dry_run {
        info!("DRY RUN MODE: No changes will be made");
    }

    let client = create_github_client(&config.github_pat)?;

    // Get repositories
    info!("Fetching repositories for owner: {}", config.repo_owner);
    let repositories = get_repositories(&client, &config.repo_owner)?;

    // Count non-archived repositories
    let active_repos = repositories.iter().filter(|r| !r.archived).count();
    info!(
        "Found {} repositories ({} active, {} archived)",
        repositories.len(),
        active_repos,
        repositories.len() - active_repos
    );

    // Process each repository
    for repo in repositories {
        // Skip logging for archived repositories completely
        if repo.archived {
            continue; // Skip silently
        }

        info!("Processing repository: {}", repo.full_name);
        process_repository(&client, &repo, &config)?;
    }

    info!("Webhook enforcement completed successfully");
    Ok(())
}

fn create_github_client(github_pat: &str) -> Result<Client, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", github_pat)).unwrap(),
    );
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static("Rust-GitHub-Webhook-Manager"),
    );
    headers.insert(
        "X-GitHub-Api-Version",
        HeaderValue::from_static("2022-11-28"),
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    Client::builder()
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(30))
        .build()
}

fn get_repositories(client: &Client, owner: &str) -> Result<Vec<Repository>, AppError> {
    // First try to get repositories as if owner is an organization
    match get_org_repositories(client, owner) {
        Ok(repos) => {
            info!(
                "Successfully fetched repositories for organization: {}",
                owner
            );
            Ok(repos)
        }
        Err(err) => {
            // If that fails, try to get repositories as if owner is a user
            match err {
                AppError::ApiError { status, .. } if status == 404 => {
                    info!("Owner is not an organization, trying as user");
                    get_user_repositories(client, owner)
                }
                _ => Err(err),
            }
        }
    }
}

fn get_org_repositories(client: &Client, org: &str) -> Result<Vec<Repository>, AppError> {
    let mut all_repos = Vec::new();
    let mut page = 1;
    let per_page = 100;

    loop {
        let url = format!(
            "https://api.github.com/orgs/{}/repos?page={}&per_page={}&type=all",
            org, page, per_page
        );

        let response = client.get(&url).send()?;

        // Check for next page before consuming response body
        let has_next = has_next_page(&response);

        // Handle error response without consuming it
        check_response_status(&response)?;

        let repos: Vec<Repository> = response.json()?;
        if repos.is_empty() {
            break;
        }

        all_repos.extend(repos);

        // Use the previously stored result for pagination
        if !has_next {
            break;
        }

        page += 1;
    }

    Ok(all_repos)
}

fn get_user_repositories(client: &Client, username: &str) -> Result<Vec<Repository>, AppError> {
    let mut all_repos = Vec::new();
    let mut page = 1;
    let per_page = 100;

    loop {
        // Use the authenticated /user/repos endpoint which gives access to private repos
        let url = format!(
            "https://api.github.com/user/repos?page={}&per_page={}&affiliation=owner&visibility=all",
            page, per_page
        );

        let response = client.get(&url).send()?;

        // Check for next page before consuming response body
        let has_next = has_next_page(&response);

        // Handle error response without consuming it
        check_response_status(&response)?;

        let repos: Vec<Repository> = response.json()?;
        if repos.is_empty() {
            break;
        }

        // Filter to only include repos owned by the specified user
        let owned_repos: Vec<Repository> = repos
            .into_iter()
            .filter(|r| r.owner.login == username)
            .collect();

        all_repos.extend(owned_repos);

        // Use the previously stored result for pagination
        if !has_next {
            break;
        }

        page += 1;
    }

    Ok(all_repos)
}

fn process_repository(
    client: &Client,
    repo: &Repository,
    config: &AppConfig,
) -> Result<(), AppError> {
    // Check if repository is archived and silently skip it
    if repo.archived {
        // Skip without logging any warnings or errors
        debug!("Skipping archived repository: {}", repo.full_name);
        return Ok(());
    }

    // List existing webhooks
    let hooks = match get_webhooks(client, &repo.owner.login, &repo.name) {
        Ok(hooks) => hooks,
        Err(err) => {
            // Check if this is a 403 error, which might indicate an archived repository
            if let AppError::ApiError { status, message } = &err {
                if *status == 403 {
                    // Give a more specific message for archived repositories
                    info!("Skipping repository {}: {}", repo.full_name, message);
                    return Ok(()); // Skip this repository rather than failing the entire process
                }
            }
            return Err(err);
        }
    };

    debug!("Found {} webhooks in repository {}", hooks.len(), repo.name);

    // Find any webhook with matching URL
    let matching_hook = hooks.iter().find(|h| h.config.url == config.webhook_url);

    match matching_hook {
        Some(hook) => {
            // Check if webhook needs updates
            let desired_config = WebhookConfig {
                url: config.webhook_url.clone(),
                content_type: "json".to_string(),
                secret: Some(config.webhook_secret.clone()),
                insecure_ssl: "1".to_string(),
            };

            // Check if secret is masked (GitHub returns asterisks for security)
            let is_secret_masked = hook
                .config
                .secret
                .as_ref()
                .map_or(false, |s| s.chars().all(|c| c == '*'));

            // Only count secret as needing update if it's not masked or we're forcing secret updates
            let needs_secret_update = if is_secret_masked && !config.force_secret {
                debug!(
                    "Webhook for {} has a masked secret ('********'). Assuming it's correct. Use --force-secret to override.",
                    repo.full_name
                );
                false // Assume masked secret is correct unless force_secret is true
            } else if is_secret_masked && config.force_secret {
                info!(
                    "Webhook for {} has a masked secret but --force-secret is enabled. Will update secret.",
                    repo.full_name
                );
                true
            } else {
                hook.config.secret != desired_config.secret
            };

            let needs_update = hook.config.content_type != desired_config.content_type
                || needs_secret_update
                || hook.config.insecure_ssl != desired_config.insecure_ssl
                || hook.events != vec!["*".to_string()]
                || !hook.active;

            if needs_update {
                info!(
                    "Webhook for {} needs to be updated (id: {})",
                    repo.full_name, hook.id
                );

                if !config.dry_run {
                    match update_webhook(client, &repo.owner.login, &repo.name, hook.id, config) {
                        Ok(_) => info!("Updated webhook for {}", repo.full_name),
                        Err(err) => {
                            // Check if this is a 403 error, which might indicate an archived repository
                            if let AppError::ApiError { status, message } = &err {
                                if *status == 403 {
                                    // Give a more specific message for archived repositories
                                    warn!(
                                        "Could not update webhook for {}: {}",
                                        repo.full_name, message
                                    );
                                    return Ok(()); // Continue with other repositories
                                }
                            }
                            return Err(err);
                        }
                    }
                } else {
                    info!("[DRY RUN] Would update webhook for {}", repo.full_name);
                }
            } else {
                info!(
                    "Webhook for {} is already configured correctly",
                    repo.full_name
                );
            }
        }
        None => {
            info!("No matching webhook found for {}", repo.full_name);

            if !config.dry_run {
                match create_webhook(client, &repo.owner.login, &repo.name, config) {
                    Ok(_) => info!("Created webhook for {}", repo.full_name),
                    Err(err) => {
                        // Check if this is a 403 error, which might indicate an archived repository
                        if let AppError::ApiError { status, message } = &err {
                            if *status == 403 {
                                // Give a more specific message for archived repositories
                                warn!(
                                    "Could not create webhook for {}: {}",
                                    repo.full_name, message
                                );
                                return Ok(()); // Continue with other repositories
                            }
                        }
                        return Err(err);
                    }
                }
            } else {
                info!("[DRY RUN] Would create webhook for {}", repo.full_name);
            }
        }
    }

    Ok(())
}

fn get_webhooks(client: &Client, owner: &str, repo: &str) -> Result<Vec<Webhook>, AppError> {
    let url = format!("https://api.github.com/repos/{}/{}/hooks", owner, repo);
    let response = client.get(&url).send()?;
    check_response_status(&response)?;

    let hooks: Vec<Webhook> = response.json()?;
    Ok(hooks)
}

fn create_webhook(
    client: &Client,
    owner: &str,
    repo: &str,
    config: &AppConfig,
) -> Result<(), AppError> {
    let url = format!("https://api.github.com/repos/{}/{}/hooks", owner, repo);

    let webhook = WebhookCreate {
        config: WebhookConfig {
            url: config.webhook_url.clone(),
            content_type: "json".to_string(),
            secret: Some(config.webhook_secret.clone()),
            insecure_ssl: "1".to_string(),
        },
        events: vec!["*".to_string()],
        active: true,
    };

    let response = client.post(&url).json(&webhook).send()?;
    check_response_status(&response)?;

    Ok(())
}

fn update_webhook(
    client: &Client,
    owner: &str,
    repo: &str,
    hook_id: u64,
    config: &AppConfig,
) -> Result<(), AppError> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/hooks/{}",
        owner, repo, hook_id
    );

    let webhook = WebhookCreate {
        config: WebhookConfig {
            url: config.webhook_url.clone(),
            content_type: "json".to_string(),
            secret: Some(config.webhook_secret.clone()),
            insecure_ssl: "1".to_string(),
        },
        events: vec!["*".to_string()],
        active: true,
    };

    let response = client.patch(&url).json(&webhook).send()?;
    check_response_status(&response)?;

    Ok(())
}

fn check_response_status(response: &Response) -> Result<(), AppError> {
    // Check and log rate limit information
    if let Some(rate_limit) = extract_rate_limit(response) {
        if rate_limit.remaining < 10 {
            warn!(
                "GitHub API rate limit nearly exhausted: {}/{} (resets in {} seconds)",
                rate_limit.remaining,
                rate_limit.limit,
                rate_limit.reset.saturating_sub(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                )
            );
        } else {
            debug!(
                "GitHub API rate limit: {}/{} remaining",
                rate_limit.remaining, rate_limit.limit
            );
        }
    }

    let status = response.status();
    if status.is_success() {
        return Ok(());
    }

    // Handle specific error status codes
    match status.as_u16() {
        401 => {
            error!("Authentication failed. Check your GitHub PAT.");
            Err(AppError::ApiError {
                status: status.as_u16(),
                message: "Authentication failed - invalid GitHub token".to_string(),
            })
        }
        403 => {
            if response
                .headers()
                .get("X-RateLimit-Remaining")
                .map_or(false, |v| v == "0")
            {
                error!("GitHub API rate limit exceeded.");
                Err(AppError::ApiError {
                    status: status.as_u16(),
                    message: "Rate limit exceeded".to_string(),
                })
            } else {
                // This could be due to archived repository, repository visibility,
                // or other permission issues
                error!("Permission denied: {}", response.url());

                // Special note for possible archived repositories
                warn!("If this is a repository webhook operation, check if the repository is archived. GitHub prevents webhook operations on archived repositories.");

                Err(AppError::ApiError {
                    status: status.as_u16(),
                    message: format!("Permission denied for {}. GitHub prevents webhook operations on archived repositories. Check if the repository is archived or if your token lacks required permissions.", response.url()),
                })
            }
        }
        404 => {
            warn!("Resource not found: {}", response.url());
            Err(AppError::ApiError {
                status: status.as_u16(),
                message: format!("Resource not found: {}", response.url()),
            })
        }
        _ => {
            error!("GitHub API error: {} for URL: {}", status, response.url());
            Err(AppError::ApiError {
                status: status.as_u16(),
                message: format!("GitHub API error ({}): {}", status, response.url()),
            })
        }
    }
}

fn extract_rate_limit(response: &Response) -> Option<RateLimit> {
    let limit = response
        .headers()
        .get("X-RateLimit-Limit")?
        .to_str()
        .ok()?
        .parse::<u32>()
        .ok()?;

    let remaining = response
        .headers()
        .get("X-RateLimit-Remaining")?
        .to_str()
        .ok()?
        .parse::<u32>()
        .ok()?;

    let reset = response
        .headers()
        .get("X-RateLimit-Reset")?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()?;

    Some(RateLimit {
        limit,
        remaining,
        reset,
    })
}

fn has_next_page(response: &Response) -> bool {
    if let Some(link_header) = response.headers().get(LINK) {
        if let Ok(link_str) = link_header.to_str() {
            return link_str.contains("rel=\"next\"");
        }
    }
    false
}

fn remove_webhooks(config: &AppConfig, all: bool) -> Result<(), AppError> {
    if all {
        info!(
            "Removing ALL webhooks from repositories for owner: {}",
            config.repo_owner
        );
    } else {
        info!(
            "Removing webhooks with URL {} from repositories for owner: {}",
            config.webhook_url, config.repo_owner
        );
    }

    let client = create_github_client(&config.github_pat)?;
    let repositories = get_repositories(&client, &config.repo_owner)?;

    // Count non-archived repositories
    let active_repos = repositories.iter().filter(|r| !r.archived).count();
    info!(
        "Found {} repositories ({} active, {} archived)",
        repositories.len(),
        active_repos,
        repositories.len() - active_repos
    );

    let mut removed_count = 0;
    let mut processed_count = 0;
    let mut skipped_count = 0;

    for repo in repositories {
        // Skip archived repositories
        if repo.archived {
            debug!("Skipping archived repository: {}", repo.full_name);
            skipped_count += 1;
            continue;
        }

        processed_count += 1;
        let result = if all {
            remove_all_webhooks_from_repository(&client, &repo, config.dry_run)
        } else {
            remove_matching_webhook_from_repository(
                &client,
                &repo,
                &config.webhook_url,
                config.dry_run,
            )
        };

        match result {
            Ok(count) => {
                removed_count += count;
                if count > 0 {
                    if config.dry_run {
                        info!(
                            "[DRY RUN] Would remove {} webhook(s) from {}",
                            count, repo.full_name
                        );
                    } else {
                        info!("Removed {} webhook(s) from {}", count, repo.full_name);
                    }
                } else {
                    debug!("No matching webhooks found in {}", repo.full_name);
                }
            }
            Err(err) => {
                error!(
                    "Failed to remove webhooks from repository {}: {}",
                    repo.full_name, err
                );
            }
        }
    }

    if config.dry_run {
        info!(
            "[DRY RUN] Would remove {} webhook(s) from {} repositories ({} skipped)",
            removed_count, processed_count, skipped_count
        );
    } else {
        info!(
            "Removed {} webhook(s) from {} repositories ({} skipped)",
            removed_count, processed_count, skipped_count
        );
    }

    Ok(())
}

fn remove_all_webhooks_from_repository(
    client: &Client,
    repo: &Repository,
    dry_run: bool,
) -> Result<usize, AppError> {
    let hooks = get_webhooks(client, &repo.owner.login, &repo.name)?;
    let hook_count = hooks.len();

    if hook_count == 0 {
        return Ok(0);
    }

    if !dry_run {
        for hook in &hooks {
            match remove_webhook(client, &repo.owner.login, &repo.name, hook.id) {
                Ok(_) => {}
                Err(err) => {
                    warn!(
                        "Failed to remove webhook (id: {}) from repository {}: {}",
                        hook.id, repo.full_name, err
                    );
                }
            }
        }
    }

    Ok(hook_count)
}

fn remove_matching_webhook_from_repository(
    client: &Client,
    repo: &Repository,
    webhook_url: &str,
    dry_run: bool,
) -> Result<usize, AppError> {
    let hooks = get_webhooks(client, &repo.owner.login, &repo.name)?;
    let matching_hooks: Vec<&Webhook> = hooks
        .iter()
        .filter(|h| h.config.url == webhook_url)
        .collect();

    let matching_count = matching_hooks.len();
    if matching_count == 0 {
        return Ok(0);
    }

    if !dry_run {
        for hook in matching_hooks {
            match remove_webhook(client, &repo.owner.login, &repo.name, hook.id) {
                Ok(_) => {}
                Err(err) => {
                    warn!(
                        "Failed to remove webhook (id: {}) with URL {} from repository {}: {}",
                        hook.id, webhook_url, repo.full_name, err
                    );
                }
            }
        }
    }

    Ok(matching_count)
}

fn remove_webhook(client: &Client, owner: &str, repo: &str, hook_id: u64) -> Result<(), AppError> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/hooks/{}",
        owner, repo, hook_id
    );
    let response = client.delete(&url).send()?;
    check_response_status(&response)?;

    Ok(())
}
