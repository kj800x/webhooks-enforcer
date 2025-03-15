# GitHub Webhooks Enforcer

A Rust script that verifies and configures webhook settings across all repositories owned by a specified user or organization.

## Features

- Fetches all repositories for a specified GitHub user or organization
- Verifies existing webhook settings against desired configuration
- Creates or updates webhooks as needed
- Supports dry run mode to preview changes without applying them
- Handles API pagination and rate limits
- Command-line interface for easy usage

## Requirements

- Rust (latest stable version recommended)
- GitHub Personal Access Token with `admin:repo_hook` scope

## Setup

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/webhooks-enforcer.git
   cd webhooks-enforcer
   ```

2. Create a `.env` file by copying the example:
   ```
   cp .env.example .env
   ```

3. Edit the `.env` file and set the required environment variables:
   ```
   GITHUB_PAT=your_github_personal_access_token
   WEBHOOK_URL=https://your-webhook-endpoint.example.com/webhook
   WEBHOOK_SECRET=your_webhook_secret_key
   REPO_OWNER=your_github_username_or_organization
   DRY_RUN=false
   ```

## Usage

### Command-Line Interface

The application supports both environment variables and command-line arguments:

```
webhooks-enforcer [OPTIONS] [COMMAND]
```

Options:
- `-o, --owner <OWNER>` - GitHub owner (user or organization)
- `-u, --url <URL>` - Webhook URL
- `-s, --secret <SECRET>` - Webhook secret
- `-d, --dry-run` - Perform a dry run without making changes
- `-h, --help` - Display help information
- `-V, --version` - Display version information

Commands:
- `list` - List all repositories for the given owner
  - `-m, --mismatched` - Only show repositories with missing or misconfigured webhooks

### Examples

Build the application:

```
cargo build --release
```

Enforce webhooks using environment variables from `.env`:

```
./target/release/webhooks-enforcer
```

Enforce webhooks with command-line arguments:

```
./target/release/webhooks-enforcer --owner myorg --url https://example.com/webhook --secret mysecret
```

List all repositories and their webhook status:

```
./target/release/webhooks-enforcer list
```

List only repositories with missing or misconfigured webhooks:

```
./target/release/webhooks-enforcer list --mismatched
```

Perform a dry run to see what changes would be made:

```
./target/release/webhooks-enforcer --dry-run
```

### Environment Variables

- `GITHUB_PAT`: GitHub Personal Access Token with appropriate permissions
- `WEBHOOK_URL`: URL where webhook payloads will be sent
- `WEBHOOK_SECRET`: Secret key for securing webhook payloads
- `REPO_OWNER`: GitHub username or organization name owning the repositories
- `DRY_RUN`: Set to "true" to log actions without making changes

## Webhook Configuration

The script configures webhooks with the following settings:

```json
{
  "config": {
    "url": "{WEBHOOK_URL}",
    "content_type": "json",
    "secret": "{WEBHOOK_SECRET}",
    "insecure_ssl": "1"
  },
  "events": ["*"],
  "active": true
}
```

## Error Handling

The script includes robust error handling for:
- API rate limits
- Network issues
- Missing environment variables
- Permission errors

## License

MIT
