// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! PR comment posting utilities.
//!
//! Supports:
//! - GitHub (Actions)
//! - GitLab (CI)
//! - Bitbucket (Pipelines)
//! - Azure DevOps (Pipelines)

use super::ci_env::{detect_ci_platform, CiPlatform};
use std::env;

/// Context extracted from CI environment
#[derive(Debug, Clone)]
pub struct PRContext {
    pub platform: CiPlatform,
    pub token: String,
    pub repo: String,      // owner/repo for GitHub, project_id for GitLab
    pub pr_number: String, // PR/MR number
    pub api_url: String,   // Base API URL
}

impl PRContext {
    /// Detect CI platform and extract PR context from environment
    pub fn from_env() -> Result<Self, String> {
        match detect_ci_platform() {
            Some(CiPlatform::GitHub) => Self::from_github_env(),
            Some(CiPlatform::GitLab) => Self::from_gitlab_env(),
            Some(CiPlatform::Bitbucket) => Self::from_bitbucket_env(),
            Some(CiPlatform::AzureDevOps) => Self::from_azure_devops_env(),
            None => Err("No supported CI environment detected. Supported: GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure DevOps Pipelines".to_string()),
        }
    }

    fn from_github_env() -> Result<Self, String> {
        let token = env::var("GITHUB_TOKEN")
            .or_else(|_| env::var("GH_TOKEN"))
            .map_err(|_| {
                "GITHUB_TOKEN not set. Add 'permissions: pull-requests: write' to your workflow."
            })?;

        let repo = env::var("GITHUB_REPOSITORY").map_err(|_| "GITHUB_REPOSITORY not set")?;

        // PR number comes from event payload
        let pr_number = Self::extract_github_pr_number()?;

        let api_url =
            env::var("GITHUB_API_URL").unwrap_or_else(|_| "https://api.github.com".to_string());

        Ok(PRContext {
            platform: CiPlatform::GitHub,
            token,
            repo,
            pr_number,
            api_url,
        })
    }

    fn extract_github_pr_number() -> Result<String, String> {
        // First check GITHUB_EVENT_PATH for pull_request event
        if let Ok(event_path) = env::var("GITHUB_EVENT_PATH") {
            if let Ok(content) = std::fs::read_to_string(&event_path) {
                if let Ok(event) = serde_json::from_str::<serde_json::Value>(&content) {
                    // pull_request event
                    if let Some(pr_num) = event
                        .get("pull_request")
                        .and_then(|pr| pr.get("number"))
                        .and_then(|n| n.as_u64())
                    {
                        return Ok(pr_num.to_string());
                    }
                    // issue_comment event (for /review commands)
                    if let Some(pr_num) = event
                        .get("issue")
                        .and_then(|issue| issue.get("number"))
                        .and_then(|n| n.as_u64())
                    {
                        return Ok(pr_num.to_string());
                    }
                }
            }
        }

        // Fallback: check GITHUB_REF for refs/pull/123/merge format
        if let Ok(github_ref) = env::var("GITHUB_REF") {
            if github_ref.starts_with("refs/pull/") {
                let parts: Vec<&str> = github_ref.split('/').collect();
                if parts.len() >= 3 {
                    return Ok(parts[2].to_string());
                }
            }
        }

        Err(
            "Could not determine PR number. Ensure workflow runs on pull_request event."
                .to_string(),
        )
    }

    fn from_gitlab_env() -> Result<Self, String> {
        let token = env::var("GITLAB_TOKEN")
            .or_else(|_| env::var("CI_JOB_TOKEN"))
            .map_err(|_| "GITLAB_TOKEN or CI_JOB_TOKEN not set")?;

        let project_id = env::var("CI_PROJECT_ID").map_err(|_| "CI_PROJECT_ID not set")?;

        let mr_iid = env::var("CI_MERGE_REQUEST_IID").map_err(|_| {
            "CI_MERGE_REQUEST_IID not set. Ensure pipeline runs on merge_request events."
        })?;

        let api_url =
            env::var("CI_API_V4_URL").unwrap_or_else(|_| "https://gitlab.com/api/v4".to_string());

        Ok(PRContext {
            platform: CiPlatform::GitLab,
            token,
            repo: project_id,
            pr_number: mr_iid,
            api_url,
        })
    }

    fn from_bitbucket_env() -> Result<Self, String> {
        let token = env::var("BITBUCKET_TOKEN").map_err(|_| "BITBUCKET_TOKEN not set")?;

        let workspace =
            env::var("BITBUCKET_WORKSPACE").map_err(|_| "BITBUCKET_WORKSPACE not set")?;
        let repo_slug =
            env::var("BITBUCKET_REPO_SLUG").map_err(|_| "BITBUCKET_REPO_SLUG not set")?;

        let pr_id = env::var("BITBUCKET_PR_ID")
            .map_err(|_| "BITBUCKET_PR_ID not set. Ensure pipeline runs on pull-request events.")?;

        Ok(PRContext {
            platform: CiPlatform::Bitbucket,
            token,
            repo: format!("{}/{}", workspace, repo_slug),
            pr_number: pr_id,
            api_url: "https://api.bitbucket.org/2.0".to_string(),
        })
    }

    fn from_azure_devops_env() -> Result<Self, String> {
        // System.AccessToken is not exposed to scripts unless explicitly mapped.
        let token = env::var("SYSTEM_ACCESSTOKEN").map_err(|_| {
            "SYSTEM_ACCESSTOKEN not set. Map it on the step:\n  \
             env:\n    SYSTEM_ACCESSTOKEN: $(System.AccessToken)\n\
             and grant the build service 'Contribute to pull requests' on the repository."
        })?;

        let collection_uri = env::var("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI")
            .map_err(|_| "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI not set")?;

        // Project GUID, not name: names may contain spaces and need URL-encoding.
        let project_id =
            env::var("SYSTEM_TEAMPROJECTID").map_err(|_| "SYSTEM_TEAMPROJECTID not set")?;

        let repository_id =
            env::var("BUILD_REPOSITORY_ID").map_err(|_| "BUILD_REPOSITORY_ID not set")?;

        let pr_id = env::var("SYSTEM_PULLREQUEST_PULLREQUESTID").map_err(|_| {
            "SYSTEM_PULLREQUEST_PULLREQUESTID not set. Ensure the run is a pull request \
             validation build (branch policy build validation or PR trigger)."
        })?;

        Ok(PRContext {
            platform: CiPlatform::AzureDevOps,
            token,
            repo: repository_id,
            pr_number: pr_id,
            api_url: format!("{}/{}", collection_uri.trim_end_matches('/'), project_id),
        })
    }
}

/// Comment marker to identify Lexega comments for upsert
const COMMENT_MARKER: &str = "<!-- lexega-review-comment -->";

/// Extra (non-secret) headers required by the GitHub API.
const GITHUB_API_HEADERS: &[&str] = &[
    "Accept: application/vnd.github+json",
    "X-GitHub-Api-Version: 2022-11-28",
];

/// Display label for error messages.
fn platform_label(platform: &CiPlatform) -> &'static str {
    match platform {
        CiPlatform::GitHub => "GitHub",
        CiPlatform::GitLab => "GitLab",
        CiPlatform::Bitbucket => "Bitbucket",
        CiPlatform::AzureDevOps => "Azure DevOps",
    }
}

/// Platform-appropriate auth header line. Fed to curl via `--config -` on
/// stdin so the token never appears on argv (visible in /proc) or on disk.
fn auth_header(ctx: &PRContext) -> String {
    match ctx.platform {
        CiPlatform::GitLab => format!("PRIVATE-TOKEN: {}", ctx.token),
        CiPlatform::GitHub | CiPlatform::Bitbucket | CiPlatform::AzureDevOps => {
            format!("Authorization: Bearer {}", ctx.token)
        }
    }
}

/// Escape a value for a double-quoted curl config entry.
fn curl_config_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Truncated JSON for error messages.
fn json_snippet(value: &serde_json::Value) -> String {
    value.to_string().chars().take(200).collect()
}

/// Run curl and return (http_status, raw_response_body).
///
/// The auth header travels via `--config -` on stdin; the JSON payload via a
/// temp file (`--data-binary @file`), which sidesteps argv size limits — the
/// payload is markdown headed for a public PR comment, not a secret. Command
/// spawns curl directly (execve, no shell), so neither channel is ever
/// shell-parsed. The response body lands in a temp file and the `-w` write-out
/// confines stdout to the status code.
fn curl_transport(
    method: &str,
    url: &str,
    auth: &str,
    extra_headers: &[&str],
    payload: Option<&serde_json::Value>,
) -> Result<(u16, Vec<u8>), String> {
    use std::io::Write;

    // pid alone is not unique: concurrent callers in one process (tests) collide.
    static CALL_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = CALL_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let temp_dir = std::env::temp_dir();
    let pid = std::process::id();
    let body_path = temp_dir.join(format!("lexega-pr-response-{}-{}.json", pid, seq));
    let payload_path = temp_dir.join(format!("lexega-pr-payload-{}-{}.json", pid, seq));
    let cleanup = || {
        let _ = std::fs::remove_file(&body_path);
        let _ = std::fs::remove_file(&payload_path);
    };

    let body_path_str = body_path.to_str().ok_or_else(|| {
        format!(
            "Temp path is not valid UTF-8 (cannot pass to curl): {}",
            body_path.display()
        )
    })?;

    let mut args: Vec<String> = vec![
        "-sS".to_string(),
        "--max-time".to_string(),
        "30".to_string(),
        "-X".to_string(),
        method.to_string(),
        "--config".to_string(),
        "-".to_string(),
        "-o".to_string(),
        body_path_str.to_string(),
        "-w".to_string(),
        "%{http_code}".to_string(),
    ];
    for header in extra_headers {
        args.push("-H".to_string());
        args.push((*header).to_string());
    }
    if let Some(p) = payload {
        let payload_path_str = payload_path.to_str().ok_or_else(|| {
            format!(
                "Temp path is not valid UTF-8 (cannot pass to curl): {}",
                payload_path.display()
            )
        })?;
        std::fs::write(&payload_path, p.to_string())
            .map_err(|e| format!("Failed to write request payload: {}", e))?;
        args.push("-H".to_string());
        args.push("Content-Type: application/json".to_string());
        args.push("--data-binary".to_string());
        args.push(format!("@{}", payload_path_str));
    }
    args.push(url.to_string());

    let mut child = match std::process::Command::new("curl")
        .args(&args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            cleanup();
            return Err(format!("Failed to execute curl: {}", e));
        }
    };

    if let Some(ref mut stdin) = child.stdin {
        // Result deliberately discarded: returning early would orphan the
        // running curl child (Child::drop neither kills nor reaps). The
        // failure still surfaces — curl exits non-zero on a truncated config,
        // and an unauthenticated request fails the status check.
        let _ = writeln!(stdin, "header = \"{}\"", curl_config_escape(auth));
    }
    drop(child.stdin.take());

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            cleanup();
            return Err(format!("Failed to wait for curl: {}", e));
        }
    };

    if !output.status.success() {
        cleanup();
        return Err(format!(
            "curl request failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // curl claimed success but its `-o` body file is unreadable: fail the
    // call rather than hand back an empty body (2xx + empty body would
    // otherwise read as a successful API response).
    let body = match std::fs::read(&body_path) {
        Ok(b) => b,
        Err(e) => {
            cleanup();
            return Err(format!("Failed to read response body file: {}", e));
        }
    };
    cleanup();

    let status_text = String::from_utf8_lossy(&output.stdout);
    let status: u16 = status_text.trim().parse().map_err(|_| {
        format!(
            "Could not read HTTP status from curl write-out: {:?}",
            status_text
        )
    })?;

    Ok((status, body))
}

/// Execute an API call. Success means a 2xx status AND a JSON body (empty
/// body allowed). The JSON requirement is not redundant with the status
/// check: Azure DevOps serves its HTML sign-in page with HTTP 203 when auth
/// fails.
fn api_call(
    ctx: &PRContext,
    method: &str,
    url: &str,
    extra_headers: &[&str],
    payload: Option<&serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let label = platform_label(&ctx.platform);
    let (status, body) = curl_transport(method, url, &auth_header(ctx), extra_headers, payload)?;

    let value = if body.is_empty() {
        serde_json::Value::Null
    } else {
        match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => {
                let text = String::from_utf8_lossy(&body);
                let snippet: String = text.chars().take(200).collect();
                let hint = match ctx.platform {
                    CiPlatform::AzureDevOps => {
                        " (Azure DevOps serves a sign-in page when auth fails — is SYSTEM_ACCESSTOKEN mapped on the step?)"
                    }
                    CiPlatform::GitHub | CiPlatform::GitLab | CiPlatform::Bitbucket => "",
                };
                return Err(format!(
                    "Unexpected {} API response (HTTP {}, not JSON){}: {}",
                    label, status, hint, snippet
                ));
            }
        }
    };

    if !(200..=299).contains(&status) {
        return Err(api_error_message(label, status, &value));
    }

    Ok(value)
}

/// Human-readable error for a non-2xx API response.
fn api_error_message(label: &str, status: u16, value: &serde_json::Value) -> String {
    // GitHub/Azure DevOps: {"message": ...}; GitLab: {"error": ...} or
    // {"message": ...}; Bitbucket: {"error": {"message": ...}}
    let msg = value
        .get("message")
        .and_then(|m| m.as_str())
        .or_else(|| value.get("error").and_then(|e| e.as_str()))
        .or_else(|| {
            value
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
        });

    match msg {
        Some(m) if m.contains("Bad credentials") => format!(
            "{} API (HTTP {}): Authentication failed. Check your token is valid and has correct permissions.",
            label, status
        ),
        Some(m) if m.contains("Not Found") => format!(
            "{} API (HTTP {}): Resource not found. Check repo/PR number are correct and token has access.",
            label, status
        ),
        Some(m) if m.contains("rate limit") || m.contains("API rate limit") => format!(
            "{} API (HTTP {}): Rate limit exceeded. Wait a few minutes and try again.",
            label, status
        ),
        Some(m) if m.contains("Forbidden") => format!(
            "{} API (HTTP {}): Permission denied. Ensure token has 'pull-requests: write' permission.",
            label, status
        ),
        Some(m) if m.contains("TF401027") || m.contains("PullRequestContribute") => format!(
            "{} API (HTTP {}): Permission denied. Grant the build service identity 'Contribute to pull requests' on the repository (Project Settings → Repositories → Security).",
            label, status
        ),
        Some(m) => format!("{} API error (HTTP {}): {}", label, status, m),
        None => format!("{} API error (HTTP {})", label, status),
    }
}

/// Post or update a PR comment with the given markdown content
pub fn post_pr_comment(ctx: &PRContext, markdown: &str) -> Result<(), String> {
    let body = format!("{}\n{}", COMMENT_MARKER, markdown);

    match ctx.platform {
        CiPlatform::GitHub => post_github_comment(ctx, &body),
        CiPlatform::GitLab => post_gitlab_comment(ctx, &body),
        CiPlatform::Bitbucket => post_bitbucket_comment(ctx, &body),
        CiPlatform::AzureDevOps => post_azure_devops_comment(ctx, &body),
    }
}

fn post_github_comment(ctx: &PRContext, body: &str) -> Result<(), String> {
    // First, try to find existing Lexega comment to update
    let list_url = format!(
        "{}/repos/{}/issues/{}/comments",
        ctx.api_url, ctx.repo, ctx.pr_number
    );

    let payload = serde_json::json!({ "body": body });

    if let Some(comment_id) = find_existing_comment(ctx, &list_url)? {
        // Update existing comment
        let update_url = format!(
            "{}/repos/{}/issues/comments/{}",
            ctx.api_url, ctx.repo, comment_id
        );
        api_call(
            ctx,
            "PATCH",
            &update_url,
            GITHUB_API_HEADERS,
            Some(&payload),
        )?;
        eprintln!("✓ Updated existing PR comment (id: {})", comment_id);
    } else {
        // Create new comment
        api_call(ctx, "POST", &list_url, GITHUB_API_HEADERS, Some(&payload))?;
        eprintln!("✓ Posted new PR comment");
    }

    Ok(())
}

fn post_gitlab_comment(ctx: &PRContext, body: &str) -> Result<(), String> {
    // GitLab MR notes API
    let list_url = format!(
        "{}/projects/{}/merge_requests/{}/notes",
        ctx.api_url, ctx.repo, ctx.pr_number
    );

    let payload = serde_json::json!({ "body": body });

    if let Some(note_id) = find_existing_gitlab_note(ctx, &list_url)? {
        // Update existing note
        let update_url = format!(
            "{}/projects/{}/merge_requests/{}/notes/{}",
            ctx.api_url, ctx.repo, ctx.pr_number, note_id
        );
        api_call(ctx, "PUT", &update_url, &[], Some(&payload))?;
        eprintln!("✓ Updated existing MR note (id: {})", note_id);
    } else {
        // Create new note
        api_call(ctx, "POST", &list_url, &[], Some(&payload))?;
        eprintln!("✓ Posted new MR note");
    }

    Ok(())
}

fn post_bitbucket_comment(ctx: &PRContext, body: &str) -> Result<(), String> {
    // Bitbucket PR comments API
    let url = format!(
        "{}/repositories/{}/pullrequests/{}/comments",
        ctx.api_url, ctx.repo, ctx.pr_number
    );

    // Finding an earlier comment on Bitbucket means paging through every
    // comment, so each run posts a new one.
    let payload = serde_json::json!({ "content": { "raw": body } });
    api_call(ctx, "POST", &url, &[], Some(&payload))?;
    eprintln!("✓ Posted PR comment");

    Ok(())
}

fn post_azure_devops_comment(ctx: &PRContext, body: &str) -> Result<(), String> {
    // api-version=6.0: supported by Azure DevOps Services and Server 2020+.
    let threads_url = format!(
        "{}/_apis/git/repositories/{}/pullRequests/{}/threads?api-version=6.0",
        ctx.api_url, ctx.repo, ctx.pr_number
    );

    if let Some((thread_id, comment_id)) = find_existing_azure_devops_comment(ctx, &threads_url)? {
        let update_url = format!(
            "{}/_apis/git/repositories/{}/pullRequests/{}/threads/{}/comments/{}?api-version=6.0",
            ctx.api_url, ctx.repo, ctx.pr_number, thread_id, comment_id
        );
        let payload = serde_json::json!({ "content": body });
        api_call(ctx, "PATCH", &update_url, &[], Some(&payload))?;
        eprintln!("✓ Updated existing PR thread comment (id: {})", comment_id);
    } else {
        // status "closed": an informational comment must never block PR completion
        // under a "resolve all comments" branch policy.
        let payload = serde_json::json!({
            "comments": [{
                "parentCommentId": 0,
                "content": body,
                "commentType": "text"
            }],
            "status": "closed"
        });
        api_call(ctx, "POST", &threads_url, &[], Some(&payload))?;
        eprintln!("✓ Posted new PR thread comment");
    }

    Ok(())
}

fn find_existing_comment(ctx: &PRContext, list_url: &str) -> Result<Option<u64>, String> {
    let value = api_call(ctx, "GET", list_url, GITHUB_API_HEADERS, None)?;

    let comments = value.as_array().ok_or_else(|| {
        format!(
            "Unexpected GitHub API response shape (expected array): {}",
            json_snippet(&value)
        )
    })?;

    for comment in comments {
        if let Some(body) = comment.get("body").and_then(|b| b.as_str()) {
            if body.contains(COMMENT_MARKER) {
                if let Some(id) = comment.get("id").and_then(|id| id.as_u64()) {
                    return Ok(Some(id));
                }
            }
        }
    }

    Ok(None)
}

fn find_existing_gitlab_note(ctx: &PRContext, list_url: &str) -> Result<Option<u64>, String> {
    let value = api_call(ctx, "GET", list_url, &[], None)?;

    let notes = value.as_array().ok_or_else(|| {
        format!(
            "Unexpected GitLab API response shape (expected array): {}",
            json_snippet(&value)
        )
    })?;

    for note in notes {
        if let Some(body) = note.get("body").and_then(|b| b.as_str()) {
            if body.contains(COMMENT_MARKER) {
                if let Some(id) = note.get("id").and_then(|id| id.as_u64()) {
                    return Ok(Some(id));
                }
            }
        }
    }

    Ok(None)
}

/// Find the (thread_id, comment_id) of an existing Lexega comment, if any.
fn find_existing_azure_devops_comment(
    ctx: &PRContext,
    threads_url: &str,
) -> Result<Option<(u64, u64)>, String> {
    let value = api_call(ctx, "GET", threads_url, &[], None)?;

    // Threads list: {"value": [{"id": N, "comments": [{"id": M, "content": "..."}]}], "count": K}
    let threads = value
        .get("value")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            format!(
                "Unexpected Azure DevOps API response shape (no 'value' array): {}",
                json_snippet(&value)
            )
        })?;

    for thread in threads {
        let thread_id = match thread.get("id").and_then(|id| id.as_u64()) {
            Some(id) => id,
            None => continue,
        };
        if let Some(comments) = thread.get("comments").and_then(|c| c.as_array()) {
            for comment in comments {
                if let Some(content) = comment.get("content").and_then(|c| c.as_str()) {
                    if content.contains(COMMENT_MARKER) {
                        if let Some(comment_id) = comment.get("id").and_then(|id| id.as_u64()) {
                            return Ok(Some((thread_id, comment_id)));
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    /// Markdown stressing every JSON-escaping hazard: quotes, backslashes,
    /// newlines, code fences, unicode.
    const HOSTILE_MARKDOWN: &str =
        "## Findings\n\n| \"col\" | path |\n|---|---|\n| `WHERE x = 'a\\b'` | C:\\tmp\\q.sql |\n\n✓ done";

    /// Serve `responses` (one per connection) on a loopback port, recording
    /// each raw HTTP request.
    struct MockServer {
        port: u16,
        requests: Arc<Mutex<Vec<String>>>,
        handle: std::thread::JoinHandle<()>,
    }

    impl MockServer {
        fn start(responses: Vec<String>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&requests);
            let handle = std::thread::spawn(move || {
                for response in responses {
                    let (mut stream, _) = listener.accept().unwrap();
                    let raw = read_http_request(&mut stream);
                    recorded.lock().unwrap().push(raw);
                    stream.write_all(response.as_bytes()).unwrap();
                }
            });
            MockServer {
                port,
                requests,
                handle,
            }
        }

        /// Wait for all expected connections and return the captured requests.
        fn finish(self) -> Vec<String> {
            self.handle.join().unwrap();
            let requests = self.requests.lock().unwrap();
            requests.clone()
        }
    }

    /// Read one HTTP request: headers, then Content-Length body bytes.
    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let headers_end = loop {
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0, "connection closed before headers complete");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let header_text = String::from_utf8_lossy(&buf[..headers_end]).to_string();
        let content_length: usize = header_text
            .lines()
            .find_map(|l| {
                let (name, value) = l.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())?
            })
            .unwrap_or(0);
        while buf.len() < headers_end + content_length {
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0, "connection closed before body complete");
            buf.extend_from_slice(&chunk[..n]);
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    fn http_response(status_line: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status_line,
            body.len(),
            body
        )
    }

    fn test_ctx(platform: CiPlatform, port: u16) -> PRContext {
        PRContext {
            platform,
            token: "test-secret-token".to_string(),
            repo: "owner/repo".to_string(),
            pr_number: "5".to_string(),
            api_url: format!("http://127.0.0.1:{}", port),
        }
    }

    /// Extract the JSON body of the nth captured request.
    fn request_json(requests: &[String], n: usize) -> serde_json::Value {
        let body = requests[n].split("\r\n\r\n").nth(1).unwrap();
        serde_json::from_str(body)
            .unwrap_or_else(|e| panic!("request {} body is not valid JSON ({}): {}", n, e, body))
    }

    fn request_line(requests: &[String], n: usize) -> &str {
        requests[n].lines().next().unwrap()
    }

    #[test]
    fn github_posts_new_comment_with_hostile_markdown() {
        let server = MockServer::start(vec![
            http_response("200 OK", "[]"),
            http_response("201 Created", r#"{"id": 1}"#),
        ]);
        let ctx = test_ctx(CiPlatform::GitHub, server.port);

        post_pr_comment(&ctx, HOSTILE_MARKDOWN).unwrap();

        let requests = server.finish();
        assert_eq!(
            request_line(&requests, 0),
            "GET /repos/owner/repo/issues/5/comments HTTP/1.1"
        );
        assert!(requests[0].contains("Authorization: Bearer test-secret-token"));
        assert!(requests[0].contains("Accept: application/vnd.github+json"));
        assert_eq!(
            request_line(&requests, 1),
            "POST /repos/owner/repo/issues/5/comments HTTP/1.1"
        );
        let posted = request_json(&requests, 1);
        assert_eq!(
            posted["body"].as_str().unwrap(),
            format!("{}\n{}", COMMENT_MARKER, HOSTILE_MARKDOWN)
        );
    }

    #[test]
    fn github_updates_existing_marker_comment() {
        let existing = serde_json::json!([
            {"id": 41, "body": "unrelated comment"},
            {"id": 42, "body": format!("{}\nold report", COMMENT_MARKER)}
        ]);
        let server = MockServer::start(vec![
            http_response("200 OK", &existing.to_string()),
            http_response("200 OK", r#"{"id": 42}"#),
        ]);
        let ctx = test_ctx(CiPlatform::GitHub, server.port);

        post_pr_comment(&ctx, "new report").unwrap();

        let requests = server.finish();
        assert_eq!(
            request_line(&requests, 1),
            "PATCH /repos/owner/repo/issues/comments/42 HTTP/1.1"
        );
    }

    #[test]
    fn gitlab_payload_survives_backslashes() {
        // Regression: the old hand-rolled JSON escaping broke on backslashes.
        let server = MockServer::start(vec![
            http_response("200 OK", "[]"),
            http_response("201 Created", r#"{"id": 7}"#),
        ]);
        let ctx = test_ctx(CiPlatform::GitLab, server.port);

        post_pr_comment(&ctx, HOSTILE_MARKDOWN).unwrap();

        let requests = server.finish();
        assert!(requests[0].contains("PRIVATE-TOKEN: test-secret-token"));
        let posted = request_json(&requests, 1);
        assert_eq!(
            posted["body"].as_str().unwrap(),
            format!("{}\n{}", COMMENT_MARKER, HOSTILE_MARKDOWN)
        );
    }

    #[test]
    fn bitbucket_posts_content_raw() {
        let server = MockServer::start(vec![http_response("201 Created", r#"{"id": 9}"#)]);
        let ctx = test_ctx(CiPlatform::Bitbucket, server.port);

        post_pr_comment(&ctx, HOSTILE_MARKDOWN).unwrap();

        let requests = server.finish();
        assert_eq!(
            request_line(&requests, 0),
            "POST /repositories/owner/repo/pullrequests/5/comments HTTP/1.1"
        );
        let posted = request_json(&requests, 0);
        assert_eq!(
            posted["content"]["raw"].as_str().unwrap(),
            format!("{}\n{}", COMMENT_MARKER, HOSTILE_MARKDOWN)
        );
    }

    #[test]
    fn azure_devops_new_thread_posts_closed() {
        let server = MockServer::start(vec![
            http_response("200 OK", r#"{"value": [], "count": 0}"#),
            http_response("200 OK", r#"{"id": 1}"#),
        ]);
        let ctx = test_ctx(CiPlatform::AzureDevOps, server.port);

        post_pr_comment(&ctx, HOSTILE_MARKDOWN).unwrap();

        let requests = server.finish();
        assert!(request_line(&requests, 1).starts_with(
            "POST /_apis/git/repositories/owner/repo/pullRequests/5/threads?api-version=6.0"
        ));
        let posted = request_json(&requests, 1);
        // Closed status: must never block PR completion under branch policy.
        assert_eq!(posted["status"].as_str().unwrap(), "closed");
        assert_eq!(
            posted["comments"][0]["content"].as_str().unwrap(),
            format!("{}\n{}", COMMENT_MARKER, HOSTILE_MARKDOWN)
        );
    }

    #[test]
    fn azure_devops_updates_existing_thread_comment() {
        let existing = serde_json::json!({
            "value": [
                {"id": 6, "comments": [{"id": 1, "content": "human discussion"}]},
                {"id": 7, "comments": [{"id": 3, "content": format!("{}\nold", COMMENT_MARKER)}]}
            ],
            "count": 2
        });
        let server = MockServer::start(vec![
            http_response("200 OK", &existing.to_string()),
            http_response("200 OK", r#"{"id": 3}"#),
        ]);
        let ctx = test_ctx(CiPlatform::AzureDevOps, server.port);

        post_pr_comment(&ctx, "new").unwrap();

        let requests = server.finish();
        assert!(request_line(&requests, 1).starts_with(
            "PATCH /_apis/git/repositories/owner/repo/pullRequests/5/threads/7/comments/3"
        ));
    }

    #[test]
    fn azure_devops_signin_page_is_typed_error() {
        // ADO serves its sign-in page with HTTP 203 when auth fails.
        let server = MockServer::start(vec![http_response(
            "203 Non-Authoritative Information",
            "<html><body>Sign in to your account</body></html>",
        )]);
        let ctx = test_ctx(CiPlatform::AzureDevOps, server.port);

        let err = post_pr_comment(&ctx, "report").unwrap_err();

        server.finish();
        assert!(err.contains("SYSTEM_ACCESSTOKEN"), "got: {}", err);
        assert!(err.contains("HTTP 203"), "got: {}", err);
    }

    #[test]
    fn non_2xx_error_includes_status_and_hint() {
        let server = MockServer::start(vec![http_response(
            "403 Forbidden",
            r#"{"message": "Forbidden"}"#,
        )]);
        let ctx = test_ctx(CiPlatform::GitHub, server.port);

        let err = post_pr_comment(&ctx, "report").unwrap_err();

        server.finish();
        assert!(err.contains("HTTP 403"), "got: {}", err);
        assert!(err.contains("pull-requests: write"), "got: {}", err);
    }

    #[test]
    fn ado_permission_error_names_the_grant() {
        let server = MockServer::start(vec![http_response(
            "401 Unauthorized",
            r#"{"message": "TF401027: You need the Git 'PullRequestContribute' permission"}"#,
        )]);
        let ctx = test_ctx(CiPlatform::AzureDevOps, server.port);

        let err = post_pr_comment(&ctx, "report").unwrap_err();

        server.finish();
        assert!(err.contains("Contribute to pull requests"), "got: {}", err);
    }
}
