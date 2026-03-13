mod notify;

use anyhow::{anyhow, Result};
use chromiumoxide::browser::{Browser, BrowserConfig};
use chrono::Local;
use colored::Colorize;
use futures::StreamExt;
use notify::NotificationKit;
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::process;

fn format_tag(tag: &str) -> String {
    match tag {
        "SYSTEM" => "[SYSTEM]".bold().blue().to_string(),
        "TIME" => "[TIME]".bold().bright_black().to_string(),
        "INFO" => "[INFO]".bold().cyan().to_string(),
        "ACCOUNT" => "[ACCOUNT]".bold().magenta().to_string(),
        "HTTP" => "[HTTP]".bold().yellow().to_string(),
        "SUCCESS" => "[SUCCESS]".bold().green().to_string(),
        "ERROR" => "[ERROR]".bold().red().to_string(),
        "WARN" => "[WARN]".bold().yellow().to_string(),
        "NOTIFY" => "[NOTIFY]".bold().purple().to_string(),
        "STATS" => "[STATS]".bold().blue().to_string(),
        "BALANCE" => "[BALANCE]".bold().bright_yellow().to_string(),
        _ => format!("[{}]", tag),
    }
}

fn log_line(tag: &str, message: impl AsRef<str>) {
    println!("{} {}", format_tag(tag), message.as_ref());
}

fn log_account(tag: &str, account_name: &str, message: impl AsRef<str>) {
    log_line(
        tag,
        format!("account {} - {}", account_name, message.as_ref()),
    );
}

const BALANCE_HASH_FILE: &str = "balance_hash.txt";

#[derive(Debug, Deserialize, Serialize, Clone)]
struct AccountInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    cookies: SessionCookies,
    api_user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    github_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    github_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    totp_secret: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SessionCookies {
    session: String,
}

#[derive(Debug, Clone)]
struct UserInfo {
    success: bool,
    quota: f64,
    used_quota: f64,
    display: String,
    error: Option<String>,
    http_status: Option<u16>,
}

#[derive(Debug, Clone)]
struct BalanceInfo {
    quota: f64,
    used: f64,
}

fn load_balance_hash() -> Option<String> {
    fs::read_to_string(BALANCE_HASH_FILE).ok()
}

fn save_balance_hash(balance_hash: &str) -> Result<()> {
    fs::write(BALANCE_HASH_FILE, balance_hash)
        .map_err(|e| anyhow!("Warning: Failed to save balance hash: {}", e))
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    // Convert bytes to lowercase hex
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

fn generate_balance_hash(balances: &HashMap<String, BalanceInfo>) -> String {
    let simple_balances: HashMap<String, f64> =
        balances.iter().map(|(k, v)| (k.clone(), v.quota)).collect();

    // Using `unwrap` here is acceptable because `simple_balances` only contains
    // `String` keys and `f64` values and is fully under our control. If this ever
    // changes, consider turning this into a `Result<String>`.
    let balance_json = serde_json::to_string(&simple_balances).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(balance_json.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)[..16].to_string()
}

fn get_account_display_name(account_info: &AccountInfo, account_index: usize) -> String {
    account_info
        .name
        .clone()
        .unwrap_or_else(|| format!("Account {}", account_index + 1))
}

async fn get_waf_cookies_with_playwright(account_name: &str) -> Result<HashMap<String, String>> {
    log_account(
        "ACCOUNT",
        account_name,
        "starting browser to obtain WAF cookies",
    );

    // Use a unique user-data-dir to isolate each browser instance.
    // Without this, chromiumoxide defaults to a FIXED /tmp/chromiumoxide-runner
    // directory, causing cookie leakage between accounts.
    let browser_data_dir = std::env::temp_dir().join(format!(
        "anyrouter-waf-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));
    let (mut browser, mut handler) = Browser::launch(
        BrowserConfig::builder()
            .user_data_dir(&browser_data_dir)
            .window_size(1920, 1080)
            .build()
            .map_err(|e| anyhow!("Failed to build browser config: {}", e))?,
    )
    .await?;

    let handle = tokio::task::spawn(async move { while let Some(_) = handler.next().await {} });

    let page = browser.new_page("about:blank").await?;

    log_account(
        "ACCOUNT",
        account_name,
        "loading login page to obtain initial cookies",
    );

    page.goto("https://anyrouter.top/login").await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    let cookies = page.get_cookies().await?;
    let mut waf_cookies = HashMap::new();

    for cookie in cookies {
        let name = cookie.name.clone();
        let value = cookie.value.clone();
        if ["acw_tc", "cdn_sec_tc", "acw_sc__v2"].contains(&name.as_str()) {
            waf_cookies.insert(name, value);
        }
    }

    log_account(
        "ACCOUNT",
        account_name,
        format!(
            "collected {} WAF cookies after loading login page",
            waf_cookies.len()
        ),
    );

    let required_cookies = ["acw_tc", "cdn_sec_tc", "acw_sc__v2"];
    let missing_cookies: Vec<_> = required_cookies
        .iter()
        .filter(|c| !waf_cookies.contains_key::<str>(*c))
        .collect();

    browser.close().await?;
    handle.abort();
    let _ = fs::remove_dir_all(&browser_data_dir);

    if !missing_cookies.is_empty() {
        return Err(anyhow!(
            "{}: Missing WAF cookies: {:?}",
            account_name,
            missing_cookies
        ));
    }

    log_account("SUCCESS", account_name, "successfully resolved WAF cookies");

    Ok(waf_cookies)
}

async fn get_user_info(client: &Client, headers: &header::HeaderMap) -> UserInfo {
    match client
        .get("https://anyrouter.top/api/user/self")
        .headers(headers.clone())
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();

            if status.is_success() {
                if let Ok(data) = serde_json::from_str::<Value>(&body_text) {
                    if data
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        let empty_obj = json!({});
                        let user_data = data.get("data").unwrap_or(&empty_obj);
                        let quota = user_data
                            .get("quota")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0)
                            / 500000.0;
                        let used_quota = user_data
                            .get("used_quota")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0)
                            / 500000.0;

                        return UserInfo {
                            success: true,
                            quota: (quota * 100.0).round() / 100.0,
                            used_quota: (used_quota * 100.0).round() / 100.0,
                            display: format!(
                                "current balance ${:.2}, used ${:.2}",
                                quota, used_quota
                            ),
                            error: None,
                            http_status: Some(status.as_u16()),
                        };
                    }
                }
            }

            log_line("HTTP", format!("user/self HTTP {} body: {}", status, body_text));

            UserInfo {
                success: false,
                quota: 0.0,
                used_quota: 0.0,
                display: String::new(),
                error: Some(format!("user profile request failed: HTTP {}", status)),
                http_status: Some(status.as_u16()),
            }
        }
        Err(e) => UserInfo {
            success: false,
            quota: 0.0,
            used_quota: 0.0,
            display: String::new(),
            error: Some(format!("user profile request failed: {}", e)),
            http_status: None,
        },
    }
}

fn build_authenticated_client(
    waf_cookies: &HashMap<String, String>,
    session: &str,
    api_user: &str,
) -> Result<(Client, header::HeaderMap)> {
    let client = Client::builder()
        .build()
        .map_err(|e| anyhow!("failed to create HTTP client: {}", e))?;

    let mut all_cookies = waf_cookies.clone();
    if !session.is_empty() {
        all_cookies.insert("session".to_string(), session.to_string());
    }

    let cookie_header: String = all_cookies
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("; ");

    let mut headers = header::HeaderMap::new();
    headers.insert(header::COOKIE, cookie_header.parse().unwrap());
    headers.insert("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36".parse().unwrap());
    headers.insert(
        header::ACCEPT,
        "application/json, text/plain, */*".parse().unwrap(),
    );
    headers.insert(
        header::ACCEPT_LANGUAGE,
        "zh-CN,zh;q=0.9,en;q=0.8".parse().unwrap(),
    );
    headers.insert(
        header::REFERER,
        "https://anyrouter.top/console".parse().unwrap(),
    );
    headers.insert(header::ORIGIN, "https://anyrouter.top".parse().unwrap());
    headers.insert("new-api-user", api_user.parse().unwrap());

    Ok((client, headers))
}

fn generate_totp(secret_base32: &str) -> Result<String> {
    use data_encoding::BASE32;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    let normalized = secret_base32.to_uppercase().replace(' ', "");
    let secret = BASE32
        .decode(normalized.as_bytes())
        .map_err(|e| anyhow!("invalid TOTP secret (bad base32): {}", e))?;

    let time_step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        / 30;

    type HmacSha1 = Hmac<Sha1>;
    let mut mac =
        HmacSha1::new_from_slice(&secret).map_err(|e| anyhow!("HMAC error: {}", e))?;
    mac.update(&time_step.to_be_bytes());
    let result = mac.finalize().into_bytes();

    let offset = (result[19] & 0x0f) as usize;
    let code = u32::from_be_bytes([
        result[offset] & 0x7f,
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]) % 1_000_000;

    Ok(format!("{:06}", code))
}

async fn login_via_github_browser(
    account_name: &str,
    github_username: &str,
    github_password: &str,
    totp_secret: &str,
) -> Result<(HashMap<String, String>, String, String)> {
    log_account(
        "ACCOUNT",
        account_name,
        "starting browser for GitHub OAuth login",
    );

    // Unique user-data-dir: see get_waf_cookies_with_playwright for rationale.
    let browser_data_dir = std::env::temp_dir().join(format!(
        "anyrouter-login-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));
    let (mut browser, mut handler) = Browser::launch(
        BrowserConfig::builder()
            .user_data_dir(&browser_data_dir)
            .window_size(1920, 1080)
            .build()
            .map_err(|e| anyhow!("failed to build browser config: {}", e))?,
    )
    .await?;

    let handle = tokio::task::spawn(async move { while let Some(_) = handler.next().await {} });
    let page = browser.new_page("about:blank").await?;

    // Step 1: Load login page to pass WAF and collect WAF cookies
    log_account("ACCOUNT", account_name, "loading login page for WAF cookies");
    page.goto("https://anyrouter.top/login").await?;
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    let cookies = page.get_cookies().await?;
    let mut waf_cookies = HashMap::new();
    for cookie in &cookies {
        if ["acw_tc", "cdn_sec_tc", "acw_sc__v2"].contains(&cookie.name.as_str()) {
            waf_cookies.insert(cookie.name.clone(), cookie.value.clone());
        }
    }

    log_account(
        "ACCOUNT",
        account_name,
        format!("collected {} WAF cookies", waf_cookies.len()),
    );

    // Step 2: Get github_client_id from /api/status
    let status_result: String = page
        .evaluate(
            r#"(async function() {
                try {
                    var resp = await fetch('/api/status');
                    var data = await resp.json();
                    return data.data.github_client_id || '';
                } catch(e) { return 'ERROR:' + e.message; }
            })()"#,
        )
        .await?
        .into_value()?;

    if status_result.is_empty() || status_result.starts_with("ERROR:") {
        browser.close().await?;
        handle.abort();
        return Err(anyhow!(
            "failed to get github_client_id from /api/status: {}",
            status_result
        ));
    }
    let github_client_id = status_result;
    log_account(
        "ACCOUNT",
        account_name,
        format!("got github_client_id: {}", &github_client_id),
    );

    // Step 3: Call /api/oauth/state to generate CSRF state (sets session cookie)
    let state: String = page
        .evaluate(
            r#"(async function() {
                try {
                    var resp = await fetch('/api/oauth/state');
                    var data = await resp.json();
                    if (data.success) return data.data;
                    return 'ERROR:' + (data.message || 'unknown');
                } catch(e) { return 'ERROR:' + e.message; }
            })()"#,
        )
        .await?
        .into_value()?;

    if state.starts_with("ERROR:") {
        browser.close().await?;
        handle.abort();
        return Err(anyhow!("failed to get OAuth state: {}", state));
    }
    log_account(
        "ACCOUNT",
        account_name,
        format!("got OAuth state: {}", &state),
    );

    // Step 4: Navigate to GitHub OAuth authorization
    let github_oauth_url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&state={}&scope=user:email",
        github_client_id, state
    );
    page.goto(&github_oauth_url).await?;
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    let current_url: String = page
        .evaluate("window.location.href")
        .await?
        .into_value()?;

    // Step 5: Handle GitHub login
    if current_url.contains("github.com/login") {
        log_account(
            "ACCOUNT",
            account_name,
            "on GitHub login page, filling credentials",
        );

        page.find_element("#login_field")
            .await?
            .click()
            .await?
            .type_str(github_username)
            .await?;

        page.find_element("#password")
            .await?
            .click()
            .await?
            .type_str(github_password)
            .await?;

        page.find_element("input[name='commit']")
            .await?
            .click()
            .await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        let current_url: String = page
            .evaluate("window.location.href")
            .await?
            .into_value()?;

        // Step 6: Handle TOTP 2FA
        if current_url.contains("/sessions/two-factor") || current_url.contains("/2fa") {
            log_account(
                "ACCOUNT",
                account_name,
                "GitHub 2FA required, generating TOTP code",
            );

            let code = generate_totp(totp_secret)?;

            // GitHub's 2FA page defaults to passkey/WebAuthn — click through to TOTP input
            let switched_to_totp: bool = page
                .evaluate(
                    r#"(function() {
                        var links = document.querySelectorAll('a, button');
                        for (var i = 0; i < links.length; i++) {
                            var text = (links[i].textContent || '').toLowerCase();
                            if (text.indexOf('authenticator') !== -1 || text.indexOf('totp') !== -1 ||
                                text.indexOf('another way') !== -1 || text.indexOf('other method') !== -1 ||
                                text.indexOf('verification code') !== -1 || text.indexOf('use your') !== -1 ||
                                text.indexOf('authentication app') !== -1 || text.indexOf('另一种方式') !== -1) {
                                links[i].click();
                                return true;
                            }
                        }
                        return false;
                    })()"#,
                )
                .await?
                .into_value()?;

            if switched_to_totp {
                log_account(
                    "ACCOUNT",
                    account_name,
                    "switched from passkey to TOTP input",
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            }

            let totp_filled: bool = page
                .evaluate(format!(
                    r#"(function() {{
                        var selectors = ['#app_totp', '#totp', 'input[name="app_totp"]', 'input[name="totp"]',
                                         'input[autocomplete="one-time-code"]',
                                         'input[type="text"][inputmode="numeric"]',
                                         'input[type="number"]', 'input[inputmode="numeric"]',
                                         'input[type="text"]:not([name="authenticity_token"]):not([type="hidden"])'];
                        for (var i = 0; i < selectors.length; i++) {{
                            var el = document.querySelector(selectors[i]);
                            if (el) {{
                                el.focus();
                                el.value = '{}';
                                el.dispatchEvent(new Event('input', {{bubbles: true}}));
                                el.dispatchEvent(new Event('change', {{bubbles: true}}));
                                return true;
                            }}
                        }}
                        return false;
                    }})()"#,
                    code
                ))
                .await?
                .into_value()?;

            if !totp_filled {
                browser.close().await?;
                handle.abort();
                return Err(anyhow!(
                    "could not find TOTP input field on GitHub 2FA page"
                ));
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }

        // Step 7: Handle OAuth authorization prompt (first-time auth)
        let current_url: String = page
            .evaluate("window.location.href")
            .await?
            .into_value()?;

        if current_url.contains("/oauth/authorize") {
            log_account(
                "ACCOUNT",
                account_name,
                "authorizing OAuth app on GitHub",
            );

            if let Ok(btn) = page.find_element("#js-oauth-authorize-btn").await {
                btn.click().await?;
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    } else if current_url.contains("/oauth/authorize") {
        // Already logged in but needs authorization
        log_account(
            "ACCOUNT",
            account_name,
            "authorizing OAuth app on GitHub (already logged in)",
        );
        if let Ok(btn) = page.find_element("#js-oauth-authorize-btn").await {
            btn.click().await?;
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }

    // Step 8: Wait for redirect back to anyrouter.top
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    let final_url: String = page
        .evaluate("window.location.href")
        .await?
        .into_value()?;

    log_account(
        "ACCOUNT",
        account_name,
        format!("after GitHub auth, landed at: {}", &final_url),
    );

    if !final_url.contains("anyrouter.top") {
        browser.close().await?;
        handle.abort();
        return Err(anyhow!(
            "GitHub OAuth login did not redirect back to anyrouter.top (ended at: {})",
            final_url
        ));
    }

    // The React SPA handles the OAuth callback automatically:
    // /oauth/github?code=...&state=... → AJAX to /api/oauth/github → navigate to /console/token
    // By now the session cookie is already set and the user is logged in.

    // Extract user info from localStorage (set by the React app after successful login)
    let user_id: String = page
        .evaluate(
            r#"(function() {
                try {
                    var user = JSON.parse(localStorage.getItem('user') || '{}');
                    return (user.id || '').toString();
                } catch(e) { return ''; }
            })()"#,
        )
        .await?
        .into_value()?;

    if user_id.is_empty() {
        browser.close().await?;
        handle.abort();
        return Err(anyhow!(
            "OAuth login seemed to complete but no user data found in localStorage"
        ));
    }

    log_account(
        "ACCOUNT",
        account_name,
        format!("OAuth login returned user_id: {}", &user_id),
    );

    let final_cookies = page.get_cookies().await?;
    let session = final_cookies
        .iter()
        .find(|c| c.name == "session")
        .map(|c| c.value.clone())
        .ok_or_else(|| anyhow!("session cookie not found after OAuth login"))?;

    for cookie in &final_cookies {
        if ["acw_tc", "cdn_sec_tc", "acw_sc__v2"].contains(&cookie.name.as_str()) {
            waf_cookies.insert(cookie.name.clone(), cookie.value.clone());
        }
    }

    browser.close().await?;
    handle.abort();
    let _ = fs::remove_dir_all(&browser_data_dir);

    log_account(
        "SUCCESS",
        account_name,
        format!(
            "GitHub OAuth login successful, session obtained (len={})",
            session.len()
        ),
    );

    Ok((waf_cookies, session, user_id))
}

async fn update_accounts_in_cloudflare(accounts: &[AccountInfo]) -> Result<()> {
    let client = reqwest::Client::new();
    let auth_header = sha256_hex(&env::var("AUTH_VALUE")?);

    let accounts_json = serde_json::to_string(accounts)?;

    let resp = client
        .put("https://kv-tutorial.cazean.workers.dev/")
        .header("x-auth", auth_header)
        .header(header::CONTENT_TYPE, "application/json")
        .json(&json!({
            "key": "anyrouter-accounts",
            "value": accounts_json
        }))
        .send()
        .await?;

    match resp.status() {
        status if status.is_success() => Ok(()),
        status => {
            let body = resp.text().await.unwrap_or_default();
            Err(anyhow!(
                "failed to update Cloudflare KV: HTTP {} - {}",
                status,
                body
            ))
        }
    }
}

async fn check_in_account(
    account_info: &mut AccountInfo,
    account_index: usize,
) -> (bool, Option<UserInfo>, bool) {
    let account_name = get_account_display_name(account_info, account_index);
    println!();
    log_account("ACCOUNT", &account_name, "starting check-in");

    let api_user = account_info.api_user.clone();
    let mut session_updated = false;

    if api_user.trim().is_empty() {
        log_account(
            "ERROR",
            &account_name,
            "configuration error: API user identifier is missing or empty",
        );
        return (false, None, false);
    }

    if account_info.cookies.session.trim().is_empty() {
        if account_info.github_username.is_some()
            && account_info.github_password.is_some()
            && account_info.totp_secret.is_some()
        {
            log_account(
                "INFO",
                &account_name,
                "session cookie is empty, will attempt GitHub OAuth login",
            );
        } else {
            log_account(
                "ERROR",
                &account_name,
                "configuration error: session cookie is missing and no GitHub login credentials configured",
            );
            return (false, None, false);
        }
    }

    let waf_cookies = match get_waf_cookies_with_playwright(&account_name).await {
        Ok(cookies) => cookies,
        Err(e) => {
            log_account("ERROR", &account_name, e.to_string());
            return (false, None, false);
        }
    };

    let (mut client, mut headers) =
        match build_authenticated_client(&waf_cookies, &account_info.cookies.session, &api_user) {
            Ok(result) => result,
            Err(e) => {
                log_account("ERROR", &account_name, e.to_string());
                return (false, None, false);
            }
        };

    let mut user_info = get_user_info(&client, &headers).await;

    if !user_info.success && user_info.http_status == Some(401) {
        if let (Some(ref github_username), Some(ref github_password), Some(ref totp_secret)) = (
            account_info.github_username.clone(),
            account_info.github_password.clone(),
            account_info.totp_secret.clone(),
        ) {
            log_account(
                "ACCOUNT",
                &account_name,
                "session expired (HTTP 401), attempting GitHub OAuth login",
            );
            match login_via_github_browser(&account_name, github_username, github_password, totp_secret).await {
                Ok((new_waf_cookies, new_session, new_user_id)) => {
                    log_account(
                        "SUCCESS",
                        &account_name,
                        "GitHub OAuth login successful, session renewed",
                    );
                    account_info.cookies.session = new_session;
                    if !new_user_id.is_empty() {
                        account_info.api_user = new_user_id;
                    }
                    session_updated = true;

                    match build_authenticated_client(
                        &new_waf_cookies,
                        &account_info.cookies.session,
                        &account_info.api_user,
                    ) {
                        Ok((new_client, new_headers)) => {
                            client = new_client;
                            headers = new_headers;
                        }
                        Err(e) => {
                            log_account("ERROR", &account_name, e.to_string());
                            return (false, None, session_updated);
                        }
                    }

                    user_info = get_user_info(&client, &headers).await;
                }
                Err(e) => {
                    log_account(
                        "ERROR",
                        &account_name,
                        format!("GitHub OAuth login failed: {}", e),
                    );
                    return (false, None, false);
                }
            }
        } else {
            log_account(
                "WARN",
                &account_name,
                "session expired but no GitHub login credentials configured for auto-renewal",
            );
            return (false, Some(user_info), false);
        }
    }

    if user_info.success {
        log_account(
            "BALANCE",
            &account_name,
            format!("pre check-in - {}", user_info.display),
        );
    } else if let Some(ref error) = user_info.error {
        log_account(
            "WARN",
            &account_name,
            format!("unable to fetch account info before check-in: {}", error),
        );
    }

    log_account(
        "HTTP",
        &account_name,
        "sending POST /api/user/sign_in request",
    );

    let mut checkin_headers = headers.clone();
    checkin_headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    checkin_headers.insert("X-Requested-With", "XMLHttpRequest".parse().unwrap());

    match client
        .post("https://anyrouter.top/api/user/sign_in")
        .headers(checkin_headers)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
    {
        Ok(response) => {
            log_account(
                "HTTP",
                &account_name,
                format!(
                    "received response {} for POST /api/user/sign_in",
                    response.status()
                ),
            );

            if response.status().is_success() {
                match response.json::<Value>().await {
                    Ok(result) => {
                        let is_success = result.get("ret").and_then(|v| v.as_i64()) == Some(1)
                            || result.get("code").and_then(|v| v.as_i64()) == Some(0)
                            || result
                                .get("success")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);

                        if is_success {
                            log_account(
                                "SUCCESS",
                                &account_name,
                                "check-in completed successfully",
                            );

                            let post_user_info = get_user_info(&client, &headers).await;
                            if post_user_info.success {
                                log_account(
                                    "BALANCE",
                                    &account_name,
                                    format!("post check-in - {}", post_user_info.display),
                                );
                                user_info = post_user_info;
                            } else if let Some(ref error) = post_user_info.error {
                                log_account(
                                    "WARN",
                                    &account_name,
                                    format!(
                                        "unable to fetch account info after check-in: {}",
                                        error
                                    ),
                                );
                            }

                            (true, Some(user_info), session_updated)
                        } else {
                            let error_msg = result
                                .get("msg")
                                .or_else(|| result.get("message"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("Unknown error");
                            log_account(
                                "ERROR",
                                &account_name,
                                format!("check-in failed: {}", error_msg),
                            );
                            (false, Some(user_info), session_updated)
                        }
                    }
                    Err(_) => {
                        log_account(
                            "ERROR",
                            &account_name,
                            "check-in failed: invalid JSON response from server",
                        );
                        (false, Some(user_info), session_updated)
                    }
                }
            } else {
                log_account(
                    "ERROR",
                    &account_name,
                    format!("check-in failed: HTTP {}", response.status()),
                );
                (false, Some(user_info), session_updated)
            }
        }
        Err(e) => {
            log_account(
                "ERROR",
                &account_name,
                format!("check-in failed: network error {}", e),
            );
            (false, None, session_updated)
        }
    }
}

async fn get_account_from_cloudflare() -> Result<Vec<AccountInfo>> {
    let client = reqwest::Client::new();
    let auth_header = sha256_hex(&env::var("AUTH_VALUE")?);
    let resp = client
        .get("https://kv-tutorial.cazean.workers.dev/")
        .query(&[("key", "anyrouter-accounts")])
        .header("x-auth", auth_header)
        .send()
        .await?;
    match resp.status() {
        reqwest::StatusCode::OK => {
            let accounts: Vec<AccountInfo> = resp.json().await?;
            Ok(accounts)
        }
        reqwest::StatusCode::NOT_FOUND => Ok(vec![]),
        status => {
            let body = resp.text().await.unwrap_or_default();
            Err(anyhow!("unexpected status {status}: {body}"))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();

    log_line(
        "SYSTEM",
        "AnyRouter.top multi-account auto check-in script started (using Playwright)",
    );
    log_line(
        "TIME",
        format!(
            "Execution time: {}",
            Local::now().format("%Y-%m-%d %H:%M:%S")
        ),
    );

    let mut accounts: Vec<AccountInfo> = get_account_from_cloudflare().await?;
    log_line(
        "INFO",
        format!("Found {} account configurations", accounts.len()),
    );

    let last_balance_hash = load_balance_hash();

    let mut success_count = 0;
    let total_count = accounts.len();
    let mut notification_content = Vec::new();
    let mut current_balances: HashMap<String, BalanceInfo> = HashMap::new();
    let mut need_notify = false;
    let mut balance_changed = false;
    let mut any_session_updated = false;

    for (i, account) in accounts.iter_mut().enumerate() {
        let account_key = format!("account_{}", i + 1);

        let (success, user_info, session_updated) = check_in_account(account, i).await;

        if session_updated {
            any_session_updated = true;
        }

        if success {
            success_count += 1;
        }

        let mut should_notify_this_account = false;

        if !success {
            should_notify_this_account = true;
            need_notify = true;
            let account_name = get_account_display_name(account, i);
            log_account(
                "NOTIFY",
                &account_name,
                "check-in failed, will include in notification",
            );
        }

        if let Some(ref info) = user_info {
            if info.success {
                current_balances.insert(
                    account_key.clone(),
                    BalanceInfo {
                        quota: info.quota,
                        used: info.used_quota,
                    },
                );
            }
        }

        if should_notify_this_account {
            let account_name = get_account_display_name(account, i);
            let status = if success {
                "CHECK-IN OK"
            } else {
                "CHECK-IN FAILED"
            };

            let detail = if let Some(ref info) = user_info {
                if info.success {
                    info.display.clone()
                } else if let Some(ref error) = info.error {
                    error.clone()
                } else {
                    "no additional error details available".to_string()
                }
            } else {
                "no user information available".to_string()
            };

            let account_result = format!(
                "[RESULT] account {} - {} ({})",
                account_name, status, detail
            );

            notification_content.push(account_result);
        }
    }

    if any_session_updated {
        match update_accounts_in_cloudflare(&accounts).await {
            Ok(_) => log_line("SUCCESS", "renewed session cookies persisted to Cloudflare KV"),
            Err(e) => log_line(
                "ERROR",
                format!("failed to persist renewed sessions to Cloudflare KV: {}", e),
            ),
        }
    }

    let current_balance_hash = if !current_balances.is_empty() {
        Some(generate_balance_hash(&current_balances))
    } else {
        None
    };

    if let Some(ref hash) = current_balance_hash {
        if last_balance_hash.is_none() {
            balance_changed = true;
            need_notify = true;
            log_line(
                "NOTIFY",
                "First run detected; will send notification with current balances",
            );
        } else if last_balance_hash.as_ref() != Some(hash) {
            balance_changed = true;
            need_notify = true;
            log_line(
                "NOTIFY",
                "Detected balance changes since last run; will send notification",
            );
        } else {
            log_line("INFO", "No balance changes detected since last run");
        }
    }

    if balance_changed {
        for (i, account) in accounts.iter().enumerate() {
            let account_key = format!("account_{}", i + 1);
            if let Some(balance) = current_balances.get(&account_key) {
                let account_name = get_account_display_name(account, i);
                let account_result = format!(
                    "[BALANCE] account {} - current balance ${:.2}, used ${:.2}",
                    account_name, balance.quota, balance.used
                );

                if !notification_content
                    .iter()
                    .any(|item| item.contains(&account_name))
                {
                    notification_content.push(account_result);
                }
            }
        }
    }

    if let Some(ref hash) = current_balance_hash {
        save_balance_hash(hash)?;
    }

    if need_notify && !notification_content.is_empty() {
        let mut summary = vec![
            "[STATS] Check-in result summary:".to_string(),
            format!(
                "[STATS] Successful accounts: {}/{}",
                success_count, total_count
            ),
            format!(
                "[STATS] Failed accounts: {}/{}",
                total_count - success_count,
                total_count
            ),
        ];

        if success_count == total_count {
            summary.push("[STATS] Overall status: ALL SUCCESS".to_string());
        } else if success_count > 0 {
            summary.push("[STATS] Overall status: PARTIAL SUCCESS".to_string());
        } else {
            summary.push("[STATS] Overall status: ALL FAILED".to_string());
        }

        let time_info = format!(
            "Execution time: {}",
            Local::now().format("%Y-%m-%d %H:%M:%S")
        );

        let notify_content = format!(
            "{}\n\n{}\n\n{}",
            time_info,
            notification_content.join("\n\n"),
            summary.join("\n")
        );

        println!("{}", notify_content);

        let notifier = NotificationKit::new();
        notifier
            .push_message("AnyRouter Check-in Alert", &notify_content)
            .await;

        log_line(
            "NOTIFY",
            "Notification sent due to failures or balance changes",
        );
    } else {
        log_line(
            "INFO",
            "All accounts successful and no balance changes detected, notification skipped",
        );
    }

    process::exit(if success_count == total_count { 0 } else { 1 });
}
