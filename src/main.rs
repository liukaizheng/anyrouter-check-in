mod notify;

use anyhow::{anyhow, Result};
use chromiumoxide::browser::{Browser, BrowserConfig};
use chrono::Local;
use colored::Colorize;
use futures::StreamExt;
use notify::NotificationKit;
use reqwest::{cookie::Jar, header, Client};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::process;
use std::sync::Arc;

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

#[derive(Debug, Deserialize, Serialize)]
struct AccountInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    cookies: SessionCookies,
    api_user: String,
}

#[derive(Debug, Deserialize, Serialize)]
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

    let (mut browser, mut handler) = Browser::launch(
        BrowserConfig::builder()
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
            if status.is_success() {
                if let Ok(data) = response.json::<Value>().await {
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
                        };
                    }
                }
            }

            UserInfo {
                success: false,
                quota: 0.0,
                used_quota: 0.0,
                display: String::new(),
                error: Some(format!("user profile request failed: HTTP {}", status)),
            }
        }
        Err(e) => UserInfo {
            success: false,
            quota: 0.0,
            used_quota: 0.0,
            display: String::new(),
            error: Some(format!("user profile request failed: {}", e)),
        },
    }
}

async fn check_in_account(
    account_info: &AccountInfo,
    account_index: usize,
) -> (bool, Option<UserInfo>) {
    let account_name = get_account_display_name(account_info, account_index);
    println!();
    log_account("ACCOUNT", &account_name, "starting check-in");

    let api_user = &account_info.api_user;

    if api_user.trim().is_empty() {
        log_account(
            "ERROR",
            &account_name,
            "configuration error: API user identifier is missing or empty",
        );
        return (false, None);
    }

    let mut user_cookies = HashMap::new();
    user_cookies.insert("session".to_owned(), account_info.cookies.session.clone());
    if account_info.cookies.session.trim().is_empty() {
        log_account(
            "ERROR",
            &account_name,
            "configuration error: session cookie is missing or empty",
        );
        return (false, None);
    }

    let waf_cookies = match get_waf_cookies_with_playwright(&account_name).await {
        Ok(cookies) => cookies,
        Err(e) => {
            log_account("ERROR", &account_name, e.to_string());
            return (false, None);
        }
    };

    let jar = Arc::new(Jar::default());

    for (key, value) in waf_cookies.iter().chain(user_cookies.iter()) {
        jar.add_cookie_str(
            &format!("{}={}", key, value),
            &"https://anyrouter.top".parse().unwrap(),
        );
    }

    let client = match Client::builder().cookie_provider(jar).build() {
        Ok(client) => client,
        Err(e) => {
            log_account(
                "ERROR",
                &account_name,
                format!("failed to create HTTP client: {}", e),
            );
            return (false, None);
        }
    };

    let mut headers = header::HeaderMap::new();
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

    // Fetch account info before check-in (may fail; non-fatal)
    let mut user_info = get_user_info(&client, &headers).await;
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

                            // Attempt to refresh account info after a successful check-in
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

                            (true, Some(user_info))
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
                            (false, Some(user_info))
                        }
                    }
                    Err(_) => {
                        log_account(
                            "ERROR",
                            &account_name,
                            "check-in failed: invalid JSON response from server",
                        );
                        (false, Some(user_info))
                    }
                }
            } else {
                log_account(
                    "ERROR",
                    &account_name,
                    format!("check-in failed: HTTP {}", response.status()),
                );
                (false, Some(user_info))
            }
        }
        Err(e) => {
            log_account(
                "ERROR",
                &account_name,
                format!("check-in failed: network error {}", e),
            );
            (false, None)
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

    let accounts = get_account_from_cloudflare().await?;
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

    for (i, account) in accounts.iter().enumerate() {
        let account_key = format!("account_{}", i + 1);

        let (success, user_info) = check_in_account(account, i).await;

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
