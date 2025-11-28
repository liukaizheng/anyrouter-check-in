use anyhow::{anyhow, Result};
use reqwest::Client;
use serde_json::json;
use std::env;

pub struct NotificationKit {
    email_user: String,
    email_pass: String,
    email_to: String,
    smtp_server: String,
    pushplus_token: Option<String>,
    server_push_key: Option<String>,
    dingding_webhook: Option<String>,
    feishu_webhook: Option<String>,
    weixin_webhook: Option<String>,
}

impl NotificationKit {
    pub fn new() -> Self {
        Self {
            email_user: env::var("EMAIL_USER").unwrap_or_default(),
            email_pass: env::var("EMAIL_PASS").unwrap_or_default(),
            email_to: env::var("EMAIL_TO").unwrap_or_default(),
            smtp_server: env::var("CUSTOM_SMTP_SERVER").unwrap_or_default(),
            pushplus_token: env::var("PUSHPLUS_TOKEN").ok(),
            server_push_key: env::var("SERVERPUSHKEY").ok(),
            dingding_webhook: env::var("DINGDING_WEBHOOK").ok(),
            feishu_webhook: env::var("FEISHU_WEBHOOK").ok(),
            weixin_webhook: env::var("WEIXIN_WEBHOOK").ok(),
        }
    }

    pub async fn send_email(&self, title: &str, content: &str) -> Result<()> {
        if self.email_user.is_empty() || self.email_pass.is_empty() || self.email_to.is_empty() {
            return Err(anyhow!("Email configuration not set"));
        }

        use lettre::message::header::ContentType;
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::{Message, SmtpTransport, Transport};

        let smtp_server = if !self.smtp_server.is_empty() {
            self.smtp_server.clone()
        } else {
            format!("smtp.{}", self.email_user.split('@').nth(1).unwrap_or(""))
        };

        let email = Message::builder()
            .from(format!("AnyRouter Assistant <{}>", self.email_user).parse()?)
            .to(self.email_to.parse()?)
            .subject(title)
            .header(ContentType::TEXT_PLAIN)
            .body(content.to_string())?;

        let creds = Credentials::new(self.email_user.clone(), self.email_pass.clone());
        let mailer = SmtpTransport::relay(&smtp_server)?
            .credentials(creds)
            .build();

        mailer.send(&email)?;
        Ok(())
    }

    pub async fn send_pushplus(&self, title: &str, content: &str) -> Result<()> {
        let token = self
            .pushplus_token
            .as_ref()
            .ok_or_else(|| anyhow!("PushPlus Token not configured"))?;

        let client = Client::new();
        let data = json!({
            "token": token,
            "title": title,
            "content": content,
            "template": "html"
        });

        client
            .post("http://www.pushplus.plus/send")
            .json(&data)
            .send()
            .await?;

        Ok(())
    }

    pub async fn send_server_push(&self, title: &str, content: &str) -> Result<()> {
        let key = self
            .server_push_key
            .as_ref()
            .ok_or_else(|| anyhow!("Server Push key not configured"))?;

        let client = Client::new();
        let data = json!({
            "title": title,
            "desp": content
        });

        client
            .post(&format!("https://sctapi.ftqq.com/{}.send", key))
            .json(&data)
            .send()
            .await?;

        Ok(())
    }

    pub async fn send_dingtalk(&self, title: &str, content: &str) -> Result<()> {
        let webhook = self
            .dingding_webhook
            .as_ref()
            .ok_or_else(|| anyhow!("DingTalk Webhook not configured"))?;

        let client = Client::new();
        let data = json!({
            "msgtype": "text",
            "text": {
                "content": format!("{}\n{}", title, content)
            }
        });

        client.post(webhook).json(&data).send().await?;
        Ok(())
    }

    pub async fn send_feishu(&self, title: &str, content: &str) -> Result<()> {
        let webhook = self
            .feishu_webhook
            .as_ref()
            .ok_or_else(|| anyhow!("Feishu Webhook not configured"))?;

        let client = Client::new();
        let data = json!({
            "msg_type": "interactive",
            "card": {
                "elements": [{
                    "tag": "markdown",
                    "content": content,
                    "text_align": "left"
                }],
                "header": {
                    "template": "blue",
                    "title": {
                        "content": title,
                        "tag": "plain_text"
                    }
                }
            }
        });

        client.post(webhook).json(&data).send().await?;
        Ok(())
    }

    pub async fn send_wecom(&self, title: &str, content: &str) -> Result<()> {
        let webhook = self
            .weixin_webhook
            .as_ref()
            .ok_or_else(|| anyhow!("WeChat Work Webhook not configured"))?;

        let client = Client::new();
        let data = json!({
            "msgtype": "text",
            "text": {
                "content": format!("{}\n{}", title, content)
            }
        });

        client.post(webhook).json(&data).send().await?;
        Ok(())
    }

    pub async fn push_message(&self, title: &str, content: &str) {
        // Email
        match self.send_email(title, content).await {
            Ok(_) => println!("[Email]: Message push successful!"),
            Err(e) => println!("[Email]: Message push failed! Reason: {}", e),
        }

        // PushPlus
        match self.send_pushplus(title, content).await {
            Ok(_) => println!("[PushPlus]: Message push successful!"),
            Err(e) => println!("[PushPlus]: Message push failed! Reason: {}", e),
        }

        // Server Push
        match self.send_server_push(title, content).await {
            Ok(_) => println!("[Server Push]: Message push successful!"),
            Err(e) => println!("[Server Push]: Message push failed! Reason: {}", e),
        }

        // DingTalk
        match self.send_dingtalk(title, content).await {
            Ok(_) => println!("[DingTalk]: Message push successful!"),
            Err(e) => println!("[DingTalk]: Message push failed! Reason: {}", e),
        }

        // Feishu
        match self.send_feishu(title, content).await {
            Ok(_) => println!("[Feishu]: Message push successful!"),
            Err(e) => println!("[Feishu]: Message push failed! Reason: {}", e),
        }

        // WeChat Work
        match self.send_wecom(title, content).await {
            Ok(_) => println!("[WeChat Work]: Message push successful!"),
            Err(e) => println!("[WeChat Work]: Message push failed! Reason: {}", e),
        }
    }
}