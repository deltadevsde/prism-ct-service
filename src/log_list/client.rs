use super::error::LogListError;
use super::types::LogList;
use reqwest::Client;

const GOOGLE_ALL_LOGLIST_URL: &str = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json";

pub struct LogListClient {
    client: Client,
    url: String,
}

impl LogListClient {
    pub fn new(url: String) -> Self {
        Self {
            client: Client::new(),
            url,
        }
    }

    pub fn new_google() -> Self {
        Self::new(GOOGLE_ALL_LOGLIST_URL.to_string())
    }

    pub async fn fetch_log_list(&self) -> Result<LogList, LogListError> {
        self.fetch_from_url(&self.url).await
    }

    pub async fn fetch_from_url(&self, url: &str) -> Result<LogList, LogListError> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(LogListError::NetworkError)?;

        let text = response.text().await.map_err(LogListError::NetworkError)?;
        println!("REST call to {}", url);
        serde_json::from_str(&text).map_err(|e| LogListError::ParseError(e.to_string()))
    }
}
