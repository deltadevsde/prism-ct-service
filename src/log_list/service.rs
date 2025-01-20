use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use super::{client::LogListClient, error::LogListError, types::Log};

const DEFAULT_CACHE_DURATION: Duration = Duration::from_secs(60 * 60 * 24); // 1 days

struct CachedLogs {
    logs: Vec<Log>,
    logs_by_id: HashMap<String, usize>,
    logs_by_operator: HashMap<String, Vec<usize>>,
    last_updated: SystemTime,
}

impl Default for CachedLogs {
    fn default() -> Self {
        Self {
            logs: Vec::new(),
            logs_by_id: HashMap::new(),
            logs_by_operator: HashMap::new(),
            last_updated: SystemTime::UNIX_EPOCH,
        }
    }
}

pub struct CachingLogListService {
    client: LogListClient,
    cache: Arc<Mutex<CachedLogs>>,
    cache_duration: Duration,
}

impl CachingLogListService {
    pub fn new(cache_duration: Duration) -> Self {
        Self {
            client: LogListClient::new_google(),
            cache: Arc::new(Mutex::new(CachedLogs::default())),
            cache_duration,
        }
    }

    pub async fn get_by_id(&self, id: &str) -> Result<Log, LogListError> {
        self.check_and_refresh_cache().await?;
        let cache = self.cache.lock().unwrap();
        match cache.logs_by_id.get(id) {
            Some(&index) => Ok(cache.logs[index].clone()),
            None => Err(LogListError::ParseError("Log not found".to_string())),
        }
    }

    pub async fn get_all_by_operator(&self, operator: &str) -> Result<Vec<Log>, LogListError> {
        self.check_and_refresh_cache().await?;
        let cache = self.cache.lock().unwrap();
        Ok(cache
            .logs_by_operator
            .get(operator)
            .map(|indices| indices.iter().map(|&i| cache.logs[i].clone()).collect())
            .unwrap_or_default())
    }

    async fn check_and_refresh_cache(&self) -> Result<(), LogListError> {
        let now = SystemTime::now();
        {
            let cache = self.cache.lock().unwrap();
            let fresh = now
                .duration_since(cache.last_updated)
                .map(|duration| duration < self.cache_duration)
                .unwrap_or(false);
            drop(cache);

            if fresh {
                return Ok(());
            }
        }

        let new_log_list = self.client.fetch_log_list().await?;
        let mut logs = Vec::new();
        let mut logs_by_operator = HashMap::new();
        let mut logs_by_id = HashMap::new();

        for operator in &new_log_list.operators {
            let mut operator_indices = Vec::new();

            for log in &operator.logs {
                // Unusable logs are not included here
                if !log.is_usable() {
                    continue;
                }

                let index = logs.len();
                logs.push(log.clone());
                logs_by_id.insert(log.log_id.clone(), index);
                operator_indices.push(index);
            }

            logs_by_operator.insert(operator.name.clone(), operator_indices);
        }

        let mut cache = self.cache.lock().unwrap();
        cache.logs = logs;
        cache.logs_by_id = logs_by_id;
        cache.logs_by_operator = logs_by_operator;
        cache.last_updated = now;
        Ok(())
    }
}

impl Default for CachingLogListService {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_DURATION)
    }
}
