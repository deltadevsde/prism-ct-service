use std::fmt::Display;

use reqwest::Error as ReqwestError;

#[derive(Debug)]
pub enum LogListError {
    NetworkError(ReqwestError),
    ParseError(String),
}

impl Display for LogListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogListError::NetworkError(e) => write!(f, "Network error: {}", e),
            LogListError::ParseError(e) => write!(f, "Parse error: {}", e),
        }
    }
}
