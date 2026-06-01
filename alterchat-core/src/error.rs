use thiserror::Error;

#[derive(Error, Debug)]
pub enum AlterChatError {
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Database error: {0}")]
    Database(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, AlterChatError>;
