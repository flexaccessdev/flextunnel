//! Error types for the proxy.

use std::error::Error as StdError;
use thiserror::Error;

/// Boxed error type used for error chaining across crate boundaries.
pub type BoxError = Box<dyn StdError + Send + Sync + 'static>;

/// Context wrapper that preserves an optional underlying source error.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct ErrorContext {
    message: String,
    #[source]
    source: Option<BoxError>,
}

impl ErrorContext {
    /// Create context error with an underlying source.
    pub fn with_source<E>(message: impl Into<String>, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

/// Proxy-specific errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProxyError {
    /// Network I/O error.
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(#[source] ErrorContext),

    /// Signaling/iroh error (transient, e.g., connection failed).
    #[error("Signaling error: {0}")]
    Signaling(String),

    /// Authentication failed (permanent, e.g., invalid token, server rejected).
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Connection lost during the session.
    #[error("Connection lost: {0}")]
    ConnectionLost(String),
}

impl ProxyError {
    /// Create a configuration error with preserved source.
    pub fn config_with_source<E>(message: impl Into<String>, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::Config(ErrorContext::with_source(message, source))
    }
}

/// Result type alias for proxy operations.
pub type ProxyResult<T> = Result<T, ProxyError>;
