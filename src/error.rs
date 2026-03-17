use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),

    #[error("JSON deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Template rendering error: {0}")]
    Template(#[from] askama::Error),

    #[error("{0}")]
    NotFound(String),
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate {
    status: StatusCode,
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal error: {self}"),
            ),
        };

        tracing::error!(%status, %message, "request error");

        let html = ErrorTemplate { status, message }
            .render()
            .unwrap_or_else(|_| "Internal server error".to_string());

        (status, Html(html)).into_response()
    }
}
