use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use eve_oauth2::{create_login_url, get_access_token, validate_token};
use oauth2::TokenResponse;
use serde::{Deserialize, Serialize};
use std::env;
use time::Duration;
use tower_sessions::{cookie::SameSite, Expiry, MemoryStore, Session, SessionManagerLayer};

const STATE_KEY: &str = "state";

#[derive(Deserialize)]
struct CallbackParams {
    state: String,
    code: String,
}

#[derive(Serialize)]
struct Character {
    character_id: i32,
    character_name: String,
}

#[derive(Default, Deserialize, Serialize, Debug)]
struct State(String);

#[tokio::main]
async fn main() {
    let _ = dotenv::dotenv();

    let application_domain = env::var("APPLICATION_DOMAIN")
        .expect("APPLICATION_DOMAIN not set, please set it in your .env!");

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(Duration::seconds(120)));

    let app = Router::new()
        .route("/login", get(login))
        .route("/callback", get(callback))
        .layer(session_layer);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8000")
        .await
        .unwrap();

    println!("Login with http://{}/login", application_domain);
    axum::serve(listener, app).await.unwrap();
}

async fn login(session: Session) -> Redirect {
    let application_domain = env::var("APPLICATION_DOMAIN")
        .expect("APPLICATION_DOMAIN not set, please set it in your .env!");
    let client_id =
        env::var("ESI_CLIENT_ID").expect("ESI_CLIENT_SECRET not set, please set it in your .env!");
    let client_secret = env::var("ESI_CLIENT_SECRET")
        .expect("ESI_CLIENT_SECRET not set, please set it in your .env!");

    let redirect_url = format!("http://{}/callback", application_domain);
    let scopes = vec!["publicData".to_string()];

    let auth_data = create_login_url(client_id, client_secret, redirect_url, scopes);

    session
        .insert(STATE_KEY, State(auth_data.state))
        .await
        .unwrap();

    Redirect::temporary(&auth_data.login_url)
}

async fn callback(session: Session, params: Query<CallbackParams>) -> Response {
    let state: State = session.get(STATE_KEY).await.unwrap().unwrap_or_default();

    if state.0 != params.0.state {
        return (
            StatusCode::BAD_REQUEST,
            "There was an issue logging you in, please try again.",
        )
            .into_response();
    }

    let client_id =
        env::var("ESI_CLIENT_ID").expect("ESI_CLIENT_SECRET not set, please set it in your .env!");
    let client_secret = env::var("ESI_CLIENT_SECRET")
        .expect("ESI_CLIENT_SECRET not set, please set it in your .env!");

    let token = get_access_token(client_id, client_secret, params.0.code).await;
    let token_claims = validate_token(token.access_token().secret().to_string()).await;

    let id_str = token_claims.claims.sub.split(':').collect::<Vec<&str>>()[2];

    let character_id: i32 = id_str.parse().expect("Failed to parse id to i32");
    let character_name: String = token_claims.claims.name;

    let character = Character {
        character_id,
        character_name,
    };

    (StatusCode::OK, Json(character)).into_response()
}
