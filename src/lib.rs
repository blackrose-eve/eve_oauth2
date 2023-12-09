pub mod models;

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{DecodingKey, TokenData, Validation};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};

use models::{EveJwtClaims, EveJwtKey, EveJwtKeys, EveSsoMetaData};

/// Generates an authentication URL for EVE Online SSO which you redirect your user to for login.
///
/// Takes client_id & client_secret variables which you get from your EVE developer application (https://developers.eveonline.com/).
/// redirect_url specifies where your callback is to handle the authorization code, this must match the one in your developer appliacation!
/// scopes is a vec of scopes which represent the permissions you need from that character such as reading assets or wallet data, these must match the ones in your developer application!
pub fn handle_eve_authentication(
    client_id: String,
    client_secret: String,
    redirect_url: String,
    scopes: Vec<Scope>,
) -> String {
    let client = BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new("https://login.eveonline.com/v2/oauth/authorize/".to_string())
            .expect("Failed to create new authorization url"),
        Some(
            TokenUrl::new("https://login.eveonline.com/v2/oauth/token".to_string())
                .expect("Failed to create new EVE oauth token URL"),
        ),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).expect("Failed to set redirect_uri"));

    let (eve_oauth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(scopes)
        .url();

    eve_oauth_url.to_string()
}

/// Handles redirect from EVE Online SSO
///
/// Takes client_id & client_secret variables which you get from your EVE developer application (https://developers.eveonline.com/).
/// Redirect code is pulled from the GET request URL when the user is redirected to your redirect route
///
/// Returns the token_data with data that can be accessed by calling token_data.claims, you can get a user's name through token_data.claims.name
pub async fn handle_eve_redirect(
    client_id: String,
    client_secret: String,
    redirect_code: String,
) -> TokenData<EveJwtClaims> {
    let client = BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new("https://login.eveonline.com/v2/oauth/authorize/".to_string())
            .expect("Failed to create new authorization url"),
        Some(
            TokenUrl::new("https://login.eveonline.com/v2/oauth/token".to_string())
                .expect("Failed to create new EVE oauth token URL"),
        ),
    );

    let token = client
        .exchange_code(AuthorizationCode::new(redirect_code.to_string()))
        .request_async(async_http_client)
        .await
        .expect("Failed to get token using redirect_code");

    validate_token(token.access_token().secret().to_string()).await
}

async fn validate_token(token: String) -> TokenData<EveJwtClaims> {
    let sso_meta_data_url = "https://login.eveonline.com/.well-known/oauth-authorization-server";

    let res: EveSsoMetaData = reqwest::Client::new()
        .get(sso_meta_data_url)
        .send()
        .await
        .expect("Failed to get EveSsoMetaData")
        .json()
        .await
        .expect("Failed to deserialize EveSsoMetaData");

    let res: EveJwtKeys = reqwest::Client::new()
        .get(res.jwks_uri)
        .send()
        .await
        .expect("Failed to get EveJwtKeys")
        .json()
        .await
        .expect("Failed to deserialize EveJwtKeys");

    let jwk_key = select_key(res.keys).expect("Failed to find RS256 EveJwtKey");

    let jwk_n: String;
    let jwk_e: String;

    if let EveJwtKey::RS256 {
        e,
        kid: _,
        kty: _,
        n,
        r#use: _,
    } = jwk_key
    {
        jwk_n = n;
        jwk_e = e;
    } else {
        panic!("Failed to get JWT key values!")
    }

    match jsonwebtoken::decode::<EveJwtClaims>(
        &token,
        &DecodingKey::from_rsa_components(&jwk_n, &jwk_e)
            .expect("Failed to generate decoding key from EveJwtKey"),
        &Validation::new(jsonwebtoken::Algorithm::RS256),
    ) {
        Ok(c) => c,
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => panic!("Token is invalid"),
            ErrorKind::InvalidIssuer => panic!("Issuer is invalid"),
            _ => panic!("Unknown token error"),
        },
    }
}

fn select_key(keys: Vec<EveJwtKey>) -> Option<EveJwtKey> {
    for key in keys {
        if let EveJwtKey::RS256 {
            e: _,
            kid: _,
            kty: _,
            n: _,
            r#use: _,
        } = &key
        {
            return Some(key);
        }
    }

    None
}
