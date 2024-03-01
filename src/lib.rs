pub mod models;

use cached::proc_macro::cached;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{DecodingKey, TokenData, Validation};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    RedirectUrl, Scope, StandardTokenResponse, TokenUrl,
};

use models::{EveJwtClaims, EveJwtKey, EveJwtKeys, EveSsoMetaData};

pub struct AuthenticationData {
    pub login_url: String,
    pub state: String,
}

/// Generates a state verification string & authentication URL for EVE Online SSO which you use to redirect your user to EVE's login.
/// More details on the usage of the state string here: https://auth0.com/docs/secure/attack-protection/state-parameters
///
/// Takes client_id & client_secret variables which you get from your EVE developer application (https://developers.eveonline.com/).
/// redirect_url specifies where your callback is to handle the authorization code, this must match the one in your developer appliacation!
/// scopes is a vec of scopes which represent the permissions you need from that character such as reading assets or wallet data, these must match the ones in your developer application!
pub fn create_login_url(
    client_id: String,
    client_secret: String,
    redirect_url: String,
    scopes: Vec<String>,
) -> AuthenticationData {
    fn convert_scopes(scopes: Vec<String>) -> Vec<Scope> {
        scopes.iter().map(|s| Scope::new(s.clone())).collect()
    }

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

    let scopes = convert_scopes(scopes);

    let (eve_oauth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(scopes)
        .url();

    AuthenticationData {
        login_url: eve_oauth_url.to_string(),
        state: csrf_token.secret().to_string(),
    }
}

/// Handles callback from EVE Online SSO
///
/// Takes client_id & client_secret variables which you get from your EVE developer application (https://developers.eveonline.com/).
///
/// Redirect code is pulled from the GET request URL when the user is redirected to your callback route
///
/// Returns the token which you can you retrieve the claims from using validate_token
/// ```
/// let token_claims = validate_token(token.access_token().secret().to_string()).await;
/// ```
pub async fn get_access_token(
    client_id: String,
    client_secret: String,
    code: String,
) -> StandardTokenResponse<EmptyExtraTokenFields, oauth2::basic::BasicTokenType> {
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

    client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request_async(async_http_client)
        .await
        .expect("Failed to get token using redirect_code")
}

/// Validates a token which can be retrieved using `get_access_token`
///
/// On successful validation it will return the EVE JWT claims
pub async fn validate_token(token: String) -> TokenData<EveJwtClaims> {
    #[cached(time = 10800)]
    async fn get_eve_jwt_keys() -> EveJwtKeys {
        let sso_meta_data_url =
            "https://login.eveonline.com/.well-known/oauth-authorization-server";

        let res: EveSsoMetaData = reqwest::Client::new()
            .get(sso_meta_data_url)
            .send()
            .await
            .expect("Failed to get EveSsoMetaData")
            .json()
            .await
            .expect("Failed to deserialize EveSsoMetaData");

        reqwest::Client::new()
            .get(res.jwks_uri)
            .send()
            .await
            .expect("Failed to get EveJwtKeys")
            .json()
            .await
            .expect("Failed to deserialize EveJwtKeys")
    }

    let jwk_key =
        select_key(get_eve_jwt_keys().await.keys).expect("Failed to find RS256 EveJwtKey");

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

    let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&["EVE Online"]);
    validation.set_issuer(&["https://login.eveonline.com"]);

    match jsonwebtoken::decode::<EveJwtClaims>(
        &token,
        &DecodingKey::from_rsa_components(&jwk_n, &jwk_e)
            .expect("Failed to generate decoding key from EveJwtKey"),
        &validation,
    ) {
        Ok(c) => c,
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => panic!("Token is invalid"),
            ErrorKind::InvalidIssuer => panic!("Issuer is invalid"),
            _ => panic!("Unknown token error: {:?}", err),
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
