# Rust EVE OAuth2

[Black Rose](https://black-rose.space)'s implementation of an OAuth2 method for authenticating with EVE Online's SSO for use with your preferred Rust web framework.

## Initial Setup

1. You will first need to create an application at <https://developers.eveonline.com/>.
2. Set your callback URL in your application to the same one you will use in your application else you will encounter errors.
    - localhost:8000/callback
3. Select the scopes your application intends on using, add more later if needed.
4. Create a .env file with your client id & client secret that you will use in your login & callback API routes.

## Implementation

You will need the following API routes:

1. Login GET route to send the user to CCP's login page (`localhost:8000/login`)
    - Call the `create_login_url` function to get the login link for the page 
    - Store the state code returned from `create_login_url` in a session
2. Redirect GET route with code & state paramters (`localhost:8000/callback?code=...&state=...`)
    - Validate state from session with the state code from the calback for [additional security](https://auth0.com/docs/secure/attack-protection/state-parameters
)
    - Call the `get_access_token` function which uses the application client id & client secret & the code returned in the redirect to retrieve an access token
    - Call the `validate_access_token` function to validate the token & to access the data within the token you can use in your application to verify the user

See the [axum](https://github.com/blackrose-eve/eve_oauth2/tree/main/examples/axum.rs) example to see the implementation above in action.

To test out the axum example:
    1. Copy .env.example to .env and fill out the variables which you can get from https://developers.eveonline.com/
    2. Run `cargo run --example axum`
    3. Login at `http://localhost:8000/login`
    4. On successful login you'll see your character id & name
