# Rust EVE OAuth2

OAuth2 method for authenticating with EVE Online's SSO using your preferred Rust web framework.

## Initial Setup

1. You will first need to create an application at <https://developers.eveonline.com/>.
2. Set your redirect URL in your application to the same one you will use in your application else you will encounter errors.
    - localhost:8000/redirect
    - auth.black-rose.space/redirect
3. Select the scopes your application intends on using, add more later if needed.
4. Create a .env file with your client id & client secret that you will use in your login & redirect API routes.

## Implementation

You will need the following API routes

1. Login GET route to send the user to CCP's login page
2. Redirect GET route with code & state paramters (localhost:8000/api/redirect?code=...&state=...)

See examples directory for working examples in actix & rocket.

## How it works

### User End (Simple Explanation)

1. User goes to your webpage (localhost:3000/login) & clicks the login button which takes them to your api (localhost:8000/api/login).
2. The API login route then redirects them to EVE Online using a URL generated with your `clientId` & `clientSecret` to identify your application.
3. The user then is asked to login through EVE & then they are told which scopes your website is requesting, these are permissions that allow your website to access data such as wallet information & assets.
4. Once the user logs in they are then redirected to a "callback" route (localhost:8000/api/login/redirect) which verifies who they are using an authorization code in the redirect link.
5. The user is then redirected to your website if the validation is successful.

### Your Program (Detailed Explanation)

1. User goes to your login route & is redirected to EVE Online using a link generated with your `cientId` & `clientSecret` as well as the scopes you set.
2. After login they are redirected to your callback route with an authorization code which is used to then request the user's token.
3. The user's token is then validated by fetching the public keys for validating an RS256 encoded JWT.
4. The JWT is then decoded using the public keys and then verifying the issuer.
5. The token data is then returned to your redirect route which you can then use to identify a user, you will receive information such as:

    - Character name
    - Character id in the format of EVECHARACTER:2114794365
    - Character owner hash, this tells you the difference between character ownership if they were to transfer characters to another player or account which prevents them from accessing the previous owner's user account on your site using that character.

6. From there you'll want to store the user in a database identified by character owner hash (not character id) & then redirect them to your website with a cookie to identify who they are going forward such as a cookie with a JWT containing their user id.

You can see more detailed explanations in the EVE Online ESI Documentation under the SSO section here: <https://docs.esi.evetech.net/>

## Questions

If you have any questions contact us through the Black Rose Discord (<https://discord.gg/BCnMQ6KMfa>).

## Contribution/Improvements

This crate still has some work to do

1. The EVE authorization function needs to be able to accept custom scopes to allow for different use cases
2. Error handling needs to be improved upon as the majority of error handling is simply .expect() which will cause the code to panic when an error is encountered causing that API thread to fail.
