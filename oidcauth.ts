import { Config } from './configuration';
import { PKCE } from './pkce';

export namespace OIDC {
    export interface TokenData {
        accessToken: string;
        expiresAt: number; // Store the timestamp when the token expires
        tokenType?: string;
        resource?: string;
        idToken?: string;
        refreshToken?: string;
        refreshTokenExpiresIn?: number;
        scope?: string;
        expiresIn?: number;
    }

    export async function authenticate(config: Config, routeToOriginCallback: (origin: string) => void = () => { }): Promise<void> {
        if (config.oidcAuth.enabled) {
            let storedCodeVerifier = "";
            const code = new URLSearchParams(document.location.search).get("code") as string;

            // Check if stored access token is still valid
            if (OIDC.isAccessTokenExpired()) {
                if (code) {
                    // Retrieve the `code_verifier` from localStorage
                    storedCodeVerifier = localStorage.getItem("codeVerifier") as string;
                    if (!storedCodeVerifier) {
                        console.error("Code verifier not found in localStorage");
                        return;
                    }
                } else {
                    await OIDC.fetchAuthorizationCode(config);
                }

                // Exchange the code for an access token using the `code_verifier`
                await OIDC.exchangeCodeForToken(config, code, storedCodeVerifier);
                routeToOriginCallback(localStorage.getItem("origin") as string);
            }
        }
    }

    // Function to handle the initial redirect to the Identity Provider for login
    export async function fetchAuthorizationCode(config: Config): Promise<void> {
        const oidcSettings = config.oidcAuth.settings;

        // 1. Generate a `code_verifier`
        const codeVerifier = PKCE.generateCodeVerifier();
        localStorage.setItem('codeVerifier', codeVerifier);  // Save for later use

        // 2. Generate the corresponding `code_challenge`
        const codeChallenge = await PKCE.generateCodeChallenge(codeVerifier);

        // 3. Construct the authorization URL with PKCE parameters
        const loginUrl = `${oidcSettings.authority}?` +
            `client_id=${oidcSettings.client_id}&` +
            `redirect_uri=${encodeURIComponent(oidcSettings.redirect_uri)}&` +
            `response_type=${oidcSettings.response_type}&` +
            `scope=${oidcSettings.scope}&` +
            // `state=some-random-state&` +  // Optional: Include state for CSRF protection
            `code_challenge_method=S256&code_challenge=${codeChallenge}`;  // PKCE parameters

        localStorage.setItem("origin", window.location.href);  // Store original URL
        window.location.href = loginUrl;  // Redirect the user to the login page
    };

    // Function for exchanging authorization code for an access token
    export async function exchangeCodeForToken(config: Config, code: string, storedCodeVerifier: string): Promise<TokenData | null> {
        if (!code || !storedCodeVerifier)
            console.warn("Authorization code and/or code verifier is null.", {code: code, codeVerifier: storedCodeVerifier}); 

        const oidcSettings = config.oidcAuth.settings;

        // Define the token exchange request parameters
        const params = new URLSearchParams();
        params.append('client_id', oidcSettings.client_id);
        params.append('code', code);
        params.append('grant_type', 'authorization_code');
        params.append('redirect_uri', oidcSettings.redirect_uri);
        params.append('code_verifier', storedCodeVerifier);

        try {
            // Make the request to the token endpoint
            const response = await fetch(oidcSettings.token_endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: params.toString()  // Send parameters as x-www-form-urlencoded
            });

            // Parse and return the response as JSON
            if (response.ok) {
                const token = await response.json();
                OIDC.storeAccessToken(token);
                window.history.replaceState({}, document.title, "/"); // Clean up URL
                return token;
            } else {
                console.error('Failed to exchange code for token', response);
                return null;
            }
        } catch (error) {
            console.error('Error exchanging code for token:', error);
            return null;
        }
    }

    // Store the token and expiration time
    export function storeAccessToken(tokenResponse: any): TokenData {
        const token: TokenData = {
            accessToken: tokenResponse.access_token,
            // Calculate expiration time based on current time
            expiresAt: Date.now() + tokenResponse.expires_in * 1000, // expires_in is in seconds
            tokenType: tokenResponse.token_type,
            resource: tokenResponse.resource,
            idToken: tokenResponse.id_token,
            refreshToken: tokenResponse.refresh_token,
            refreshTokenExpiresIn: tokenResponse.refresh_token_expires_in,
            scope: tokenResponse.scope,
            expiresIn: tokenResponse.expires_in
        };
        localStorage.setItem("accessToken", JSON.stringify(token));
        return token;
    }

    // Function to retrieve stored access token
    export function getAccessToken(): TokenData | null {
        try {
            const token: TokenData = JSON.parse(localStorage.getItem("accessToken") as string);
            if (token) {
                return token; // If no token is stored, treat it as expired
            }
        } catch (error) {
            console.error("Something went wrong parsing access token data:", error);
        }
        return null;
    }

    // Function to check if the token has expired
    export function isAccessTokenExpired(): boolean {
        const tokenString = localStorage.getItem("accessToken");
        if (!tokenString) {
            return true; // If no token is stored, treat it as expired
        }
        const token: TokenData = JSON.parse(tokenString);
        return Date.now() > token.expiresAt; // Compare current time with expiration
    }

    // Removes all stored data related to OIDC
    export function purge(): void {
        try {
            localStorage.removeItem("accessToken");
            localStorage.removeItem("codeVerifier");
            localStorage.removeItem("origin");
            console.warn("All stored OIDC data has been purged.")
        } catch (error) {
            console.error("Something went wrong purging OIDC data:", error);
        }
    }
}




