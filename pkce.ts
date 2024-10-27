// Utility functions to handle PKCE code generation and transformations

export namespace PKCE {
    // Generate a random string to use as `code_verifier`
    export function generateCodeVerifier(length: number = 128): string {
        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
        let result = '';
        for (let i = 0; i < length; i++) {
            const randomIndex = Math.floor(Math.random() * charset.length);
            result += charset[randomIndex];
        }
        return result;
    }

    // Convert the code verifier to a code challenge using SHA-256
    export async function generateCodeChallenge(codeVerifier: string): Promise<string> {
        const encoder = new TextEncoder();
        const data = encoder.encode(codeVerifier);
        const digest = await crypto.subtle.digest('SHA-256', data);
        return base64UrlEncode(new Uint8Array(digest));
    }

    // Helper function to Base64 URL encode the SHA-256 hash
    export function base64UrlEncode(arrayBuffer: Uint8Array): string {
        const base64String = btoa(String.fromCharCode(...arrayBuffer));
        return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    // Helper function to parse a JWT (ID token) to extract user info
    export function parseJwt(token: string) {
        const base64Url = token.split('.')[1];
        const base64 = decodeURIComponent(atob(base64Url).split('').map(function (c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(base64);
    }
}