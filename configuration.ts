export type Config = {
    oidcAuth: {
        enabled: boolean;
        settings: {
            client_id: string;
            authority: string;
            response_type: string;
            scope: string;
            redirect_uri: string;
            grant_type: string;
            token_endpoint: string;
        }
    }
}