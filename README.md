# Microsoft Entra Authcode Flow BOF
A Beacon Object File (BOF) that obtains Microsoft Entra access and refresh tokens by launching a browser with an OAuth authorization code flow URL. This technique allows operators to keep all token exchange activities on the endpoint and circumvent conditional access policies.

**Blog:** [Obtaining Microsoft Entra Refresh Tokens via Beacon](https://www.infosecnoodle.com/p/obtaining-microsoft-entra-refresh)

<img width="1346" height="567" alt="image" src="https://github.com/user-attachments/assets/6aa9d7b6-6d35-40cf-bbaf-37c4265844b0" />

## How It Works
1. Launches a new browser tab (via `CreateProcessA`) with an OAuth authorization URL
2. Monitors window titles for the redirect containing the authorization code
3. Exchanges the code for access and refresh tokens


## Requirements
- User must be authenticated to Entra ID in their browser (valid `ESTSAUTH` cookies)
- Client ID must have consent in the tenant
- Client ID must accept `https://login.microsoftonline.com/common/oauth2/nativeclient` redirect URI

## Usage
Load `entra-authcode-flow.cna` in Cobalt Strike (or the Python script for Outflank C2).

```text
beacon> entra-authcode-flow <clientid> <scope> <browser> [email_hint]
beacon> entra-authcode-flow 1fec8e78-bce4-4aaf-ab1b-5451cc387264 "openid offline_access https://graph.microsoft.com/.default" 0 bob@example.com
```

## References
- **[@freefirex](https://x.com/freefirex2)**: [get_azure_token BOF](https://github.com/trustedsec/CS-Remote-OPs-BOF/blob/main/src/Remote/get_azure_token/entry.c) - Original Azure token BOF implementation
- **[Secureworks](https://www.secureworks.com/)**: [Family of Client IDs Research](https://github.com/secureworks/family-of-client-ids-research) - Client IDs
- **[@_dirkjan](https://x.com/_dirkjan)**: [ROADtools First-Party Scopes](https://github.com/dirkjanm/ROADtools/blob/master/roadtx/roadtools/roadtx/firstpartyscopes.json) - Microsoft first-party application scopes
