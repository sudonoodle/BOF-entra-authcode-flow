# Microsoft Entra Authcode Flow BOF

A Beacon Object File (BOF) to obtain Microsoft Entra tokens via authcode flow.

## Usage

Compile with `make` and import the `entra-authcode-flow.cna` aggressor to Cobalt Strike.

```text
beacon> help entra-authcode-flow
beacon> entra-authcode-flow <clientid> <scope> <browser> [opt: email-hint]
```

<img width="1005" alt="SCR-20250508-tmfj" src="https://github.com/user-attachments/assets/bfc3c262-b435-41a6-9a9d-7373706db23d" />

## References

- Blog post [Obtaining Microsoft Entra Refresh Tokens via Beacon](https://www.infosecnoodle.com/p/obtaining-microsoft-entra-refresh)
- Original [`get_azure_token`](https://github.com/trustedsec/CS-Remote-OPs-BOF/blob/main/src/Remote/get_azure_token/entry.c) BOF by [freefirex ](https://x.com/freefirex2)from TrustedSec Remote Ops repo
- [Family of client IDs research](https://github.com/secureworks/family-of-client-ids-research) by Secureworks
- [First-party scopes](https://github.com/dirkjanm/ROADtools/blob/master/roadtx/roadtools/roadtx/firstpartyscopes.json) - [Dirk-Jan](https://x.com/_dirkjan) 
