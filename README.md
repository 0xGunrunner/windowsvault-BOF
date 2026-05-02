# WindowsVault BOF

A Beacon Object File (BOF) for enumerating credentials stored in the Windows Credential Vault (vaultcli.dll). Extracts saved logins from Internet Explorer, Edge, and other applications that use the Windows Vault.

## Overview

Windows Vault stores credentials for various applications including:
- Internet Explorer / Edge saved passwords
- Windows network credentials
- Application-specific credentials

This BOF mirrors the functionality of Seatbelt's `WindowsVault` command and is compatible with Cobalt Strike and other C2 frameworks that support BOFs.

## Features

- Enumerates all accessible vaults (Web Credentials, Windows Credentials, etc.)
- Extracts Resource, Identity, and Credential fields
- Supports Windows 7 and Windows 8+ vault item structures
- Handles multiple element types (String, SID, ByteArray, etc.)
- No CRT dependencies — pure Win32 API calls

## Requirements

- Target: Windows 7 or later
- Permissions: Must run in the context of the target user (see Usage Notes)

## Compilation

### Kali Linux (MinGW)

```bash
# x64
x86_64-w64-mingw32-gcc -masm=intel -Wall -c -o windowsvault.x64.o windowsvault.c

# x86
i686-w64-mingw32-gcc -masm=intel -Wall -c -o windowsvault.x86.o windowsvault.c
```

### Makefile

```makefile
CC_x64 = x86_64-w64-mingw32-gcc
CC_x86 = i686-w64-mingw32-gcc
CFLAGS = -masm=intel -Wall -c

all: windowsvault.x64.o windowsvault.x86.o

windowsvault.x64.o: windowsvault.c
	$(CC_x64) $(CFLAGS) -o $@ $<

windowsvault.x86.o: windowsvault.c
	$(CC_x86) $(CFLAGS) -o $@ $<

clean:
	rm -f *.o
```

## Usage

### Cobalt Strike (AdaptixC2)

```
beacon> windowsvault
```

### Other C2 Frameworks

Load the BOF according to your framework's documentation. The entry point is `go` with no arguments.

## Example Output

```
[*] Windows Vault Enumeration
    OS: Win8+ | Vaults found: 2

  [Vault 0]
    GUID : {4BF4C442-9B8A-41A0-B380-DD4A704DDB28}
    Type : Web Credentials
    Items: 2

    --- Item 0 ---
      SchemaGuid : {3CCD5499-87A8-4B10-A215-608888DD3B55}
      Resource    : https://192.168.4.111/
      Identity    : itemployer
      PackageSid  : (null)
      Credential  : NotOnlyAccess

    --- Item 1 ---
      SchemaGuid : {3CCD5499-87A8-4B10-A215-608888DD3B55}
      Resource    : https://192.168.4.111/
      Identity    : definitelynottoor
      PackageSid  : (null)
      Credential  : BugTrackerL0gOFF

  [Vault 1]
    GUID : {77BC582B-F0A6-4E15-4E80-61736B6F3B29}
    Type : Windows Credentials
    Items: 0
```

## Usage Notes

### Security Context

The BOF must run in the context of the user whose vault you want to enumerate. Running as SYSTEM or a different user will typically result in `Items: 0` because the Vault API cannot decrypt credentials without the user's DPAPI master key.

**To enumerate another user's vault:**

```bash
# Steal token from target user's process
beacon> steal_token <pid>

# Or use make_token with valid credentials
beacon> make_token DOMAIN\user password

# Then run the BOF
beacon> windowsvault
```

### Vault Types

| GUID | Type |
|------|------|
| `4BF4C442-9B8A-41A0-B380-DD4A704DDB28` | Web Credentials |
| `77BC582B-F0A6-4E15-4E80-61736B6F3B29` | Windows Credentials |
| `3CCD5499-87A8-4B10-A215-608888DD3B55` | Windows Web Password Credential |

## Technical Details

### Vault Item Element Layout

The `VAULT_ITEM_ELEMENT` structure uses the following memory layout:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 bytes | Property ID / Internal |
| 8 | 4 bytes | VAULT_ELEMENT_TYPE |
| 12 | 4 bytes | Padding |
| 16 | varies | Data (pointer or inline) |

### Supported Element Types

- `VaultElementTypeString` (7) — Wide string pointer
- `VaultElementTypeSid` (8) — Security Identifier
- `VaultElementTypeByteArray` (9) — Binary data
- `VaultElementTypeBoolean` (0)
- `VaultElementTypeShort` (1)
- `VaultElementTypeUnsignedShort` (2)
- `VaultElementTypeInt` (3)
- `VaultElementTypeUnsignedInt` (4)
- `VaultElementTypeGuid` (6)
- `VaultElementTypeTimeStamp` (10)

### Win8 vs Win7 Structures

Windows 8+ added a `pPackageSid` field to the `VAULT_ITEM` structure. The BOF automatically detects the OS version and uses the correct structure size for iteration.

| OS | Struct Size |
|----|-------------|
| Win8+ | 80 bytes |
| Win7 | 72 bytes |

## References

- [Seatbelt](https://github.com/GhostPack/Seatbelt) — Original C# implementation
- [vaultcli.dll API](https://docs.microsoft.com/en-us/windows/win32/seccrypto/credential-manager) — Windows Credential Manager API

## License

MIT License

## Disclaimer

This tool is intended for authorized security testing and red team operations only. Use responsibly and only on systems you have permission to test.
