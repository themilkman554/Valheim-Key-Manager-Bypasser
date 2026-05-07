[REPO]: https://github.com/themilkman554/Valheim-Key-Manager-Bypasser
[PAGES]: https://themilkman554.github.io/Valheim-Key-Manager-Bypasser/
# Valheim Key Manager Bypasser

## Why It Exists

Some Valheim mod authors embed a licensing system called **Key Manager** inside their `.dll` files to paywall / stonewall mods.
At runtime this system performs a license check and, if it fails (e.g. on a Linux dedicated server, without an internet connection, or when the mod is used without an active key), it calls `Application.Quit()` to abort the game and logs fatal errors to the BepInEx console.

This project patches those checks from the `.dll` IL code so the mod loads and runs without restriction. Useful for Linux dedicated servers, offline use and testing mods.

---

## How To Use

The easiest way to use it: **[open the web patcher][PAGES]** in your browser - or download the source and open `index.html` locally.

Either browse, or drag and drop your mod `.dll` into the upload box on the page and wait for the patching status. If it is patched, a download will start automatically with your patched mod, named like: `patched_{modname}.dll`.

---

## How It Works

### 1. IL-level patching (primary method)

The patcher reads the `.dll` as a raw binary and walks the **ECMA-335 metadata** (the structured format that every .NET assembly uses) without any external library. It finds the KeyManager protection methods and overwrites the very first byte(s) of their IL code stream so they return immediately, before any license logic runs.

#### What gets parsed

| Structure | Purpose |
|---|---|
| PE section table | Maps virtual addresses to file offsets |
| CLI header | Locates the metadata root |
| `#Strings` / `#Blob` / `#~` streams | Name strings, method signatures, table data |
| All 45 metadata tables | TypeDef, MethodDef, TypeRef, MemberRef, NestedClass |

#### The three patch targets

Each target is found by two independent strategies (a structural search and a literal-name search), so the patcher still works even if only one approach applies:

| Target | What it does | Patch applied |
|---|---|---|
| `KeyManager.KeyManager::CheckAllowed` | Public entry point that returns an int; non-zero means "denied" | Prepend `ldc.i4.2; ret` to always return 2 (allowed) |
| Abort scheduler (`DdTLC...`) | Schedules periodic `Application.Quit()` calls | Prepend `ret` so the method does nothing |
| Fatal logger (`KLaie...`) | Writes `[Fatal :KeyManager ...]` noise to the BepInEx log | Prepend `ret` so the method does nothing |

#### Structural search (how patterns are found without knowing names)

- **Abort scheduler:** The patcher scans every method that returns `System.Action`. If that method's IL contains a `ldftn <target>; newobj System.Action` sequence, the referenced `<target>` method is the abort callback. It must be static, parameterless, void, and declared in the same type.
- **Fatal logger:** Once the abort scheduler's declaring type is known, the patcher looks inside it for static `void(SomeEnum)` methods where `SomeEnum` is a nested enum of that same type, the characteristic signature of the logger helper.

#### Literal-name search (fallback for known obfuscated identifiers)

Searches all types by exact obfuscated name (`hLMfzAbLmwherEVpUSIwXsUbDQAVA`) and patches methods named `DdTLCbDRTTpbVzNKpUBDJoCGHzNQ` (abort) and `KLaieQNEwJKtgTCxmbpdGBVwcqCzA` (logger) directly.

#### In-place patching

The patcher edits the bytes of the method body directly inside the file buffer:
- `ret` = `0x2A` (1 byte), makes a void method return immediately.
- `ldc.i4.2; ret` = `0x18 0x2A` (2 bytes), makes an int-returning method immediately return `2`.

No assembly rewrite or re-serialization is needed; only the first 1-2 bytes of each target method change.

#### Warnings

After patching, the tool reports what it found and flags anything unexpected:

| Warning | Meaning |
|---|---|
| `"No KeyManager namespace found in file.  Nothing to patch."` | The .dll does not seem to be KeyManager protected. |
| `"KeyManager namespace was found in file, but CheckAllowed was not patched."` | The public API has likely moved. Output .dll may still fail. |
| `"Abort scheduler was not found."` | Periodic checks may still abort the game. |
| `"Fatal error logger was not silenced. This is a cosmetic issue only."` | Mod should work fine, but expect log noise in the console. |

---

### 2. Magic-byte pattern matching (fallback)

If the IL-level patcher finds no KeyManager metadata (e.g. the file is not a managed .NET assembly, or uses an unexpected structure), the tool falls back to scanning for a known raw byte sequence and patching the byte at a fixed offset within it:

```
Pattern : 01 2B 01 16 0D 09 2C 08 20 E5 49 59 C8 25 2B 06
Offset  : +6
Patch   : 0x2D
```

Additional patterns can be added to the `magicPatterns` array in `patcher.js`.

---

## Contributors

![contributors badge](https://readme-contribs.as93.net/contributors/themilkman554/Valheim-Key-Manager-Bypasser?shape=circle&fontSize=10)

Contributions welcome when patching logic needs updating.

## Acknowledgements

Includes IL patching from:
- [KeyNeutralizer](https://gitlab.com/KeyNeutralizer/KeyNeutralizer) - [MIT Licensed](third-party-licenses.md)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
