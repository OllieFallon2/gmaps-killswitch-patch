# Fixing old Google Maps for Android without patching the APK

Old versions of Google Maps show a full-screen page rendered in WebView prompting you to update the app and refuse to run. For years, the fix was to patch the smali and re-sign the APK. However, this changes the signature, and GMS then rejects the app, breaking sign-in and many other functions of the app.

This project removes the kill switch **without modifying the app at all**. A small [mitmproxy](https://mitmproxy.org/) script changes one byte in the sever's config response, so the original, unmodified APK keeps working, sign-in included.

> Not affiliated with Google. Use your own legitimately obtained copy of the app. This repo does **not** include any APKs.

## Contents

1. [Tested versions](#tested-versions)
2. [How the kill switch works](#how-the-kill-switch-works)
3. [How it was found](#how-it-was-found)
4. [The fix](#the-fix)
5. [Requirements](#requirements)
6. [Setup and running](#setup-and-running)
7. [Checking that it worked](#checking-that-it-worked)
8. [Troubleshooting](#troubleshooting)
9. [Limitations and security](#limitations-and-security)
10. [Adapting to other versions](#adapting-to-other-versions)
11. [Reporting test results](#reporting-test-results)
12. [Files and credit](#files-and-credit)

---

## Tested versions

### Google Maps

| Version | Date | Result | Notes |
|---|---|---|---|
| 9.0.0 | Nov 2014 | Works | Everything works perfectly. |
| Anything else | | Not tested | See [Adapting to other versions](#adapting-to-other-versions) and [Reporting test results](#reporting-test-results). |

Details of the 9.0.0 build, from decompiling it with jadx:

- package 'com.google.android.apps.maps'
- `minSdkVersion` 18, `targetSdkVersion` 17
- native libraries for `armeabi-v7a` only (32-bit ARM)

I have only tested this one version. Other versions may use a different field layout or response framing, so treat them as untested until you've checked (see the adaptation section).

### Test environment

| Part | What I used |
|---|---|
| Phone | Samsung Galaxy S10 (SM-G973F), not rooted |
| Computer | M1 MacBook Air |
| Proxy | mitmproxy (`mitmdump`), installed with Homebrew |

---

## How the kill switch works

Reading the decompiled 9.0.0 app shows the whole mechanism:
 
1. At startup the app fetches a config message from
   `POST https://clients4.google.com/glm/mmap`.
2. A protobuf message in that response (class `com.google.t.b.a.uy` in this
   build) has four string fields. **Field 2** holds the kill-switch page URL,
   in practice `https://maps.gstatic.com/gmm/upgrades/index.html`.
3. A handler class (`com.google.android.apps.gmm.terms.b`) saves that string in
   the app's preferences as `currentKillSwitchContentUrl`. If it is non-null,
   the app shows `KillSwitchFragment`, which loads the URL in a WebView.
4. If a later response has **no** field 2, the handler stores `null` and removes
   the fragment itself.

In pseudocode:
 
```text
on config received:
    url = config.field2 if present else null
    preferences.killSwitchUrl = url
    if url != null: show KillSwitchFragment(url)
    else:           dismiss KillSwitchFragment
```
 
The decision is made by the server, not by a local version comparison. The page
URL is not stored as a string anywhere in the APK, which is why searching the
code for `gmm/upgrades` finds nothing.
 
---
 
## How it was found
 
Everything here is read-only. The APK is never modified.
 
```bash
# 1. Decompile
jadx -d maps-src Maps.apk
 
# 2. Check what it targets
grep -E "minSdkVersion|targetSdkVersion|package=" maps-src/resources/AndroidManifest.xml
ls maps-src/resources/lib/
 
# 3. Fragment class names survive obfuscation, so search for the class
grep -rl KillSwitch maps-src/sources
```

Then follow the references:
 
- `KillSwitchFragment` only displays a URL passed to it, so find its callers
  (`terms/b.java` and `terms/c.java` in 9.0.0).
- `terms/b.java` reads the URL from a protobuf object (`uy`). In that class's
  parsing constructor, the `case` numbers are protobuf tags
  (`field << 3 | wire type`): `10` = field 1, `18` = field 2, `26` = field 3,
  `34` = field 4. The kill-switch URL is the one stored when bit 2 is set,
  which is field 2.
- With the phone's traffic going through a proxy, the `/glm/mmap` response
  showed the URL inside a gzip-compressed record.
---

## The fix
 
Protobuf parsers skip fields whose numbers they don't know. The tag byte in
front of the kill-switch string is `0x12` (field 2, length-delimited). Change it
to `0x7A` (field 15, length-delimited) and the string is parsed as an unknown
field, so the app sees field 2 as absent.
 
Illustrative bytes (the URL is 48 characters, `0x30`):
 
```text
before:  12 30 68 74 74 70 73 3a 2f 2f ...   tag=field 2,  length 48, "https://..."
after:   7a 30 68 74 74 70 73 3a 2f 2f ...   tag=field 15, length 48, "https://..."
```
 
Only one byte changes and no lengths inside the message need fixing. The core
of the script is:
 
```python
tag, length = raw[start - 2], raw[start - 1]      # bytes just before "http..."
if tag != 0x12 or MARK not in raw[start:start + length]:
    logging.warning("unexpected bytes before URL")  # fail safe: change nothing
    return None
out = bytearray(raw)
out[start - 2] = 0x7A                              # field 15, wire type 2
```
 
### The response framing
 
`/glm/mmap` responses are not a bare protobuf. This is my reading of captured
9.0.0 traffic, not a documented format:
 
```text
2 header bytes (00 17)
then repeated records:
    1 byte    record type
    4 bytes   big-endian signed length
              (negative = gzip-compressed, abs(length) = compressed size)
    N bytes   payload
```
 
The record sizes add up exactly to the full response length. The kill-switch URL
sat in the second record, inside a gzip stream, so the script decompresses each
record, changes the tag byte, recompresses, and rewrites that record's length.
If anything doesn't match what it expects, it logs a warning and leaves the
response untouched.
 
---

## Requirements
 
- A device that can run the app. 9.0.0 ships only 32-bit ARM libraries, so the
  device must support 32-bit ARM. Android emulators on Apple Silicon can't run
  it for that reason.
- Android 14 or newer refuses to install apps with a very old `targetSdk`.
  Newer `adb` has `adb install --bypass-low-target-sdk-block`.
- An app that targets API 23 or lower, so that Android trusts **user-installed
  CA certificates** for it. 9.0.0 targets API 17. Apps targeting API 24 or
  higher would ignore the certificate, and this method would not work for them.
- A computer on the same Wi-Fi network with mitmproxy installed.
- **No root is needed.**
---

## Setup and running
 
### 1. Install mitmproxy and generate its certificate
 
```bash
brew install mitmproxy        # or: pipx install mitmproxy
mitmdump                      # run once, then Ctrl+C; creates ~/.mitmproxy
```
 
### 2. Point the phone at the proxy
 
Find your computer's IP (macOS: `ipconfig getifaddr en0`), then either set a
manual proxy in the Wi-Fi settings or use adb:
 
```bash
adb shell settings put global http_proxy YOUR_COMPUTER_IP:8080
```
 
To turn it off again:
 
```bash
adb shell settings put global http_proxy :0
```
 
### 3. Install the mitmproxy certificate on the phone
 
With `mitmdump` running and the proxy set, open `http://mitm.it` in the phone's
browser and download the Android certificate. Then go to Settings → Security →
Encryption & credentials → Install a certificate → CA certificate. Android
requires a screen lock to be set.
 
### 4. Install the app
 
```bash
adb install Maps.apk          # your own copy of Google Maps
```
 
### 5. Run the script
 
```bash
mitmdump -s killswitch.py --allow-hosts '^clients4\.google\.com:443$'
```
 
The `--allow-hosts` option matters. It makes mitmproxy decrypt **only** the one
host Maps needs and pass everything else through untouched. Without it, Google
Play Services and the Play Store, which pin Google's real certificates, fail to
connect through the proxy.
 
Force-stop and relaunch Maps:
 
```bash
adb shell am force-stop com.google.android.apps.maps
adb shell monkey -p com.google.android.apps.maps -c android.intent.category.LAUNCHER 1
```
 
---

## Checking that it worked
 
The terminal running `mitmdump` should print:
 
```text
kill-switch field neutralised
```
 
The update screen should not appear. Another check is that the log shows no
`GET https://maps.gstatic.com/gmm/upgrades/index.html` after the config
response. Before the fix, that request appeared about a quarter of a second
after the config response arrived.
 
If the screen shows once on the first launch, that is the URL stored by an
earlier run. Once the edited response arrives, the app stores `null`. Force-stop
and relaunch to confirm.
 
---

## Troubleshooting
 
| Symptom | Likely cause | What to do |
|---|---|---|
| Sign-in or Play Store says "There was a problem connecting to accounts.google.com" | mitmproxy is decrypting hosts it shouldn't. Play Services pins Google's certificates. | Restart with `--allow-hosts '^clients4\.google\.com:443$'`. |
| `Client TLS handshake failed` for `play.google.com` | Same cause. | Same fix. Those hosts are not needed. |
| Log says `unexpected bytes before URL` | The response layout differs from 9.0.0. | Run `inspect_mmap.py` and compare. See [Adapting to other versions](#adapting-to-other-versions). |
| Log says nothing and the screen still shows | The response didn't contain the URL on this launch, or the field layout is different. | Run `inspect_mmap.py` to see what the response contains. |
| Install is refused on Android 14+ | Old `targetSdk` block. | `adb install --bypass-low-target-sdk-block Maps.apk` |
| App crashes on launch | Device has no 32-bit ARM support. | Use a device whose ABI list includes `armeabi-v7a` (`adb shell getprop ro.product.cpu.abilist`). |
| Screen returns later | The proxy was off when the app refreshed its config. | Keep the proxy running whenever you use Maps. |
 
---

## Limitations and security
 
- **The proxy must be reachable whenever you use Maps.** The server sends the
  kill-switch URL on every config fetch, and the app refreshes at least daily.
  Without the proxy the screen comes back.
- If the phone's proxy setting is on but the computer is off, other apps lose
  their connection. Turn the setting off when you're away.
- If Google changes the response layout, the script fails safe (it logs a
  warning and changes nothing), but the screen returns until the script is
  updated.
- Tested on one device and one version. A 2014 login flow could stop working
  for reasons unrelated to the kill switch.
- The mitmproxy CA certificate on the phone lets whoever holds the private key
  in `~/.mitmproxy` read traffic from apps that trust user certificates. Keep
  that folder private, and remove the certificate from the phone when you're
  done (Settings → Security → Encryption & credentials → User credentials).
- Don't leave the proxy listening on an untrusted network.
---

## Adapting to other versions
 
Class names are obfuscated and differ per build, so don't expect `terms/b.java`
to exist elsewhere. The steps:
 
1. Decompile and find the kill-switch fragment (see [How it was found](#how-it-was-found)).
2. Find who calls it and which protobuf field supplies the URL.
3. Note the tag number in that message's parsing constructor.
4. Capture a real response with the read-only helper:
```bash
   mitmdump -s inspect_mmap.py
```
 
   It prints the framing, finds the URL inside the gzip records, and shows the
   bytes around it. Check that the tag byte before the URL is the one you found
   in step 3.
5. If the tag or framing differs, adjust `patch_payload()` in `killswitch.py`.
 
---
 
## Reporting test results
 
If you try another version, please open an issue or pull request with:
 
```text
Maps version and date:
Result (works / fails / partly):
Device and Android version:
Did sign-in work:
Did inspect_mmap.py show tag 0x12 before the URL:
Anything you had to change in killswitch.py:
```
 
Confirmed versions can then be added to the table above.
 
---

## Files and credit

| File | Purpose |
|---|---|
| `killswitch.py` | The mitmproxy addon that edits the response |
| `inspect_mmap.py` | Read-only helper for exploring responses on other versions |

The idea of looking for `KillSwitchFragment` came from Kenneth Jenkins, who [patched the APK](https://kennethjenkins.net/posts/apk-patching/) of Google Maps 7.0.2. Many thanks for the very helpful blog post!
