# Stan Mic Bridge

**Use your Mac microphone in Windows—even after you close Chrome.**

A small native macOS menu bar app streams live microphone audio over your private Tailscale network to a Windows virtual microphone. Built for dictating into Windows apps while using a remote desktop. RustDesk and Typeless work with it, but neither is a protocol dependency.

```text
Mac microphone → native menu bar app → private HTTPS/WebSocket
                                         ↓
Windows receiver → VB-CABLE → Windows default microphone → your app
```

## Features

- Native Mac sender with Start, Stop, connection status, and automatic reconnect.
- App icon for Finder/login items and a microphone symbol in the menu bar.
- Close Chrome and Terminal while the menu bar app keeps running.
- Save the connection once in macOS Keychain; no repeated token entry.
- Check GitHub releases from the menu and choose to download/install inside the app.
- Convert microphone audio to 48 kHz mono Float32 with bounded buffering.
- Switch Windows default microphone roles on first audio, then restore them when the session ends.
- Browser sender included as an alternative; its tab must remain open.
- No audio files or transcripts recorded by the bridge. Your dictation application's own data policy still applies.

## Requirements

**Mac:** macOS 12+ and Tailscale. A universal prebuilt app supports Intel and Apple Silicon. Apple Command Line Tools (`xcode-select --install`) are needed only for the optional source build.

**Windows:** Python 3.12 is the reference runtime, [VB-CABLE](https://vb-audio.com/Cable/), and [Tailscale](https://tailscale.com/download). Install the virtual audio driver using its official installer and follow its reboot instructions. Select a working physical microphone as the Windows default before setup. The virtual endpoint must be named `CABLE Output (VB-Audio Virtual Cable)`.

Both devices must be on a tailnet with access between them. Enable Tailscale HTTPS/Serve for the Windows machine. Do not use Funnel or publicly expose the receiver.

## 1. Set up the Windows receiver

Clone this repository and run PowerShell from its directory:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock.txt
.\.venv\Scripts\python.exe setup_receiver.py --origin 'https://YOUR-WINDOWS-HOST.YOUR-TAILNET.ts.net:8443'
```

Use the actual HTTPS name from your Tailscale machine, not the example. Setup creates a random connection token and saves the current physical microphone roles for restoration. Keep `config.json` and `audio-defaults.json` private; they are ignored by Git. Setup does not replace an existing configuration.

Start the receiver in the foreground first:

```powershell
.\.venv\Scripts\python.exe server.py
```

In a second PowerShell window, enable a private HTTPS proxy:

```powershell
tailscale serve --bg --https=8443 http://127.0.0.1:8765
```

The receiver listens only on loopback. The configured origin must exactly match the HTTPS address, including the port. Build your private pairing link from `config.json`: `ORIGIN/#token=TOKEN`. Treat that link like a password; do not put it in an issue, screenshot, or commit.

After testing, stop the foreground process with Ctrl+C, then launch a hidden receiver:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File .\Start-Receiver.ps1
```

To start it after Windows login, open `shell:startup` with Win+R and create a shortcut with this Target (replace the repository path):

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\path\stan-mic-bridge\Start-Receiver.ps1"
```

Set the shortcut's **Start in** to the repository folder. This project does not install a Windows system service; microphone forwarding requires the receiver to run in your logged-in session. RustDesk's separate system service does not launch this receiver.

## 2. Install the native Mac app

Download **StanMicBridge-macOS.zip** from the [latest release](https://github.com/stantheman0128/stan-mic-bridge/releases/latest), extract it, and move **Stan Mic Bridge.app** into `~/Applications`. In Finder, Command+Shift+G opens that folder. Quit an older running version before replacing it. Launch the installed app. The prebuilt app is ad-hoc signed, not Developer ID notarized; if macOS blocks it, review the app's origin and use the system's per-app approval in **Privacy & Security → Open Anyway**. No security settings are changed by the app. [Apple's explanation](https://support.apple.com/102445).

Alternatively, clone or download this repository and build locally:

```bash
bash mac/install.command
```

The installer builds with Apple Swift, locally signs the app, and installs `~/Applications/Stan Mic Bridge.app`. It preserves an older installation as a dated backup and asks you to quit a running copy before upgrading. No Homebrew or third-party Mac runtime is needed. A rebuilt app may prompt again for microphone or Keychain access.

The app checks the existing microphone authorization before starting. It requests access only when the system reports that permission has not been decided; an already-authorized Start goes directly to connection. Login startup, microphone permission, and Keychain access are separate settings. Stopping and starting the same installation should reuse its permission. Ad-hoc builds have a version-specific code identity and may prompt again after upgrades; the optional fixed local signing setup below keeps a persistent identity instead. [Apple's code-signing requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements).

The icon is generated reproducibly from `mac/GenerateIcon.swift` using AppKit and packaged as `AppIcon.icns` before signing. No external image download is required.

1. Click **Mic** in the menu bar and choose **設定連線…** (Configure connection).
2. Paste your private `https://…/#token=…` link and save it in Keychain.
3. Choose **開始傳送** (Start) and allow microphone access.
4. In Windows, use an app that follows the default microphone. For Typeless, choose automatic microphone detection and disable its option to mute other audio during dictation.
5. Close Chrome and dictate a sentence to confirm actual delivery.

Choose **停止傳送** (Stop) to stop recording and restore Windows microphone defaults, or quit the app. Only one sender may connect at a time; stop a browser sender before using the native app.

### Open automatically after Mac login

In **System Settings → General → Login Items** (or **Login Items & Extensions**), add `~/Applications/Stan Mic Bridge.app` to **Open at Login**. In the file picker, press Command+Shift+G and enter `~/Applications` if needed. On macOS Monterey, use **System Preferences → Users & Groups → Login Items** instead. [Apple's instructions](https://support.apple.com/guide/mac-help/open-items-automatically-when-you-log-in-mh15189/mac).

This opens the menu bar app after login. **Normal launches, including login and manual reopening, start stopped; click Start to transmit.** Automatic restoration after an update does not change login behavior. An enabled session can reconnect after sleep/wake, but the Mac cannot send while asleep or powered off.

### Check for updates

The Mic menu shows the installed version. Choose **檢查更新…** (Check for updates) to check independently of microphone transmission. The menu automatically reopens when the check finishes, showing the result without another click. When a newer version is available, it offers installation; release history remains a separate action. The app contacts this project's public GitHub Releases API only when clicked. Checking does not stop recording and does not send your microphone connection credentials to GitHub.

For a newer version, choose **下載並安裝更新** (Download and install update). The app downloads the prebuilt ZIP, verifies the GitHub-provided SHA-256 digest, archive structure, bundle identity/version, and code signature, then stops transmission, installs, and reopens. Clicking Download and install starts the update directly, with no extra confirmation or download window. A single menu status row shows progress. An active, ready transmission is restored after updating when saved credentials and microphone authorization remain available; an already-stopped session stays stopped. There is no Terminal or local compilation involved. Downloads and validation leave existing transmission running; quitting the app before installation cancels the update. Only installation at `~/Applications/Stan Mic Bridge.app` is supported.

Starting in 1.3.1, restoring transmission after an update is the default and has no checkbox. The decision uses the actual state at installation handoff: transmission must still be active with a ready receiver. Stopping during download prevents restoration; a session still connecting, retrying, or awaiting permission does not qualify. The request applies only to that update launch, requires saved connection credentials and existing microphone authorization, and is consumed once. Normal relaunch, login, and crash recovery remain stopped. If macOS requires microphone authorization again, the app stays stopped and asks you to use Start. The old version controls the update into 1.3.1, so its previous resume setting still governs that one transition.

An independent helper waits for the old app to exit, preserves its bundle as a backup, and verifies that the new app reaches its UI startup checkpoint. Replacement and startup failures trigger restoration where safe; if an unresponsive new process cannot be stopped, the helper leaves the backup intact and explains how to restore it instead of modifying a running app. Startup readiness does not prove microphone or network functionality. Connection credentials remain in Keychain. With fixed local signing enabled, the updater also uses the local signing identity in Keychain; it does not rewrite the connection credentials.

Versions before 1.2.0 need one manual upgrade (Finder replacement or source installer) before in-app installation is available. There are no scheduled checks or silent installations. Automatic restoration after an update requires the conditions above. Missing or invalid release assets are refused rather than installed.

**Recovery from the 1.2.0–1.2.2 symbolic-link error:** those versions' installed update helper can mistake macOS's normal `/var` alias for an unsafe installation path. The failure occurs before replacing the installed app. Install 1.2.3 or newer once through the source installer or manual app replacement to activate the repaired helper; retrying the old in-app updater cannot replace that helper. Version 1.2.3 canonicalizes only OS-provided home/temp anchors and still rejects symbolic links within the installation and staging directories.

### Signing identity and repeated permission prompts

Public release packages use ad-hoc signing. Their designated requirements are tied to a particular build, so updates can cause macOS to ask again for microphone or Keychain access. An auto-resume preference cannot grant those permissions.

A paid Developer ID is not required for the optional fixed local signing mode introduced in 1.3.0. After quitting the running app, use the source installer once:

```bash
bash mac/install.command --local-signing
```

This creates or reuses a persistent self-signed code-signing identity on this Mac and signs the new app before installation. The private key stays in this Mac's Keychain; only a public certificate fingerprint is saved in the app's local configuration. The first transition from ad-hoc signing can require microphone and Keychain approval again. Fixed local signing does not guarantee Keychain approval survives later updates: macOS can use a per-build code hash as an additional Keychain partition check for self-signed apps, independently of the stable designated requirement. Selecting Always Allow can therefore apply to that build without covering the next one. See Apple's [partition identity selection](https://github.com/apple-oss-distributions/Security/blob/main/securityd/src/clientid.cpp) and [additional partition validation](https://github.com/apple-oss-distributions/Security/blob/main/securityd/src/acls.cpp). Do not delete the signing identity or its configuration between updates.

When enabled, future in-app updates still validate the original release download, then locally sign the app and helper with the same pinned identity and check designated-requirement continuity before installation. Missing keys or identity mismatches stop the update instead of silently reverting to ad-hoc signing. The menu displays local signing status. This is personal-use signing, not Developer ID notarization; it does not disable Gatekeeper or change microphone privacy settings. Permission retention must still be confirmed across updates on the target Mac, especially after migration or OS policy changes.

Use the in-app updater or the source installer to preserve this identity. Replacing the app directly with the public ad-hoc ZIP loses the local signature and can cause another permission prompt.

If Keychain is locked or signing authorization was cancelled, unlock it and retry. If the original signing key or configuration was lost, restore the original data; rerunning the installer does not recreate the same private key. Changing to a new identity would be a separate recovery action and can require permission again. The updater never rotates identities automatically.

References: [Apple TN2206: Code signing in depth](https://developer.apple.com/library/archive/technotes/tn2206/) and [Apple TN3127: Code signing requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements).

### Audio diagnostics

**音訊狀態…** (Audio status) displays local session counters to compare captured, converted, sent, and discarded audio frames. It does not record audio, persist speech, or include connection credentials. These counters help identify missing audio; they are not a speech-recognition accuracy score. The transport uses uncompressed 48 kHz mono float32 PCM. Different microphones, source processing, network jitter, and queue starvation can affect the result heard by a Windows dictation app.

## Browser alternative

Open the same private pairing link in a microphone-capable browser, press Start, and keep that tab open. The browser stores its token only in page memory, so a reload may require the link again. The native app uses Keychain and does not need Chrome.

## Recovery and limitations

- Native transport failures retry with capped backoff; Stop cancels retries. Audio is not queued indefinitely during outages.
- The receiver restores defaults after disconnect or roughly eight seconds without audio. A restoration journal is used after a receiver crash; it is applied on the next receiver start.
- A different microphone manually selected during a session is preserved when restoring.
- All three Windows default capture roles change while forwarding. Some applications cache their device and need recording restarted.
- The native sender currently has no acoustic echo cancellation or noise suppression. Headphones help prevent the remote speaker output from re-entering the microphone.
- Mac UI is currently Traditional Chinese. Prebuilt binaries are ad-hoc signed, not Developer ID notarized.
- Devices producing very large audio batches can lose older samples under the low-latency queue limit.

## Verification

The original deployment passed synthetic Windows virtual-audio round trips and microphone-role restoration checks. The author also reported successful native Mac installation/use. Hardware combinations, Mac login startup, and native sleep/wake behavior are not comprehensively tested.

Lightweight checks (Node.js is needed only for the browser simulation):

```text
python -m unittest discover -s tests -p "test_*.py"
node tests/sender-recovery.cjs
bash -n mac/install.command
```

`verify_audio.py` and `verify_routes.py` are opt-in Windows integration checks. They require a running configured receiver and VB-CABLE, send synthetic audio, and temporarily change microphone defaults. Do not run them during a live session. To verify the actual experience, dictate with Chrome closed, Stop, then Start and dictate another sentence; a connection indicator alone is not proof of audio delivery.

## Security and protocol

TLS is provided by Tailscale Serve. The receiver requires an exact Origin and a random bearer token supplied in the WebSocket URL. Authentication happens before any audio device is opened. There is one active sender, a message-size bound, and finite-sample validation. Native credentials are stored in Keychain; no token is bundled in source. The sender uses normal system TLS validation and refuses redirects.

The first WebSocket message is JSON `{"sampleRate":48000}` (the receiver also accepts 44100 for browsers). After `{"ready":true}`, send binary mono IEEE-754 little-endian Float32 PCM. The native app uses 1024-frame chunks. The receiver can log operational timestamps, frame counters, and error categories, but disables request access logs and does not save audio.

MIT licensed. VB-CABLE, Tailscale, and any dictation software are separate products with their own terms; no affiliation is implied.
