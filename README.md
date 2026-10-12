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
- Manually check GitHub releases from the menu, then choose whether to open the update instructions.
- Convert microphone audio to 48 kHz mono Float32 with bounded buffering.
- Switch Windows default microphone roles on first audio, then restore them when the session ends.
- Browser sender included as an alternative; its tab must remain open.
- No audio files or transcripts recorded by the bridge. Your dictation application's own data policy still applies.

## Requirements

**Mac:** macOS 12+, Apple Command Line Tools (`xcode-select --install`), and Tailscale. The installer builds for the Mac's current architecture; it does not download a prebuilt binary.

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

Clone or download this repository on your Mac, then run:

```bash
bash mac/install.command
```

The installer builds with Apple Swift, locally signs the app, and installs `~/Applications/Stan Mic Bridge.app`. It preserves an older installation as a dated backup and asks you to quit a running copy before upgrading. No Homebrew or third-party Mac runtime is needed. A rebuilt app may prompt again for microphone or Keychain access.

The app checks the existing microphone authorization before starting. It requests access only when the system reports that permission has not been decided; an already-authorized Start goes directly to connection. Login startup, microphone permission, and Keychain access are separate settings. Stopping and starting the same installation should reuse its permission. Because this installer uses ad-hoc signing, a rebuilt version has a different code identity and macOS may ask again after an upgrade. This does not mean every Start requires approval. [Apple's code-signing requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements).

The icon is generated reproducibly from `mac/GenerateIcon.swift` using AppKit and packaged as `AppIcon.icns` before signing. No external image download is required.

1. Click **Mic** in the menu bar and choose **設定連線…** (Configure connection).
2. Paste your private `https://…/#token=…` link and save it in Keychain.
3. Choose **開始傳送** (Start) and allow microphone access.
4. In Windows, use an app that follows the default microphone. For Typeless, choose automatic microphone detection and disable its option to mute other audio during dictation.
5. Close Chrome and dictate a sentence to confirm actual delivery.

Choose **停止傳送** (Stop) to stop recording and restore Windows microphone defaults, or quit the app. Only one sender may connect at a time; stop a browser sender before using the native app.

### Open automatically after Mac login

In **System Settings → General → Login Items** (or **Login Items & Extensions**), add `~/Applications/Stan Mic Bridge.app` to **Open at Login**. In the file picker, press Command+Shift+G and enter `~/Applications` if needed. On macOS Monterey, use **System Preferences → Users & Groups → Login Items** instead. [Apple's instructions](https://support.apple.com/guide/mac-help/open-items-automatically-when-you-log-in-mh15189/mac).

This opens the menu bar app after login. **Each new launch starts stopped; click Start to transmit.** It does not enable unattended recording. An enabled session can reconnect after sleep/wake, but the Mac cannot send while asleep or powered off.

### Check for updates

Choose **檢查更新…** (Check for updates) in the Mic menu. The app contacts this project's public GitHub Releases API only when clicked, compares the latest stable version, and displays its release notes. Checking does not stop recording and does not send your microphone connection credentials to GitHub.

For a newer version, choose **查看更新與安裝** to open its release page. Download `StanMicBridge-source.zip`, quit the existing app, extract the archive, and run `bash StanMicBridge/install.command` from the extracted parent folder. Installation is manual; the app never downloads or executes an updater in the background. The installer preserves an older app as a backup and keeps the same bundle identifier and Keychain service. Your saved connection stays in Keychain, though macOS can ask you to authorize access again after rebuilding.

Version 1.0.0 has no update menu, so upgrade it once with the release installer. There are no scheduled checks, silent installations, or automatic recording after updates.

## Browser alternative

Open the same private pairing link in a microphone-capable browser, press Start, and keep that tab open. The browser stores its token only in page memory, so a reload may require the link again. The native app uses Keychain and does not need Chrome.

## Recovery and limitations

- Native transport failures retry with capped backoff; Stop cancels retries. Audio is not queued indefinitely during outages.
- The receiver restores defaults after disconnect or roughly eight seconds without audio. A restoration journal is used after a receiver crash; it is applied on the next receiver start.
- A different microphone manually selected during a session is preserved when restoring.
- All three Windows default capture roles change while forwarding. Some applications cache their device and need recording restarted.
- The native sender currently has no acoustic echo cancellation or noise suppression. Headphones help prevent the remote speaker output from re-entering the microphone.
- Mac UI is currently Traditional Chinese. There is no notarized binary; updates use a source installer and Apple Command Line Tools.
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
