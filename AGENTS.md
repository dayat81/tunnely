# Tunnely — CODER Agent

## Project
WireGuard VPN client for Android. Kotlin + Material3. Package: `com.tunnely.app`.

## Repo layout
- `android/app/src/main/kotlin/com/tunnely/app/` — Kotlin source
  - `vpn/TunnelyVpnService.kt` — foreground service managing VPN lifecycle
  - `vpn/MtuProber.kt`, `FlowMonitor.kt`, `Curve25519.kt` — VPN utilities
  - `ui/ConnectFragment.kt` — main connect screen
  - `api/ApiClient.kt` — server API client
  - `MainActivity.kt` — single activity, bottom nav
- `android/app/src/main/AndroidManifest.xml` — manifest (permissions, services)
- `android/app/build.gradle.kts` — version: `versionCode`/`versionName`

## Build
```bash
cd ~/tunnely/android
./gradlew assembleDebug
# APK output: app/build/outputs/apk/debug/app-debug.apk
```

## WireGuard
- Uses `com.wireguard.android:tunnel` library (GoBackend)
- `GoBackend$VpnService` (wireguard) handles actual VPN
- `TunnelyVpnService` is our foreground wrapper

## Known issues (history)
- v1.x: startForeground() missing type → use `FOREGROUND_SERVICE_SPECIAL_USE`
- v1.3.x: VPN permission not requested → need `VpnService.prepare()` flow
- Always bump versionCode + versionName before release

## Release workflow
1. Edit `build.gradle.kts`: bump versionCode +1, versionName (semver)
2. `./gradlew assembleDebug`
3. `git add -A && git commit -m "fix: <desc> (vX.Y.Z)" && git tag vX.Y.Z`
4. `git push && git push --tags`
5. `gh release create vX.Y.Z app/build/outputs/apk/debug/app-debug.apk --repo dayat81/tunnely --title "vX.Y.Z" --notes "<what changed>"`
6. `gh issue comment <num> --repo dayat81/tunnely --body "Fixed in vX.Y.Z. Download: <release url>"`

## Conventions
- Minimal diffs. Don't refactor unrelated code.
- Kotlin idiom: use coroutine scopes, lifecycle-aware.
- Comments only when logic is non-obvious.
- Commit messages: `fix:`/`feat:`/`chore:` prefix.

## Agent mode
You are triggered by a cron job when the tester posts new test results.
Read the injected test report, fix root cause, build, release, notify.
Be terse in responses — save tokens.
