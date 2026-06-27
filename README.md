# Tunnely

A standalone WireGuard VPN client for Android with automated MTU discovery, flow monitoring, and modern Material3 dark theme.

## Features

- **One-tap Connect**: Automatically probes MTU and establishes VPN connection
- **Flow Monitoring**: Real-time per-flow traffic data when connected
- **Split Tunneling**: Choose which apps use the VPN
- **Auto Configuration**: Register with server API to get VPN config automatically
- **Curve25519 Keys**: Pure Java key generation (RFC 7748)
- **Modern UI**: GitHub-inspired dark theme with Material3 components

## Architecture

Single-activity app with 3 bottom tabs:

1. **Connect**: Main screen with status indicator, server/client info, and connect button
2. **Flows**: Per-flow traffic monitoring with sorting options
3. **Settings**: Server config, DNS, MTU, split tunneling, allowed IPs

## Dependencies

- WireGuard Android: `com.wireguard.android:tunnel:1.0.20260102`
- Material3: `com.google.android.material:material:1.12.0`
- OkHttp: `com.squareup.okhttp3:okhttp:4.12.0`
- AndroidX Lifecycle, Coroutines

## Build

```bash
cd android
./gradlew assembleDebug
```

## Configuration

Default server: `osig.aksa.ai:51820`

### API Endpoints

- `POST /api/vpn/register` - Register client public key
- `GET /api/vpn/traffic/client/{ip}` - Get traffic data

## Project Structure

```
tunnely/
├── android/
│   ├── app/
│   │   ├── build.gradle.kts
│   │   ├── proguard-rules.pro
│   │   └── src/main/
│   │       ├── AndroidManifest.xml
│   │       ├── kotlin/com/tunnely/app/
│   │       │   ├── MainActivity.kt
│   │       │   ├── TunnelyApp.kt
│   │       │   ├── api/
│   │       │   │   └── ApiClient.kt
│   │       │   ├── ui/
│   │       │   │   ├── ConnectFragment.kt
│   │       │   │   ├── FlowsFragment.kt
│   │       │   │   ├── SettingsFragment.kt
│   │       │   │   └── FlowAdapter.kt
│   │       │   └── vpn/
│   │       │       ├── Curve25519.kt
│   │       │       ├── FlowMonitor.kt
│   │       │       ├── MtuProber.kt
│   │       │       ├── TunnelyVpnService.kt
│   │       │       └── VpnPreferences.kt
│   │       └── res/
│   │           ├── drawable/
│   │           ├── layout/
│   │           ├── menu/
│   │           ├── values/
│   │           └── color/
│   ├── build.gradle.kts
│   ├── settings.gradle.kts
│   ├── gradle.properties
│   └── gradle/wrapper/
└── README.md
```

## Color Scheme

- Background: `#0D1117` (GitHub dark)
- Cards: `#161B22` with border `#30363D`
- Primary: `#58A6FF` (blue)
- Connected: `#3FB950` (green)
- Disconnected: `#F85149` (red)

## License

MIT
