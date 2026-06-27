# WireGuard
-keep class com.wireguard.** { *; }
-keep class com.wireguard.android.** { *; }
-dontwarn com.wireguard.**

# Tunnely
-keep class com.tunnely.app.vpn.** { *; }
-keep class com.tunnely.app.api.** { *; }

# Coroutines
-keepnames class kotlinx.coroutines.** { *; }
