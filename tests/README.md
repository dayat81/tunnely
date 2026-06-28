# Tunnely App Tests

## Setup
1. Install Appium: `npm install -g appium`
2. Install UiAutomator2 driver: `appium driver install uiautomator2`
3. Start Appium: `ANDROID_HOME=~/android-sdk appium --relaxed-security`
4. Run tests: `python3 test_tunnely.py`

## Prerequisites
- Android emulator running with Tunnely app installed
- `ANDROID_HOME` environment variable set
- ADB accessible in PATH
