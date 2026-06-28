#!/usr/bin/env python3
"""Tunnely VPN App Test Script using Appium"""

import json
import time
import requests

APPIUM_URL = "http://127.0.0.1:4723"

def create_session():
    """Create Appium session for Tunnely app"""
    caps = {
        "platformName": "Android",
        "appium:automationName": "UiAutomator2",
        "appium:deviceName": "emulator-5554",
        "appium:appPackage": "com.tunnely.app",
        "appium:appActivity": ".MainActivity",
        "appium:noReset": True,
        "appium:autoGrantPermissions": True,
        "appium:newCommandTimeout": 300
    }
    resp = requests.post(f"{APPIUM_URL}/session", json={"capabilities": {"firstMatch": [caps]}})
    session_id = resp.json()["value"]["sessionId"]
    print(f"Session created: {session_id}")
    return session_id

def find_element(session_id, strategy, value):
    """Find element"""
    resp = requests.post(f"{APPIUM_URL}/session/{session_id}/element", 
        json={"using": strategy, "value": value})
    result = resp.json()
    if "value" in result and result["value"]:
        return result["value"]
    return None

def click_element(session_id, element_id):
    """Click element"""
    requests.post(f"{APPIUM_URL}/session/{session_id}/element/{element_id}/click")

def get_text(session_id, element_id):
    """Get element text"""
    resp = requests.get(f"{APPIUM_URL}/session/{session_id}/element/{element_id}/text")
    return resp.json()["value"]

def get_page_source(session_id):
    """Get page source"""
    resp = requests.get(f"{APPIUM_URL}/session/{session_id}/source")
    return resp.json()["value"]

def take_screenshot(session_id, path):
    """Take screenshot"""
    resp = requests.get(f"{APPIUM_URL}/session/{session_id}/screenshot")
    import base64
    with open(path, "wb") as f:
        f.write(base64.b64decode(resp.json()["value"]))
    print(f"Screenshot: {path}")

def wait_for_element(session_id, strategy, value, timeout=30):
    """Wait for element to appear"""
    for i in range(timeout):
        elem = find_element(session_id, strategy, value)
        if elem:
            return elem
        time.sleep(1)
    return None

def delete_session(session_id):
    """Delete session"""
    requests.delete(f"{APPIUM_URL}/session/{session_id}")
    print("Session deleted")

def main():
    print("=== Tunnely VPN Test ===")
    
    # Create session
    session_id = create_session()
    time.sleep(3)
    
    # Take initial screenshot
    take_screenshot(session_id, "/tmp/appium_01_launch.png")
    
    # Get page source to understand UI
    source = get_page_source(session_id)
    print(f"Page source length: {len(source)}")
    
    # Find and click CONNECT button
    print("\n--- Looking for CONNECT button ---")
    connect_btn = find_element(session_id, "xpath", "//android.widget.Button[@text='CONNECT']")
    if connect_btn:
        print("CONNECT button found!")
        click_element(session_id, connect_btn)
        print("Clicked CONNECT")
        time.sleep(3)
    else:
        print("CONNECT button not found, trying xpath with contains...")
        connect_btn = find_element(session_id, "xpath", "//*[contains(@text, 'CONNECT')]")
        if connect_btn:
            click_element(session_id, connect_btn)
            print("Clicked CONNECT (contains)")
            time.sleep(3)
    
    # Check for VPN permission dialog
    print("\n--- Checking for VPN permission dialog ---")
    take_screenshot(session_id, "/tmp/appium_02_after_connect.png")
    
    ok_btn = find_element(session_id, "xpath", "//android.widget.Button[@text='OK']")
    if ok_btn:
        print("VPN permission dialog found! Clicking OK...")
        click_element(session_id, ok_btn)
        time.sleep(10)
        take_screenshot(session_id, "/tmp/appium_03_after_ok.png")
    else:
        allow_btn = find_element(session_id, "xpath", "//android.widget.Button[@text='Allow']")
        if allow_btn:
            print("Allow button found! Clicking...")
            click_element(session_id, allow_btn)
            time.sleep(10)
        else:
            print("No permission dialog found")
    
    # Check connection status
    print("\n--- Checking connection status ---")
    time.sleep(5)
    
    source = get_page_source(session_id)
    
    # Look for status indicators
    connected = find_element(session_id, "xpath", "//*[contains(@text, 'Connected')]")
    handshake = find_element(session_id, "xpath", "//*[contains(@text, 'handshake')]")
    disconnect = find_element(session_id, "xpath", "//*[contains(@text, 'DISCONNECT')]")
    
    if connected:
        text = get_text(session_id, connected)
        print(f"Status: {text}")
    
    if handshake:
        text = get_text(session_id, handshake)
        print(f"Handshake: {text}")
    
    if disconnect:
        print("DISCONNECT button visible — VPN connected!")
    
    take_screenshot(session_id, "/tmp/appium_04_status.png")
    
    # Wait and check again
    print("\n--- Waiting 15s for handshake ---")
    time.sleep(15)
    
    source = get_page_source(session_id)
    if "Connected" in source and "handshake" not in source.lower():
        print("✅ VPN CONNECTED! Handshake completed!")
    elif "handshake" in source.lower():
        print("⏳ Still waiting for handshake...")
    elif "Disconnected" in source:
        print("❌ Disconnected — connection failed")
    
    take_screenshot(session_id, "/tmp/appium_05_final.png")
    
    # Check logcat via adb
    print("\n--- Checking logcat ---")
    import subprocess
    result = subprocess.run(["adb", "logcat", "-d", "-t", "50"], capture_output=True, text=True)
    tunnely_logs = [l for l in result.stdout.split("\n") if "tunnely" in l.lower() or "wireguard" in l.lower() or "gobackend" in l.lower()]
    for log in tunnely_logs[-10:]:
        print(f"  {log}")
    
    # Cleanup
    print("\n--- Cleanup ---")
    delete_session(session_id)
    
    print("\n=== Test Complete ===")

if __name__ == "__main__":
    main()
