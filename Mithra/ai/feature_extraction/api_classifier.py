# =========================
# Security API Categories
# =========================

CATEGORIES = {

    "NETWORK": [
        "Socket",
        "URLConnection",
        "HttpURLConnection",
        "OkHttp",
        "URL",
        "InetAddress",
        "ServerSocket",
        "DatagramSocket"
    ],

    "CRYPTO": [
        "Cipher",
        "MessageDigest",
        "Mac",
        "KeyGenerator",
        "SecretKey",
        "Signature",
        "SecureRandom"
    ],

    "FILE": [
        "File",
        "FileInputStream",
        "FileOutputStream",
        "BufferedInputStream",
        "BufferedOutputStream",
        "InputStream",
        "OutputStream"
    ],

    "DATABASE": [
        "SQLiteDatabase",
        "SQLiteOpenHelper",
        "Cursor"
    ],

    "WEBVIEW": [
        "WebView",
        "WebSettings",
        "JavascriptInterface"
    ],

    "SMS": [
        "SmsManager",
        "Telephony"
    ],

    "LOCATION": [
        "LocationManager",
        "FusedLocation",
        "Geocoder"
    ],

    "CAMERA": [
        "Camera",
        "CameraManager",
        "CameraDevice"
    ],

    "CONTACTS": [
        "ContactsContract"
    ],

    "MICROPHONE": [
        "MediaRecorder",
        "AudioRecord"
    ],

    "BLUETOOTH": [
        "BluetoothAdapter",
        "BluetoothDevice"
    ],

    "WIFI": [
        "WifiManager",
        "WifiInfo"
    ],

    "NOTIFICATION": [
        "NotificationManager",
        "NotificationCompat"
    ],

    "CLIPBOARD": [
        "ClipboardManager"
    ],

    "REFLECTION": [
        "Class.forName",
        "Method.invoke",
        "Field",
        "Constructor"
    ],

    "DYNAMIC_LOADING": [
        "DexClassLoader",
        "PathClassLoader"
    ],

    "RUNTIME": [
        "Runtime.exec",
        "ProcessBuilder"
    ],

    "NATIVE": [
        "System.loadLibrary",
        "JNI"
    ],

    "ACCESSIBILITY": [
        "AccessibilityService"
    ],

    "BIOMETRIC": [
        "BiometricPrompt",
        "FingerprintManager"
    ]
}


def classify_api(api: str):

    api = api.lower()

    for category, keywords in CATEGORIES.items():

        for keyword in keywords:

            if keyword.lower() in api:
                return category

    return "OTHER"