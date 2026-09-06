"""Behavior catalogue: static evidence signatures for each behavior.

Every behavior is described by :class:`BehaviorSpec`, which lists the *direct*
evidence the engine looks for:

    call_prefixes   method-reference prefixes (``Lclass;->name``, signature
                    stripped) that are direct bytecode evidence of the behavior
    class_prefixes  class/package markers (e.g. dexclassloader usage sites)
    strings         exact string literals whose presence (usually combined with
                    a `call`) implies the behavior
    permissions     Android permissions that *permit* the behavior -- presence
                    alone never proves it (that would force UNKNOWN -> TRUE)

The engine additionally links :class:`~re_engine.dataflow.models.DataFlowFinding`
whose source label appears in ``dataflow_sources`` into
``related_data_flows``, so "collected data reached a sink" is traceable inside
the behavior claim.

Static, deterministic, no classifiers, no LLMs: matching is prefix/`in`-only
over directly observed bytecode/manifest surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Common Android permission constants
# ---------------------------------------------------------------------------
PERM_RECEIVE_BOOT = "android.permission.RECEIVE_BOOT_COMPLETED"
PERM_FOREGROUND_SERVICE = "android.permission.FOREGROUND_SERVICE"
PERM_JOB = "android.permission.BIND_JOB_SERVICE"
PERM_READ_SMS = "android.permission.READ_SMS"
PERM_RECV_SMS = "android.permission.RECEIVE_SMS"
PERM_READ_CONTACTS = "android.permission.READ_CONTACTS"
PERM_READ_CALL_LOG = "android.permission.READ_CALL_LOG"
PERM_LOCATION = (
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
)
PERM_PHONE_STATE = "android.permission.READ_PHONE_STATE"
PERM_STORAGE = (
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
)
PERM_RECORD_AUDIO = "android.permission.RECORD_AUDIO"
PERM_CAMERA = "android.permission.CAMERA"
PERM_PACKAGE_USAGE = "android.permission.PACKAGE_USAGE_STATS"


# ---------------------------------------------------------------------------
# Behavior specification
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class BehaviorSpec:
    """Static evidence signature + metadata for one behavior."""

    key: str
    category: str
    name: str
    description: str
    permissions: Tuple[str, ...] = ()
    call_prefixes: Tuple[str, ...] = ()
    field_prefixes: Tuple[str, ...] = ()
    class_prefixes: Tuple[str, ...] = ()
    strings: Tuple[str, ...] = ()
    dataflow_sources: Tuple[str, ...] = ()
    permission_implies_unknown: bool = True


BEHAVIORS: List[BehaviorSpec] = [
    # ------------------------------------------------------------------
    # PERSISTENCE
    # ------------------------------------------------------------------
    BehaviorSpec(
        "persistence.boot_completion",
        "persistence",
        "Boot completion handler",
        "A component runs when the device finishes booting (BOOT_COMPLETED).",
        (PERM_RECEIVE_BOOT,),
        dataflow_sources=(),
    ),
    BehaviorSpec(
        "persistence.foreground_service",
        "persistence",
        "Foreground service",
        "A service is started in the foreground with a persistent notification.",
        (PERM_FOREGROUND_SERVICE,),
        call_prefixes=("Landroid/app/Service;->startForeground",),
    ),
    BehaviorSpec(
        "persistence.background_service",
        "persistence",
        "Background service",
        "A service component is declared to run work without user interaction.",
        (),
    ),
    BehaviorSpec(
        "persistence.scheduled_jobs",
        "persistence",
        "Scheduled jobs",
        "Work is scheduled through the Android job scheduler for later execution.",
        (PERM_JOB,),
        call_prefixes=(
            "Landroid/app/job/JobInfo$Builder;->",
            "Landroid/app/job/JobScheduler;->schedule",
            "Landroid/app/job/JobService;->onStartJob",
        ),
    ),
    BehaviorSpec(
        "persistence.alarms",
        "persistence",
        "Alarm scheduling",
        "AlarmManager schedules one-shot or repeating alarms.",
        call_prefixes=(
            "Landroid/app/AlarmManager;->set",
            "Landroid/app/AlarmManager;->scheduleExactAlarm",
            "Landroid/app/AlarmManager;->setRepeating",
            "Landroid/app/AlarmManager;->setInexactRepeating",
            "Landroid/app/AlarmManager;->setWindow",
        ),
    ),
    BehaviorSpec(
        "persistence.device_admin",
        "persistence",
        "Device administrator",
        "The app can claim device-administrator privileges (lock / wipe / policy).",
        ("android.permission.BIND_DEVICE_ADMIN",),
        call_prefixes=(
            "Landroid/app/admin/DevicePolicyManager;->",
            "Landroid/app/admin/DeviceAdminReceiver;->",
        ),
    ),
    BehaviorSpec(
        "persistence.accessibility",
        "persistence",
        "Accessibility service",
        "An accessibility service is declared, giving access to screen content "
        "and UI events.",
        ("android.permission.BIND_ACCESSIBILITY_SERVICE",),
        call_prefixes=(
            "Landroid/accessibilityservice/AccessibilityService;->onAccessibilityEvent",
            "Landroid/view/accessibility/AccessibilityEvent;->getText",
            "Landroid/view/accessibility/AccessibilityNodeInfo;->getText",
        ),
    ),
    # ------------------------------------------------------------------
    # DATA COLLECTION
    # ------------------------------------------------------------------
    BehaviorSpec(
        "collection.sms",
        "data_collection",
        "SMS collection",
        "SMS messages or message bodies are read into the app.",
        (PERM_READ_SMS, PERM_RECV_SMS),
        call_prefixes=(
            "Landroid/telephony/SmsMessage;->getMessageBody",
            "Landroid/telephony/SmsMessage;->getOriginatingAddress",
            "Landroid/telephony/SmsManager;->getAllMessagesFromIcc",
            "Landroid/provider/Telephony$Sms;->",
        ),
        dataflow_sources=("sms",),
    ),
    BehaviorSpec(
        "collection.contacts",
        "data_collection",
        "Contact collection",
        "The device contacts database is read.",
        (PERM_READ_CONTACTS,),
        call_prefixes=(
            "Landroid/provider/ContactsContract$",
            "Landroid/provider/ContactsContract;->",
        ),
        class_prefixes=("Landroid/provider/ContactsContract",),
        field_prefixes=("Landroid/provider/ContactsContract",),
        strings=("content://com.android.contacts",),
        dataflow_sources=("contacts",),
    ),
    BehaviorSpec(
        "collection.call_log",
        "data_collection",
        "Call log collection",
        "The device call log is read.",
        (PERM_READ_CALL_LOG,),
        call_prefixes=("Landroid/provider/CallLog",),
        class_prefixes=("Landroid/provider/CallLog",),
        strings=("content://call_log",),
        dataflow_sources=("call_log",),
    ),
    BehaviorSpec(
        "collection.location",
        "data_collection",
        "Location collection",
        "GPS / network location is requested or read.",
        PERM_LOCATION,
        call_prefixes=(
            "Landroid/location/LocationManager;->requestLocationUpdates",
            "Landroid/location/LocationManager;->getLastKnownLocation",
            "Landroid/location/LocationManager;->getLastLocation",
            "Landroid/location/LocationManager;->registerGnssStatusCallback",
        ),
        dataflow_sources=("location",),
    ),
    BehaviorSpec(
        "collection.device_identifiers",
        "data_collection",
        "Device identifier collection",
        "Device identifiers (IMEI / MEID / serial / subscriber id) are read.",
        (PERM_PHONE_STATE,),
        call_prefixes=(
            "Landroid/telephony/TelephonyManager;->getDeviceId",
            "Landroid/telephony/TelephonyManager;->getImei",
            "Landroid/telephony/TelephonyManager;->getMeid",
            "Landroid/telephony/TelephonyManager;->getSubscriberId",
            "Landroid/telephony/TelephonyManager;->getLine1Number",
            "Landroid/telephony/TelephonyManager;->getSimSerialNumber",
        ),
        strings=(
            "android.os.Build.SERIAL",
            "ro.serialno",
            "ro.boot.serialno",
            "ro.product.device",
        ),
        field_prefixes=("Landroid/os/Build;->", "Landroid/os/Build$VERSION;->"),
        dataflow_sources=("device_id", "device_info"),
    ),
    BehaviorSpec(
        "collection.files",
        "data_collection",
        "File read",
        "Local files are read from app-private or shared storage.",
        PERM_STORAGE,
        call_prefixes=(
            "Ljava/io/FileInputStream;->",
            "Ljava/io/FileReader;->",
            "Ljava/io/BufferedReader;->",
            "Ljava/io/InputStreamReader;->",
            "Landroid/content/Context;->openFileInput",
            "Landroid/content/Context;->getAssets",
            "Ljava/nio/file/Files;->readAllBytes",
        ),
        dataflow_sources=("file_read",),
    ),
    BehaviorSpec(
        "collection.notifications",
        "data_collection",
        "Notification reading",
        "Active notifications or notification extras are read by the app.",
        (PERM_PACKAGE_USAGE,),
        call_prefixes=(
            "Landroid/service/notification/NotificationListenerService;->getActiveNotifications",
            "Landroid/service/notification/StatusBarNotification;->getNotification",
            "Landroid/app/NotificationManager;->getActiveNotifications",
        ),
    ),
    BehaviorSpec(
        "collection.clipboard",
        "data_collection",
        "Clipboard collection",
        "The shared clipboard is read.",
        (),
        call_prefixes=(
            "Landroid/content/ClipboardManager;->getPrimaryClip",
            "Landroid/content/ClipboardManager;->getText",
            "Landroid/content/ClipData;->getItemAt",
            "Landroid/content/ClipData$Item;->getText",
        ),
        dataflow_sources=("clipboard",),
    ),
    BehaviorSpec(
        "collection.microphone",
        "data_collection",
        "Microphone recording",
        "Audio is recorded from the microphone.",
        (PERM_RECORD_AUDIO,),
        call_prefixes=(
            "Landroid/media/AudioRecord;->read",
            "Landroid/media/AudioRecord;->startRecording",
            "Landroid/media/MediaRecorder;->start",
        ),
        dataflow_sources=("audio",),
    ),
    BehaviorSpec(
        "collection.camera",
        "data_collection",
        "Camera recording",
        "The camera is opened / frames are captured in the background.",
        (PERM_CAMERA,),
        call_prefixes=(
            "Landroid/hardware/Camera;->open",
            "Landroid/hardware/Camera;->startPreview",
            "Landroid/hardware/Camera;->takePicture",
            "Landroid/hardware/camera2/CameraDevice;->",
            "Landroid/hardware/camera2/CameraCaptureSession;->capture",
        ),
        class_prefixes=("Landroid/hardware/camera2/",),
        dataflow_sources=("camera",),
    ),
    # ------------------------------------------------------------------
    # COMMAND EXECUTION
    # ------------------------------------------------------------------
    BehaviorSpec(
        "execution.command",
        "command_execution",
        "Command execution",
        "Shell commands / external processes are executed via Runtime or "
        "ProcessBuilder.",
        (),
        call_prefixes=(
            "Ljava/lang/Runtime;->exec",
            "Ljava/lang/ProcessBuilder;->start",
            "Ljava/lang/ProcessBuilder;->command",
        ),
    ),
    BehaviorSpec(
        "execution.native",
        "command_execution",
        "Native code execution",
        "Native (JNI) code is loaded or declared.",
        (),
        call_prefixes=(
            "Ljava/lang/System;->loadLibrary",
            "Ljava/lang/Runtime;->loadLibrary",
            "Ljava/lang/System;->load",
        ),
    ),
    # ------------------------------------------------------------------
    # DYNAMIC BEHAVIOR
    # ------------------------------------------------------------------
    BehaviorSpec(
        "dynamic.reflection",
        "dynamic_behavior",
        "Reflection",
        "Java reflection is used to resolve and invoke classes/methods at "
        "runtime.",
        (),
        call_prefixes=(
            "Ljava/lang/Class;->forName",
            "Ljava/lang/Class;->getMethod",
            "Ljava/lang/Class;->getMethods",
            "Ljava/lang/reflect/Method;->invoke",
            "Ljava/lang/reflect/Constructor;->newInstance",
            "Ljava/lang/ClassLoader;->loadClass",
        ),
    ),
    BehaviorSpec(
        "dynamic.class_loading",
        "dynamic_behavior",
        "Dynamic class loading",
        "DEX bytecode is loaded at runtime from memory or a custom path.",
        (),
        call_prefixes=(
            "Ldalvik/system/DexClassLoader;-><init>",
            "Ldalvik/system/InMemoryDexClassLoader;-><init>",
            "Ldalvik/system/BaseDexClassLoader;-><init>",
        ),
    ),
    BehaviorSpec(
        "dynamic.encrypted_payload",
        "dynamic_behavior",
        "Encrypted payload loading",
        "A crypto routine decrypts data that is then loaded as executable code.",
        (),
        call_prefixes=(),
    ),
    BehaviorSpec(
        "dynamic.downloaded_code",
        "dynamic_behavior",
        "Downloaded code loading",
        "Code is fetched over the network and then loaded / executed.",
        (),
        call_prefixes=(),
    ),
    # ------------------------------------------------------------------
    # NETWORK
    # ------------------------------------------------------------------
    BehaviorSpec(
        "network.http",
        "network",
        "HTTP client",
        "The app talks cleartext HTTP.",
        ("android.permission.INTERNET",),
        call_prefixes=(
            "Lorg/apache/http/",
            "Lokhttp3/OkHttpClient",
            "Lcom/squareup/okhttp/OkHttpClient",
            "Lcom/squareup/okhttp3/OkHttpClient",
            "Ljava/net/HttpURLConnection",
            "Ljava/net/URL;->openConnection",
        ),
        dataflow_sources=(),
    ),
    BehaviorSpec(
        "network.https",
        "network",
        "HTTPS/TLS",
        "The app engages TLS (HttpsURLConnection, SSLContext, socket factories).",
        ("android.permission.INTERNET",),
        call_prefixes=(
            "Ljavax/net/ssl/HttpsURLConnection",
            "Ljavax/net/ssl/SSLContext;->",
            "Ljavax/net/ssl/SSLSocketFactory",
            "Ljavax/net/ssl/SSLEngine",
            "Lorg/apache/http/conn/ssl/",
        ),
    ),
    BehaviorSpec(
        "network.sockets",
        "network",
        "Raw sockets",
        "Raw TCP/UDP sockets are opened.",
        ("android.permission.INTERNET",),
        call_prefixes=(
            "Ljava/net/Socket;->",
            "Ljava/net/DatagramSocket;->",
            "Ljava/net/ServerSocket;->",
            "Ljava/net/SocketChannel;->",
            "Landroid/net/LocalSocket;->connect",
        ),
        dataflow_sources=(),
    ),
    BehaviorSpec(
        "network.websockets",
        "network",
        "WebSockets",
        "A WebSocket channel is used for bidirectional messaging.",
        ("android.permission.INTERNET",),
        call_prefixes=(
            "Lokhttp3/WebSocket",
            "Lcom/squareup/okhttp3/WebSocket",
            "Lio/socket/",
            "Lorg/java_websocket/",
            "Lcom/neovisionaries/ws/client/",
        ),
    ),
    BehaviorSpec(
        "network.dns",
        "network",
        "DNS / host resolution",
        "Hostnames are resolved or DNS is queried directly.",
        ("android.permission.INTERNET",),
        call_prefixes=(
            "Ljava/net/InetAddress;->getByName",
            "Ljava/net/InetAddress;->getAllByName",
            "Landroid/net/nsd/NsdManager;->",
            "Landroid/net/ConnectivityManager;->lookup",
        ),
    ),
    BehaviorSpec(
        "network.custom_protocol",
        "network",
        "Custom protocols",
        "Non-standard URI schemes are referenced (custom protocol framing).",
        ("android.permission.INTERNET",),
        strings=(),
    ),
    # ------------------------------------------------------------------
    # EVASION
    # ------------------------------------------------------------------
    BehaviorSpec(
        "evasion.emulator_detection",
        "evasion",
        "Emulator detection",
        "Runtime environment checks that commonly target emulators/sandboxes.",
        (),
        strings=(
            "goldfish",
            "qemu",
            "sdk_gphone",
            "ro.kernel.qemu",
            "/dev/goldfish_pipe",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "Android SDK built for x86",
        ),
        call_prefixes=("Ljava/lang/Runtime;->getRuntime",),
        field_prefixes=("Landroid/os/Build;->", "Landroid/os/Build$VERSION;->"),
        dataflow_sources=(),
    ),
    BehaviorSpec(
        "evasion.debugger_detection",
        "evasion",
        "Debugger detection",
        "The app checks whether it is being debugged.",
        (),
        call_prefixes=("Landroid/os/Debug;->isDebuggerConnected",),
    ),
    BehaviorSpec(
        "evasion.root_detection",
        "evasion",
        "Root detection",
        "The app probes for a rooted device (su binaries / superuser packages).",
        (),
        strings=(
            "/system/bin/su",
            "/system/xbin/su",
            "/system/app/Superuser.apk",
            "/sbin/su",
            "com.noshufou.android.su",
            "eu.chainfire.supersu",
            "which su",
        ),
        call_prefixes=("Ljava/lang/Runtime;->exec",),
    ),
    BehaviorSpec(
        "evasion.anti_analysis",
        "evasion",
        "Anti-analysis",
        "Multiple evasion techniques are combined (analysis-hostility).",
        (),
    ),
    BehaviorSpec(
        "evasion.certificate_pinning",
        "evasion",
        "Certificate pinning",
        "TLS peers are pinned to specific certificates / public keys.",
        (),
        call_prefixes=(
            "Ljavax/net/ssl/X509TrustManager",
            "Ljavax/net/ssl/X509Certificate",
            "Lokhttp3/CertificatePinner",
            "Lokhttp3/internal/tls/OkHostnameVerifier",
            "Lorg/apache/http/conn/ssl/SSLSocketFactory",
        ),
    ),
    BehaviorSpec(
        "evasion.string_encryption",
        "evasion",
        "String encryption",
        "String literals are stored encrypted/encoded and decoded at runtime.",
        (),
        call_prefixes=(
            "Landroid/util/Base64;->decode",
            "Ljavax/crypto/Cipher;->doFinal",
        ),
    ),
    BehaviorSpec(
        "evasion.control_flow_obfuscation",
        "evasion",
        "Control-flow obfuscation",
        "Extremely large methods suggest flattened/opaque control flow.",
        (),
    ),
    # ------------------------------------------------------------------
    # CRYPTOGRAPHY
    # ------------------------------------------------------------------
    BehaviorSpec(
        "crypto.encryption",
        "cryptography",
        "Encryption",
        "Data is encrypted (Cipher in ENCRYPT_MODE).",
        (),
        call_prefixes=("Ljavax/crypto/Cipher;->init", "Ljavax/crypto/Cipher;->doFinal"),
    ),
    BehaviorSpec(
        "crypto.decryption",
        "cryptography",
        "Decryption",
        "Data is decrypted (Cipher in DECRYPT_MODE).",
        (),
        call_prefixes=("Ljavax/crypto/Cipher;->init", "Ljavax/crypto/Cipher;->doFinal"),
    ),
    BehaviorSpec(
        "crypto.key_generation",
        "cryptography",
        "Key generation",
        "Cryptographic keys / key pairs are generated.",
        (),
        call_prefixes=(
            "Ljavax/crypto/KeyGenerator;->",
            "Ljava/security/KeyPairGenerator;->",
            "Landroid/security/keystore/KeyGenParameterSpec",
            "Ljavax/crypto/SecretKey",
        ),
    ),
    BehaviorSpec(
        "crypto.hashing",
        "cryptography",
        "Hashing",
        "Data is digested with a cryptographic hash.",
        (),
        call_prefixes=(
            "Ljava/security/MessageDigest;->digest",
            "Ljava/security/MessageDigest;->update",
            "Ljavax/crypto/Mac;->doFinal",
        ),
    ),
    BehaviorSpec(
        "crypto.encoding",
        "cryptography",
        "Encoding",
        "Binary data is encoded/decoded (Base64 / hex, URL encoding).",
        (),
        call_prefixes=(
            "Landroid/util/Base64;->encode",
            "Landroid/util/Base64;->decode",
            "Ljava/net/URLEncoder;->encode",
            "Ljava/net/URLDecoder;->decode",
        ),
    ),
]

# Deterministic lookup by behavior id.
BY_KEY: dict = {spec.key: spec for spec in BEHAVIORS}


def behaviors_in_order() -> List[BehaviorSpec]:
    """Everything in a stable (category, key) order."""
    return sorted(BEHAVIORS, key=lambda spec: (spec.category, spec.key))