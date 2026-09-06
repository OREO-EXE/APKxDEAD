"""Android source / sink / transformation / propagation specifications.

This module is the single source of truth for what the data-flow engine treats
as a *sensitive source*, a *sink*, a *data transformation* and a *propagator*.

Everything here is a **static, prefix-based pattern table** -- no machine
learning, no evaluation of runtime behavior. A prefix match against a method
reference (``Lclass;->name(desc)``) is deliberately conservative: it never
*claims* a flow by itself. The engine separately requires call/data-flow
evidence (tainted registers reaching the sink) before emitting a
:class:`DataFlowFinding`.

Why prefix matching?
    Android framework and popular-library class names are version-stable at
    their leading segments (``Landroid/telephony/SmsManager;``,
    ``Landroid/location/LocationManager;``). A prefix is far more robust than
    an exact string and, unlike a regex over an arbitrary class name, cannot
    accidentally trigger on ``$`` or other regex metacharacters that appear in
    real descriptors. Prefixes are matched with ``startswith``, never with a
    regular expression.

Design rules:

    * Every entry is a ``(match, label)`` pair. ``match`` is compared with
      ``str.startswith`` against a normalized method reference.
    * Matching is descending-specificity-first: the longest prefix that matches
      wins, so an exact-target rule can override a broad-class rule.
    * The same reference can match multiple categories (e.g. a source that is
      also a sink) -- the engine unions results and records both roles.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Sensitive sources (sensitive data enters the app here).
#
# Format: PREFIX -> human label. A method whose reference starts with prefix is
# treated as a source producing tainted data into its return register (or,
# for static accessors, a tainted container result).
# ---------------------------------------------------------------------------
SOURCE_PREFIXES: List[Tuple[str, str]] = [
    # --- SMS ---
    ("Landroid/telephony/SmsMessage;->createFromPdu", "sms"),
    ("Landroid/telephony/SmsMessage;->getMessageBody", "sms"),
    ("Landroid/telephony/SmsMessage;->getOriginatingAddress", "sms"),
    ("Landroid/telephony/SmsManager;->getAllMessagesFromIcc", "sms"),
    ("Landroid/provider/Telephony$Sms;->", "sms"),
    ("Landroid/provider/Telephony;->", "sms"),
    ("Landroid/content/ContentResolver;->query", "content_query"),
    # --- Contacts ---
    ("Landroid/provider/ContactsContract$", "contacts"),
    ("Landroid/provider/ContactsContract;->", "contacts"),
    # --- Call logs ---
    ("Landroid/provider/CallLog", "call_log"),
    # --- Device identifiers / IMEI ---
    ("Landroid/telephony/TelephonyManager;->getDeviceId", "device_id"),
    ("Landroid/telephony/TelephonyManager;->getImei", "device_id"),
    ("Landroid/telephony/TelephonyManager;->getMeid", "device_id"),
    ("Landroid/telephony/TelephonyManager;->getSubscriberId", "device_id"),
    ("Landroid/telephony/TelephonyManager;->getLine1Number", "device_id"),
    ("Landroid/telephony/TelephonyManager;->getSimSerialNumber", "device_id"),
    ("Landroid/os/Build;->", "device_info"),
    ("Landroid/os/Build$VERSION;->", "device_info"),
    ("Landroid/provider/Settings$Secure;->getString", "settings_secure"),
    # --- Location ---
    ("Landroid/location/LocationManager;->getLastKnownLocation", "location"),
    ("Landroid/location/LocationManager;->requestLocationUpdates", "location"),
    ("Landroid/location/LocationManager;->getLastLocation", "location"),
    ("Landroid/location/Location;", "location"),
    # --- Microphone ---
    ("Landroid/media/AudioRecord;->read", "audio"),
    ("Landroid/media/AudioRecord;->", "audio"),
    ("Landroid/media/MediaRecorder;->", "audio"),
    # --- Camera ---
    ("Landroid/hardware/Camera;->", "camera"),
    ("Landroid/hardware/camera2/", "camera"),
    # --- Clipboard ---
    ("Landroid/content/ClipboardManager;->getPrimaryClip", "clipboard"),
    ("Landroid/content/ClipData;->", "clipboard"),
    # --- Notifications (data read back from extras) ---
    ("Landroid/os/Bundle;->get", "bundle"),
    ("Landroid/os/Bundle;->", "bundle"),
    ("Landroid/content/SharedPreferences;->get", "preferences"),
    ("Landroid/content/Intent;->getStringExtra", "intent_extra"),
    ("Landroid/content/Intent;->getExtras", "intent_extra"),
    ("Landroid/content/Intent;->getData", "intent_extra"),
    # --- Accessibility (screen content) ---
    ("Landroid/accessibilityservice/AccessibilityService;->", "accessibility"),
    ("Landroid/view/accessibility/AccessibilityNodeInfo;->", "accessibility"),
    # --- Files ---
    ("Ljava/io/FileInputStream;->", "file_read"),
    ("Ljava/io/FileReader;->", "file_read"),
    ("Ljava/io/BufferedReader;->", "file_read"),
    ("Ljava/io/InputStreamReader;->", "file_read"),
    ("Landroid/content/Context;->openFileInput", "file_read"),
    ("Landroid/content/Context;->getAssets", "file_read"),
    # --- Credentials / tokens ---
    ("Landroid/webkit/CookieManager;->getCookie", "cookie"),
    ("Landroid/accounts/AccountManager;->getAccounts", "account"),
    ("Landroid/accounts/AccountManager;->getPassword", "credential"),
    ("Landroid/hardware/fingerprint/", "fingerprint"),
    ("Landroid/security/keystore/", "keystore"),
    # --- Broad / generic text-getter fallbacks (low specificity) ---
    ("Ljava/lang/Object;->toString", "object_string"),
]

# Ordered by descending prefix length so more specific rules win on overlap.
SOURCE_PREFIXES = sorted(
    SOURCE_PREFIXES, key=lambda entry: len(entry[0]), reverse=True
)

# --- URI authority substrings that mark a ContentResolver.query as a source of
# a particular sensitive category (contacts / call logs / sms). ---
URI_SOURCE_SUBSTRINGS: List[Tuple[str, str]] = [
    ("contacts", "contacts"),
    ("call_log", "call_log"),
    ("call_log/", "call_log"),
    ("sms", "sms"),
    ("telephony", "sms"),
]


# ---------------------------------------------------------------------------
# Sinks (sensitive data leaves the app here).
# Format: PREFIX -> label.
# ---------------------------------------------------------------------------
SINK_PREFIXES: List[Tuple[str, str]] = [
    # --- Network: HTTP ---
    ("Ljava/net/URL;->openConnection", "http"),
    ("Ljava/net/HttpURLConnection;->", "http"),
    ("Lorg/apache/http/", "http"),
    ("Lokhttp3/", "http"),
    ("Lcom/squareup/okhttp/", "http"),
    ("Landroid/net/http/", "http"),
    # --- Network: sockets ---
    ("Ljava/net/Socket;->", "socket"),
    ("Ljava/net/DatagramSocket;->", "socket"),
    # --- WebSockets ---
    ("Lokhttp3/WebSocket", "websocket"),
    ("Lcom/squareup/okhttp3/WebSocket", "websocket"),
    ("Lio/socket/", "websocket"),
    # --- Output streams (HTTP body / socket stream / file stream) ---
    ("Ljava/io/OutputStream;->write", "output_stream"),
    ("Ljava/net/HttpURLConnection;->getOutputStream", "output_stream"),
    ("Ljava/io/FileOutputStream;->", "file_stream"),
    # --- Files ---
    ("Ljava/io/FileWriter;->write", "file_write"),
    ("Ljava/io/FileOutputStream;->write", "file_stream"),
    ("Landroid/content/Context;->openFileOutput", "file_write"),
    ("Landroid/content/Context;->getCacheDir", "file_write"),
    ("Ljava/io/PrintWriter;->", "file_write"),
    # --- Databases ---
    ("Landroid/database/sqlite/SQLiteDatabase;->", "database"),
    ("Landroid/content/ContentProvider;->", "database"),
    ("Landroid/content/ContentResolver;->insert", "database"),
    ("Landroid/content/ContentResolver;->update", "database"),
    # --- Logs ---
    ("Landroid/util/Log;->", "log"),
    # --- SMS send ---
    ("Landroid/telephony/SmsManager;->sendTextMessage", "sms_send"),
    ("Landroid/telephony/SmsManager;->sendMultipartTextMessage", "sms_send"),
    ("Landroid/telephony/SmsMessage;->", "sms_send"),
    # --- Command execution ---
    ("Ljava/lang/Runtime;->exec", "exec"),
    ("Ljava/lang/ProcessBuilder;->", "exec"),
    # --- External intent ---
    ("Landroid/content/Context;->startActivity", "external_intent"),
    ("Landroid/app/Activity;->startActivity", "external_intent"),
    ("Landroid/content/Context;->startService", "external_intent"),
    ("Landroid/content/Context;->sendBroadcast", "external_intent"),
    ("Landroid/app/PendingIntent;->send", "external_intent"),
    # --- Native calls ---
    # Native sink is determined via the ``native`` access flag on the method
    # itself; the entries below additionally mark JNI-export style accessors.
    ("Ldalvik/system/", "native"),
    ("Lcom/google/android/jni/", "native"),
]

# Ordered by descending specificity.
SINK_PREFIXES = sorted(SINK_PREFIXES, key=lambda entry: len(entry[0]), reverse=True)


# ---------------------------------------------------------------------------
# Transformations (data reshaping applied between source and sink).
# Format: PREFIX -> transformation label.
# ---------------------------------------------------------------------------
TRANSFORM_PREFIXES: List[Tuple[str, str]] = [
    ("Landroid/util/Base64;->encode", "base64"),
    ("Landroid/util/Base64;->decode", "base64"),
    ("Ljava/lang/String;->getBytes", "bytes"),
    ("Ljava/lang/String;->toCharArray", "bytes"),
    ("Ljava/net/URLEncoder;->encode", "url_encode"),
    ("Ljava/net/URLDecoder;->decode", "url_decode"),
    ("Ljava/net/URL;->encode", "url_encode"),
    # Encryption / hashing
    ("Ljavax/crypto/Cipher;->doFinal", "cipher"),
    ("Ljavax/crypto/Cipher;->update", "cipher"),
    ("Ljavax/crypto/", "cipher"),
    ("Ljava/security/MessageDigest;->digest", "hash"),
    ("Ljava/security/MessageDigest;->update", "hash"),
    # Compression
    ("Ljava/util/zip/Deflater", "compression"),
    ("Ljava/util/zip/GZIPOutputStream", "compression"),
    ("Ljava/util/zip/ZipOutputStream", "compression"),
    ("Ljava/util/zip/Inflater", "compression"),
    ("Ljava/util/zip/GZIPInputStream", "compression"),
    ("Ljava/util/zip/ZipInputStream", "compression"),
    # Serialization
    ("Ljava/io/ObjectOutputStream;->", "serialization"),
    ("Ljava/io/ObjectInputStream;->", "serialization"),
    ("Ljava/io/DataOutputStream;->", "serialization"),
    ("Ljava/io/DataOutputStream", "serialization"),
    ("Ljava/io/DataInputStream;->", "serialization"),
    ("Ljava/io/ByteArrayOutputStream;->", "bytes"),
    ("Ljava/io/ByteArrayInputStream;->", "bytes"),
    # JSON
    ("Lorg/json/JSONObject;->", "json"),
    ("Lorg/json/JSONArray;->", "json"),
    ("Lcom/google/gson/", "json"),
    ("Lorg/apache/commons/codec/", "encoding"),
    # String concatenation / joining
    ("Ljava/lang/StringBuilder;->append", "string_concat"),
    ("Ljava/lang/StringBuilder;->", "string_concat"),
    ("Ljava/lang/String;->concat", "string_concat"),
    ("Ljava/lang/String;->valueOf", "string_concat"),
    ("Ljava/lang/String;->format", "string_concat"),
    ("Ljava/lang/String;->join", "string_concat"),
    ("Ljava/text/DecimalFormat;->format", "string_concat"),
]

TRANSFORM_PREFIXES = sorted(
    TRANSFORM_PREFIXES, key=lambda entry: len(entry[0]), reverse=True
)


# ---------------------------------------------------------------------------
# Propagators: methods that move a tainted value into a structural container
# (extras / clip / cursor / JSON) or read it back out. These let taint survive
# a get-then-set round trip that would otherwise look like a break.
# ---------------------------------------------------------------------------
PROPAGATOR_PREFIXES: List[Tuple[str, str]] = [
    # Cursor <-> value
    ("Landroid/database/Cursor;->getString", "propagate"),
    ("Landroid/database/Cursor;->getInt", "propagate"),
    ("Landroid/database/Cursor;->getLong", "propagate"),
    ("Landroid/database/Cursor;->getBlob", "propagate"),
    # Intent / Bundle extras
    ("Landroid/content/Intent;->putExtra", "propagate"),
    ("Landroid/content/Intent;->putExtras", "propagate"),
    ("Landroid/os/Bundle;->putString", "propagate"),
    ("Landroid/os/Bundle;->putStringArrayList", "propagate"),
    ("Landroid/os/Bundle;->putInt", "propagate"),
    ("Landroid/os/Bundle;->putLong", "propagate"),
    ("Landroid/os/Bundle;->putByteArray", "propagate"),
    ("Landroid/os/Bundle;->putCharSequence", "propagate"),
    ("Landroid/os/Bundle;->get", "propagate"),
    # ClipData
    ("Landroid/content/ClipData;->newPlainText", "propagate"),
    ("Landroid/content/ClipData;->getDescription", "propagate"),
    ("Landroid/content/ClipData;->getItemAt", "propagate"),
    ("Landroid/content/ClipData$Item;->getText", "propagate"),
    ("Landroid/content/ClipData$Item;->coerceToText", "propagate"),
    # JSON
    ("Lorg/json/JSONObject;->put", "propagate"),
    ("Lorg/json/JSONObject;->optString", "propagate"),
    ("Lorg/json/JSONObject;->getString", "propagate"),
    ("Lorg/json/JSONArray;->put", "propagate"),
    ("Lorg/json/JSONArray;->getString", "propagate"),
    # String containers
    ("Ljava/util/ArrayList;->add", "propagate"),
    ("Ljava/util/ArrayList;->get", "propagate"),
    ("Ljava/util/List;->add", "propagate"),
    # SharedPreferences read-back
    ("Landroid/content/SharedPreferences;->edit", "propagate"),
    ("Landroid/content/SharedPreferences$Editor;->putString", "propagate"),
]

# Propagators are broadly ordered so the engine can test a reference against
# them in one descending pass.
PROPAGATOR_PREFIXES = sorted(
    PROPAGATOR_PREFIXES, key=lambda entry: len(entry[0]), reverse=True
)


# ---------------------------------------------------------------------------
# Stream markers: account-object constructions that identify a stream so later
# ``write*`` calls can be attributed to a named channel even when the stream
# object itself is not tainted.
#   STREAM_MARKERS:  method ref prefix -> stream label.
#   STREAM_CTOR_REFS: referencish prefixes whose constructor (``<init>``)
#                     marks a newly created object as a stream of that type.
# ---------------------------------------------------------------------------
STREAM_MARKERS: Dict[str, str] = {
    "Ljava/net/HttpURLConnection;->getOutputStream": "http_stream",
    "Ljava/net/URLConnection;->getOutputStream": "http_stream",
    "Ljava/net/Socket;->getOutputStream": "socket_stream",
    "Ljava/io/FileOutputStream;->": "file_stream",
    "Ljava/io/BufferedOutputStream;->": "file_stream",
    "Ljava/io/PrintWriter;->": "file_stream",
}

# Output stream constructors whose new instance becomes a stream marker.
STREAM_CTOR_PREFIXES: List[str] = [
    "Ljava/net/FileOutputStream;->",
    "Ljava/io/FileOutputStream;->",
    "Ljava/io/BufferedOutputStream;->",
    "Ljava/io/BufferedWriter;->",
    "Ljava/io/PrintWriter;->",
    "Ljava/io/DataOutputStream;->",
    "Ljava/io/ObjectOutputStream;->",
]

# Register assignment forms in ``write``-style methods that feed a stream.
WRITE_PARAM_INDEXES: Dict[str, int] = {
    "Ljava/io/OutputStream;->write": 1,  # write(reg_value)
    "Ljava/io/OutputStream;->write([B": 1,
    "Ljava/io/BufferedOutputStream;->write": 1,
    "Ljava/io/FileOutputStream;->write": 1,
}


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------
def _match(
    reference: str, table: Sequence[Tuple[str, str]]
) -> List[Tuple[str, str]]:
    """Return every ``(label, match)`` entry whose prefix matches ``reference``.

    ``reference`` is a normalized method ref like
    ``Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;...)V``.
    Matching is naive ``startswith`` on the raw reference casing as-is (DEX
    descriptors are case-preserved); the table is pre-sorted longest-first so
    results are ordered by specificity.
    """
    if not reference:
        return []
    hits: List[Tuple[str, str]] = []
    for prefix, label in table:
        if reference.startswith(prefix):
            hits.append((label, prefix))
    return hits


def match_sources(reference: str) -> List[Tuple[str, str]]:
    """Labels (plus the matched prefix) for a sensitive source reference."""
    return _match(reference, SOURCE_PREFIXES)


def match_sinks(reference: str, access_flags: str = "") -> List[Tuple[str, str]]:
    """Labels (plus matched prefix) for a sink reference.

    A method whose access flags contain ``native`` is additionally treated as
    a native-call sink regardless of its prefix, reflecting JNI dispatch.
    """
    hits = _match(reference, SINK_PREFIXES)
    if access_flags and "native" in access_flags:
        hits.append(("native", "<native>"))
    return hits


def match_transforms(reference: str) -> List[Tuple[str, str]]:
    """Transformation labels (plus matched prefix) for a reference."""
    return _match(reference, TRANSFORM_PREFIXES)


def is_propagator(reference: str) -> bool:
    """True if ``reference`` moves tainted data in/out of a container."""
    return bool(_match(reference, PROPAGATOR_PREFIXES))


def is_stream_marker(reference: str) -> Optional[str]:
    """Return the stream label if ``reference`` produces a marked stream."""
    for prefix, label in sorted(
        STREAM_MARKERS.items(), key=lambda kv: len(kv[0]), reverse=True
    ):
        if reference.startswith(prefix):
            return label
    return None


def is_stream_ctor(reference: str) -> bool:
    """True if ``reference`` constructs a stream-like object."""
    return any(reference.startswith(p) for p in STREAM_CTOR_PREFIXES)


def stream_write_channels(reference: str) -> List[str]:
    """If ``reference`` is a stream ``write*`` method, return its channel.

    Returns labels such as ``http_stream``, ``socket_stream``, ``file_stream``
    or the generic ``output_stream``; empty when the reference is not a write.
    """
    name_part = reference.partition("->")[2]
    if not name_part.startswith("write"):
        return []
    channels: List[str] = []
    if reference.startswith("Ljava/net/HttpURLConnection;->") or reference.startswith(
        "Ljava/net/URLConnection;->"
    ):
        channels.append("http_stream")
    if reference.startswith("Ljava/net/Socket;->"):
        channels.append("socket_stream")
    if reference.startswith("Ljava/io/FileOutputStream;->") or reference.startswith(
        "Ljava/io/BufferedOutputStream;->"
    ):
        channels.append("file_stream")
    if reference.startswith("Ljava/net/ServerSocket;->") or reference.startswith(
        "Ljava/net/DatagramSocket;->"
    ):
        channels.append("socket_stream")
    if not channels:
        if reference.startswith("Ljava/io/"):
            channels.append("output_stream")
    return channels


def match_uri_source(uri: str) -> List[str]:
    """Sensitive category labels implied by a Content URI substring."""
    if not uri:
        return []
    hits: List[str] = []
    for substring, label in URI_SOURCE_SUBSTRINGS:
        if substring in uri:
            hits.append(label)
    return list(dict.fromkeys(hits))
