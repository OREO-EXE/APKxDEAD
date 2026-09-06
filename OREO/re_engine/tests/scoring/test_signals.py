"""Unit tests for the deterministic signal tables and detectors."""

from re_engine.scoring.signals import (
    PERMISSION_SIGNALS,
    classify_string,
    high_identifier_entropy,
    is_command_execution,
    permissions_by_category,
    shannon_entropy,
    signal_for_call,
    suspicious_class_segments,
    suspicious_method_segments,
)


def test_web_socket_and_http_signals():
    signal = signal_for_call(
        "Lokhttp3/WebSocket;->send(Ljava/lang/String;)Z"
    )
    assert signal is not None
    assert signal.label == "OkHttp WebSocket API"
    assert signal.weight == 18

    http = signal_for_call(
        "Ljava/net/HttpURLConnection;->openConnection()V"
    )
    assert http is not None
    assert http.label == "HttpURLConnection API"


def test_dynamic_loading_priority_over_generic_classloader():
    signal = signal_for_call(
        "Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;...)V"
    )
    assert signal is not None
    assert signal.label == "DexClassLoader API"
    assert signal.weight == 40


def test_command_execution_detector():
    assert is_command_execution(
        "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;"
    )
    assert is_command_execution("Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;")
    assert not is_command_execution("Ljava/lang/Thread;->start()V")


def test_permission_categories_bucket():
    by = permissions_by_category(
        [
            "android.permission.READ_SMS",
            "android.permission.INTERNET",
            "android.permission.CAMERA",
            "android.permission.NOT_A_REAL_PERMISSION",
        ]
    )
    assert by["SMS"] == ["android.permission.READ_SMS"]
    assert by["NETWORK"] == ["android.permission.INTERNET"]
    assert by["CAMERA"] == ["android.permission.CAMERA"]
    assert "NOT_A_REAL_PERMISSION" not in PERMISSION_SIGNALS


def test_string_classification_kinds():
    url = classify_string("https://c2.example.com/beacon")
    assert any(s.label == "hardcoded URL" for s in url)

    ip = classify_string("10.0.0.5")
    assert any(s.label == "hardcoded IP address" for s in ip)

    domain = classify_string("c2.example.net")
    assert any(s.label == "hardcoded domain" for s in domain)

    encoded = classify_string("aHVza2VkLmJhc2U2NA==")
    assert any(s.label == "encoded string (base64-like)" for s in encoded)

    hexblob = classify_string("deadbeefcafebabedeadbeefcafebabe")
    assert any(s.label == "encoded string (hex-like)" for s in hexblob)


def test_string_classification_rejects_plain_text():
    assert classify_string("hello world") == []
    assert classify_string("sendTextMessage") == []
    assert classify_string("") == []
    assert classify_string("a" * 4) == []


def test_identifier_entropy_is_deterministic_and_thresholded():
    assert shannon_entropy("aaaa") == 0.0
    identifier = "a0b1c2d3e4f5AB"
    first = shannon_entropy(identifier)
    second = shannon_entropy(identifier)
    assert first == second
    assert first >= 3.8
    assert high_identifier_entropy(identifier, threshold=3.8)
    assert not high_identifier_entropy("MainActivity", threshold=3.8)
    assert not high_identifier_entropy("abc", threshold=3.8)


def test_suspicious_name_segments():
    assert suspicious_class_segments("com.evil.raya.Payload") == ["evil", "payload"]
    assert suspicious_class_segments("com.example.hello.Main") == []
    assert suspicious_method_segments("onExfilData") == ["exfil"]
    assert suspicious_method_segments("onCreate") == []