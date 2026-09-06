"""Specs: source/sink/transform/propagator/stream/URI prefix matching."""

from __future__ import annotations

from re_engine.dataflow.specs import (
    URI_SOURCE_SUBSTRINGS,
    is_propagator,
    is_stream_ctor,
    is_stream_marker,
    match_sources,
    match_transforms,
    match_sinks,
    match_uri_source,
    stream_write_channels,
)

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


def test_sms_source_prefixes():
    hits = match_sources(
        "Landroid/telephony/SmsMessage;->getMessageBody()Ljava/lang/String;"
    )
    assert any(label == "sms" for label, _ in hits)


def test_content_resolver_query_is_source():
    hits = match_sources(
        "Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;"
        "Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;"
    )
    assert any(label == "content_query" for label, _ in hits)


def test_device_id_source():
    hits = match_sources(
        "Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;"
    )
    assert any(label == "device_id" for label, _ in hits)


def test_location_source():
    hits = match_sources(
        "Landroid/location/LocationManager;->getLastKnownLocation"
        "(Ljava/lang/String;)Landroid/location/Location;"
    )
    assert any(label == "location" for label, _ in hits)


def test_non_source_matches_nothing():
    assert match_sources("Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z") == []


def test_specificity_ordering_longest_prefix_first():
    hits = match_sources(
        "Landroid/telephony/SmsManager;->getAllMessagesFromIcc"
        "()[Ljava/lang/String;"
    )
    labels = [label for label, _ in hits]
    assert labels[0] == "sms"


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------


def test_http_sink_prefixes():
    for ref in (
        "Lorg/apache/http/impl/client/DefaultHttpClient;->execute"
        "(Lorg/apache/http/client/methods/HttpGet;)Lorg/apache/http/client/methods/HttpUriRequest;",
        "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;",
        "Lokhttp3/OkHttpClient;->newCall(Lokhttp3/Request;)Lokhttp3/Call;",
    ):
        assert any(label == "http" for label, _ in match_sinks(ref))


def test_runtime_exec_sink():
    hits = match_sinks("Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;")
    assert any(label == "exec" for label, _ in hits)


def test_sms_send_sink():
    hits = match_sinks(
        "Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;"
        "Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V"
    )
    assert any(label == "sms_send" for label, _ in hits)


def test_native_access_flag_is_sink():
    hits = match_sinks("Lcom/app/Native;->invoke(I)V", access_flags="native")
    assert any(label == "native" for label, _ in hits)


def test_non_sink_matches_nothing():
    assert match_sinks("Ljava/util/ArrayList;->clear()V") == []


# ---------------------------------------------------------------------------
# Transforms
# ---------------------------------------------------------------------------


def test_base64_transform():
    hits = match_transforms(
        "Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;"
    )
    assert any(label == "base64" for label, _ in hits)


def test_url_encode_transform():
    hits = match_transforms("Ljava/net/URLEncoder;->encode(Ljava/lang/String;)Ljava/lang/String;")
    assert any(label == "url_encode" for label, _ in hits)


def test_string_concat_transform():
    hits = match_transforms(
        "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;"
    )
    assert any(label == "string_concat" for label, _ in hits)


def test_non_transform_matches_nothing():
    assert match_transforms("Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z") == []


# ---------------------------------------------------------------------------
# Propagators
# ---------------------------------------------------------------------------


def test_cursor_propagator():
    assert is_propagator("Landroid/database/Cursor;->getString(I)Ljava/lang/String;")


def test_intent_put_extra_propagator():
    assert is_propagator(
        "Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;"
    )


def test_bundle_roundtrip_propagators():
    assert is_propagator("Landroid/os/Bundle;->putString(Ljava/lang/String;Ljava/lang/String;)V")
    assert is_propagator("Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;")


def test_non_propagator():
    assert not is_propagator("Landroid/content/ContentResolver;->query()Landroid/database/Cursor;")


# ---------------------------------------------------------------------------
# Streams
# ---------------------------------------------------------------------------


def test_stream_markers():
    assert is_stream_marker(
        "Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;"
    ) == "http_stream"
    assert is_stream_marker(
        "Ljava/net/Socket;->getOutputStream()Ljava/io/OutputStream;"
    ) == "socket_stream"


def test_stream_write_channels():
    assert "http_stream" in stream_write_channels(
        "Ljava/net/HttpURLConnection;->write([BII)V"
    )
    assert "file_stream" in stream_write_channels(
        "Ljava/io/FileOutputStream;->write([BI)V"
    )
    assert "output_stream" in stream_write_channels(
        "Ljava/io/DataOutputStream;->write(I)V"
    )


def test_stream_ctor_flags():
    assert is_stream_ctor("Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V")
    assert not is_stream_ctor("Ljava/lang/Object;-><init>()V")


# ---------------------------------------------------------------------------
# URI source rules
# ---------------------------------------------------------------------------


def test_uri_authority_mapping():
    assert match_uri_source("content://sms/inbox") == ["sms"]
    assert match_uri_source("content://call_log/calls") == ["call_log"]
    assert match_uri_source("content://com.android.contacts/contacts") == ["contacts"]
    assert match_uri_source("content://misc") == []


def test_uri_rule_table_shape():
    for substring, label in URI_SOURCE_SUBSTRINGS:
        assert substring
        assert label