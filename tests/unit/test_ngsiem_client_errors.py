"""NGSIEMClient error-message honesty tests.

These tests pin the client to: never say 'Unknown error', always include the
status code, prefer LogScale's own diagnostic when it can be recovered, and
degrade predictably when it cannot.

NOTE ON RESPONSE SHAPE: falconpy's NGSIEM.start_search() pops "body" and
re-exposes the payload as "resources" (falconpy/ngsiem.py). The older tests
below mock a "body" key, which this endpoint never actually returns — that
mismatch is why the client read a key that was never present without any test
catching it. The tests are kept (the Uber class does return "body", so both
shapes must work) and paired with explicit "resources" coverage.
"""

from unittest.mock import MagicMock, patch

from talonctl.utils.ngsiem_client import NGSIEMClient


def _client_with_mock_falconpy(mock_response):
    client = NGSIEMClient.__new__(NGSIEMClient)  # bypass __init__ / creds
    client.config = {}
    client.debug = False
    mock_falconpy = MagicMock()
    mock_falconpy.start_search.return_value = mock_response
    mock_falconpy.stop_search.return_value = {"status_code": 200}
    client._client = mock_falconpy
    return client


def test_valid_query_returns_valid():
    client = _client_with_mock_falconpy(
        {"status_code": 200, "body": {"id": "abc", "resources": {"id": "abc"}}, "resources": {"id": "abc"}}
    )
    result = client.test_query_syntax("| limit 1")
    assert result["valid"] is True


def test_rejection_with_errors_passes_payload_through():
    errors_payload = [{"message": "unexpected token at column 17"}]
    client = _client_with_mock_falconpy({"status_code": 400, "body": {"errors": errors_payload}})
    result = client.test_query_syntax("bad |")
    assert result["valid"] is False
    assert "Unknown error" not in result["message"]
    assert "status=400" in result["message"]
    assert "column 17" in result["message"]


def test_rejection_with_string_error_passes_through():
    client = _client_with_mock_falconpy({"status_code": 400, "body": {"errors": "bad pipe"}})
    result = client.test_query_syntax("bad |")
    assert result["valid"] is False
    assert "Unknown error" not in result["message"]
    assert "bad pipe" in result["message"]
    assert "status=400" in result["message"]


def test_rejection_with_empty_body_says_no_detail():
    client = _client_with_mock_falconpy({"status_code": 400, "body": {}})
    result = client.test_query_syntax("bad |")
    assert result["valid"] is False
    assert "Unknown error" not in result["message"]
    assert "no detail returned by API" in result["message"]
    assert "status=400" in result["message"]


def test_rejection_with_missing_body_says_no_detail():
    client = _client_with_mock_falconpy({"status_code": 400})
    result = client.test_query_syntax("bad |")
    assert result["valid"] is False
    assert "Unknown error" not in result["message"]
    assert "no detail returned by API" in result["message"]


# --- Real response shape: NGSIEM.start_search() returns "resources", not "body" ---


def test_rejection_reads_resources_key_not_body():
    """Regression: the payload arrives under "resources" for this endpoint.

    Reading only "body" made the passthrough dead code — it could never fire,
    so every rejection degraded to "no detail returned by API".
    """
    client = _client_with_mock_falconpy(
        {"status_code": 400, "resources": {"errors": [{"message": "unexpected token at column 42"}]}}
    )
    with patch.object(NGSIEMClient, "_raw_syntax_error", return_value=None):
        result = client.test_query_syntax("bad |")
    assert result["valid"] is False
    assert "column 42" in result["message"]
    assert "no detail returned by API" not in result["message"]
    assert "status=400" in result["message"]


def test_raw_logscale_diagnostic_is_preferred_over_sdk_payload():
    """LogScale's text/plain diagnostic beats falconpy's fabricated message."""
    fabricated = {"errors": [{"message": "No content was received for this request."}], "resources": []}
    client = _client_with_mock_falconpy({"status_code": 400, "resources": fabricated})
    diagnostic = (
        "Function calls are not supported in filter expressions. "
        "(Error: FunctionCallsNotSupportedInFilterExpressions)\n"
        ' 1: #repo="base_sensor" | NOT (in(field="x", values=["a"]))\n'
        "                               ^^"
    )
    with patch.object(NGSIEMClient, "_raw_syntax_error", return_value=diagnostic):
        result = client.test_query_syntax("bad |")
    assert result["valid"] is False
    assert "FunctionCallsNotSupportedInFilterExpressions" in result["message"]
    # The fabricated SDK message must not leak through when we have the real one.
    assert "No content was received" not in result["message"]
    # Caret alignment is the point — it must survive verbatim.
    assert "                               ^^" in result["message"]


def test_falls_back_to_status_only_when_nothing_recoverable():
    client = _client_with_mock_falconpy({"status_code": 400, "resources": {}})
    with patch.object(NGSIEMClient, "_raw_syntax_error", return_value=None):
        result = client.test_query_syntax("bad |")
    assert result["valid"] is False
    assert "no detail returned by API" in result["message"]
    assert "status=400" in result["message"]


def test_valid_query_never_attempts_raw_recovery():
    """A 200 must short-circuit — no extra request on the happy path."""
    client = _client_with_mock_falconpy({"status_code": 200, "resources": {"id": "abc"}})
    with patch.object(NGSIEMClient, "_raw_syntax_error") as raw:
        result = client.test_query_syntax("| limit 1")
    assert result["valid"] is True
    raw.assert_not_called()


def test_raw_recovery_never_raises_on_transport_failure():
    """Diagnostics are best-effort; a broken bypass must not mask the verdict."""
    client = _client_with_mock_falconpy({"status_code": 400, "resources": {}})
    with patch("requests.post", side_effect=OSError("connection refused")):
        assert client._raw_syntax_error("bad |") is None
        result = client.test_query_syntax("bad |")
    assert result["valid"] is False
    assert "no detail returned by API" in result["message"]
