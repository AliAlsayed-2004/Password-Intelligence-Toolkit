from unittest.mock import patch, Mock

import pytest

from core.breach_check import (
    check_password_breach,
    format_breach_result,
    BreachCheckError,
    _sha1_prefix_suffix,
)


def test_sha1_prefix_suffix_split():
    # sha1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    prefix, suffix = _sha1_prefix_suffix("password")
    assert prefix == "5BAA6"
    assert suffix == "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
    assert len(prefix) == 5
    assert len(prefix) + len(suffix) == 40


def test_empty_password_short_circuits():
    result = check_password_breach("")
    assert result == {"breached": False, "times_seen": 0, "prefix_sent": ""}


@patch("core.breach_check.requests.get")
def test_breached_password_detected(mock_get):
    # simulate the API returning the real suffix for sha1("password") among others
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = (
        "0018A45C4D1DEF81644B54AB7F969B88D65:1\n"
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3730471\n"
        "0136E006E24E7D152139815FB0FC6A50B1:2\n"
    )
    mock_get.return_value = mock_response

    result = check_password_breach("password")
    assert result["breached"] is True
    assert result["times_seen"] == 3730471
    assert result["prefix_sent"] == "5BAA6"

    # only the prefix should ever be sent, never the full password
    called_url = mock_get.call_args[0][0]
    assert called_url.endswith("5BAA6")
    assert "1e4c9b93f3f0682250b6cf8331b7ee68fd8" not in called_url.lower()


@patch("core.breach_check.requests.get")
def test_clean_password_not_found(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "0018A45C4D1DEF81644B54AB7F969B88D65:1\n"
    mock_get.return_value = mock_response

    result = check_password_breach("a-genuinely-unique-passphrase-92xQ")
    assert result["breached"] is False
    assert result["times_seen"] == 0


@patch("core.breach_check.requests.get")
def test_non_200_raises(mock_get):
    mock_response = Mock()
    mock_response.status_code = 503
    mock_get.return_value = mock_response

    with pytest.raises(BreachCheckError):
        check_password_breach("password")


@patch("core.breach_check.requests.get")
def test_network_error_raises(mock_get):
    import requests

    mock_get.side_effect = requests.ConnectionError("no network")
    with pytest.raises(BreachCheckError):
        check_password_breach("password")


def test_format_breach_result_messages():
    breached = {"breached": True, "times_seen": 42, "prefix_sent": "ABCDE"}
    clean = {"breached": False, "times_seen": 0, "prefix_sent": "ABCDE"}

    assert "42" in format_breach_result(breached)
    assert "FOUND" in format_breach_result(breached)
    assert "OK" in format_breach_result(clean)
    assert "failed" in format_breach_result(clean, error="timeout")
