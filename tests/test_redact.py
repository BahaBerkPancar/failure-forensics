import pytest

from failure_forensics.redact import Redactor

r = Redactor()


@pytest.mark.parametrize(
    "text, gone",
    [
        ("mail alice.smith+x@example.co.uk now", "alice.smith"),
        ("call +90 532 123 45 67 please", "532 123"),
        ("call (415) 555-2671", "555-2671"),
        ("call 0532 123 45 67", "123 45 67"),
        ("iban DE89 3704 0044 0532 0130 00", "0532 0130"),
        ("iban GB82WEST12345698765432", "WEST1234"),
        ("card 4111 1111 1111 1111", "4111 1111"),
        ("card 4111-1111-1111-1111", "1111-1111"),
        ("Authorization: Bearer abcdef1234567890", "abcdef1234567890"),
        ("key sk-proj-abcdefghijklmnop1234", "abcdefghijklmnop"),
        ("token ghp_abcdefghijklmnopqrstuv", "abcdefghijklmnopqrstuv"),
        ("hash " + "ab12" * 16, "ab12ab12ab12"),
        ("secret=d41d8cd98f00b204e9800998ecf8427e", "d41d8cd98f00b204"),
        ("blob QWxhZGRpbjpvcGVuIHNlc2FtZQ1234567890abcdefGHIJKLMN", "QWxhZGRpbjpvcGVuIHNlc2FtZQ"),
        ("password = hunter2", "hunter2"),
        ("api_key: abc123", "abc123"),
    ],
)
def test_redacts(text, gone):
    out = r.text(text)
    assert gone not in out
    assert "[REDACTED" in out


@pytest.mark.parametrize(
    "text",
    [
        "SELECT id FROM orders",
        "SELECT name, SUM(total) FROM orders WHERE created_at >= '2024-11-17' GROUP BY name LIMIT 100",
        "UPDATE users SET age = 31 WHERE id = 1234567",
        "2024-11-17 12:30:45 step finished in 123.45 ms",
        "validate_customer_order_total_with_discount_v2_final_check",
        "card 4111 1111 1111 1112",  # fails Luhn
        "iban DE89 3704 0044 0532 0130 01",  # fails mod 97
        "commit 3f2a9c1d4e5b6a7c3f2a9c1d4e5b6a7c3f2a9c1d merged",  # git SHA
        "trace_id=3f2a9c1d4e5b6a7c3f2a9c1d4e5b6a7c",
        "SELECT * FROM tokens WHERE max_tokens > 5 AND token_count = 3 -- no password here",
        "version python3.12.4 build 20241117",
        "see /usr/local/lib/python3.12/site-packages/foo.py",
    ],
)
def test_no_false_positives(text):
    assert r.text(text) == text


def test_sensitive_keys_scrubbed_in_nested_values():
    out = r.scrub({"user": "a", "password": "x", "nested": [{"Authorization": "y", "max_tokens": 5}]})
    assert out == {"user": "a", "password": "[REDACTED]",
                   "nested": [{"Authorization": "[REDACTED]", "max_tokens": 5}]}


def test_custom_patterns_and_keys():
    red = Redactor(patterns=[r"ORD-\d{6}"], keys=["ssn"])
    assert "ORD-123456" not in red.text("order ORD-123456")
    assert red.scrub({"ssn": "1"}) == {"ssn": "[REDACTED]"}


def test_json_text_truncates_after_redacting():
    out = r.json_text({"q": "x" * 100, "email": "bob@example.com"}, max_len=40)
    assert out.endswith("chars]") and "bob@" not in out


def test_json_text_handles_odd_values():
    class Thing:
        pass

    assert "Thing" in r.json_text(Thing())
    loop: list = []
    loop.append(loop)
    assert isinstance(r.json_text(loop), str)


@pytest.mark.parametrize(
    "text",
    [
        "{'password': 'hunter2'}",
        '{"password": "hunter2"}',
        '{"password": "hunter2"} '.replace('"', '\\"'),
        "failed with {'user': 'a', 'api_key': 'hunter2'}",
        "Authorization: Basic hunter2",
        "Authorization: Bearer hunter2",
        "authorization = hunter2",
        "db_password=hunter2;",
        "x-api-key: hunter2",
    ],
)
def test_quoted_and_header_forms(text):
    assert "hunter2" not in r.text(text)


def test_json_dumped_values_and_dict_repr_in_json_text():
    import json

    assert "hunter2" not in r.json_text({"msg": "cfg={'password': 'hunter2'}"})
    assert "hunter2" not in r.json_text(json.dumps({"password": "hunter2", "n": 1}))
    assert "hunter2" not in r.json_text({"a": {"nested": {"Password": "hunter2"}}})


def test_custom_keys_apply_to_text_too():
    assert "123-45" not in Redactor(keys=["ssn"]).text("{'ssn': '123-45-6789'}")
