from failure_forensics.classify import (
    Failure,
    classify_run,
    normalise_message,
    signature,
)
from tests.conftest import span

T = "t" * 32


RUN = {"ff.kind": "run"}


def err(t, m):
    return {"ff.error.type": t, "ff.error.message": m}


def test_deepest_error_on_the_propagation_chain_is_the_culprit():
    spans = [
        span(T, "1", None, "run", 0, 100, "error", **RUN, **err("ValueError", "first")),
        span(T, "2", "1", "outer", 1, 90, "error", **err("ValueError", "first")),
        span(T, "3", "2", "inner", 2, 20, "error", **err("ValueError", "first")),
    ]
    f = classify_run(spans)
    assert (f.step, f.kind, f.message) == ("inner", "exception", "ValueError: first")


def test_caught_and_retried_error_does_not_fail_the_run():
    spans = [
        span(T, "1", None, "run", 0, 100, **RUN),
        span(T, "2", "1", "tool", 1, 20, "error", **err("ConnectionError", "reset")),
        span(T, "3", "1", "tool", 21, 40),
    ]
    assert classify_run(spans) is None


def test_caught_early_error_then_later_real_failure():
    spans = [
        span(T, "1", None, "run", 0, 100, "error", **RUN, **err("KeyError", "'x'")),
        span(T, "2", "1", "tool", 1, 20, "error", **err("ConnectionError", "reset")),  # caught
        span(T, "3", "1", "parse", 30, 60, "error", **err("KeyError", "'x'")),  # propagated
    ]
    f = classify_run(spans)
    assert (f.step, f.message) == ("parse", "KeyError: 'x'")


def test_wrapped_exception_still_blames_the_deepest_errored_child():
    spans = [
        span(T, "1", None, "run", 0, 100, "error", **RUN, **err("RuntimeError", "wrapped")),
        span(T, "2", "1", "gen", 1, 50, "error", **err("RuntimeError", "wrapped")),
        span(T, "3", "2", "call", 2, 10, "error", **err("ValueError", "root cause")),
    ]
    assert classify_run(spans).step == "call"


def test_wrapped_error_follows_the_last_ending_child_even_if_the_message_differs():
    spans = [
        span(T, "1", None, "run", 0, 100, "error", **RUN, **err("ValueError", "late")),
        span(T, "2", "1", "a", 1, 50, "error", **err("KeyError", "'x'")),  # caught
    ]
    f = classify_run(spans)
    assert f.step == "a"  # no child has the same error, but it ended last: a wrapped exception


def test_marked_failure_always_counts_and_wins_if_earlier():
    spans = [
        span(T, "1", None, "run", 0, 100, "error", **RUN, **err("ValueError", "late")),
        span(T, "2", "1", "judge", 1, 10, "error", **{"ff.failure.kind": "wrong_result", "ff.failure.detail": "bad"}),
        span(T, "3", "1", "tool", 20, 90, "error", **err("ValueError", "late")),
    ]
    assert classify_run(spans).kind == "wrong_result"
    spans[1].end_ns = spans[2].end_ns + 5  # marked later: the exception is the earlier failure
    assert classify_run(spans).step == "tool"
    ok_root = [span(T, "1", None, "run", 0, 100, **RUN), spans[1]]
    assert classify_run(ok_root).kind == "wrong_result"


def test_marked_failures_and_custom_kinds():
    s = [span(T, "1", None, "run", 0, 10, **RUN), span(T, "2", "1", "x", 1, 5, "error", **{"ff.failure.kind": "refusal", "ff.failure.detail": "no"})]
    assert classify_run(s).kind == "refusal"
    s[1].attributes["ff.failure.kind"] = "toxic"
    assert classify_run(s).kind == "marked:toxic"


def test_timeout_detected_by_flag_or_name():
    s = [span(T, "1", None, "r", 0, 9, "error", **RUN, **{"ff.error.type": "ReadTimeout", "ff.error.message": "slow"})]
    assert classify_run(s).kind == "timeout"
    s = [span(T, "1", None, "r", 0, 9, "error", **RUN, **{"ff.error.type": "TimeoutError", "ff.error.timeout": True})]
    assert classify_run(s).kind == "timeout"


def test_empty_output_only_when_expected():
    s = [span(T, "1", None, "r", 0, 9, **RUN), span(T, "2", "1", "answer", 1, 5, **{"ff.output": '""'})]
    assert classify_run(s) is None
    s[1].attributes["ff.expect_output"] = True
    assert classify_run(s).kind == "empty_output"


def test_no_failure_returns_none():
    assert classify_run([span(T, "1", None, "r", 0, 9, **RUN)]) is None


def test_custom_rule_and_ordering():
    def slow(spans):
        for s in spans:
            if s.name == "tool" and s.duration_ns > 10:
                return Failure(s.span_id, s.name, "marked:slow", "too slow")

    s = [span(T, "1", None, "r", 0, 99, "error", **RUN, **err("E", "m")), span(T, "2", "1", "tool", 1, 30),
         span(T, "3", "1", "later", 31, 40, "error", **err("E", "m"))]
    f = classify_run(s, [slow])
    assert (f.step, f.kind, f.end_ns, f.trace_id) == ("tool", "marked:slow", s[1].end_ns, T)


def test_signature_normalisation():
    a = normalise_message("KeyError: 'sku-12' at 10.0.0.7:5432 in /tmp/x/y.py id=3f2a9c1d4e5b6a7c")
    b = normalise_message("KeyError: 'sku-99' at 192.168.1.2:6543 in /var/z/w.py id=aaaaaaaa11111111")
    assert a == b == "KeyError: <str> at <n>:<n> in <path> id=<hex>"
    assert normalise_message("job 123e4567-e89b-12d3-a456-426614174000 failed after 2.5s") == "job <uuid> failed after <n>s"
    assert normalise_message('bad "quoted value" 42') == "bad <str> <n>"
    assert signature("tool", "timeout", "after 5s") == "tool | timeout | after <n>s"


def test_keyerror_keeps_the_missing_key_unless_it_looks_like_an_id():
    assert normalise_message("KeyError: 'sku-404'") == "KeyError: 'sku-<n>'"
    assert normalise_message("KeyError: 'sku-404'") == normalise_message("KeyError: 'sku-500'")
    assert normalise_message("KeyError: 'sku-404'") != normalise_message("KeyError: 'item-404'")
    assert normalise_message('KeyError: "user_1234567"') == 'KeyError: "user_<n>"'
    assert normalise_message("KeyError: 'deadbeef12'") == "KeyError: <str>"
    assert normalise_message("ValueError: bad 'x'") == "ValueError: bad <str>"


def test_root_raising_after_a_handled_step_blames_the_root():
    spans = [
        span(T, "1", None, "run", 0, 100, "error", **RUN, **err("ValueError", "late")),
        span(T, "2", "1", "tool", 1, 20, "error", **err("ConnectionError", "reset")),  # caught, retried
        span(T, "3", "1", "tool", 21, 40),  # the retry worked
        span(T, "4", "1", "parse", 41, 60),
    ]
    f = classify_run(spans)
    assert (f.step, f.message) == ("run", "ValueError: late")
