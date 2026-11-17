"""Tests for the text-to-sql-guardrails integration. Skipped without the `t2s` extra; the ones marked
`pg` also need TEST_DATABASE_URL (a disposable local PostgreSQL, rebuilt by the fixture)."""

import os

import pytest

pytest.importorskip("text_to_sql_guardrails")

from text_to_sql_guardrails.guard.policy import load_policy
from text_to_sql_guardrails.llm.base import Generation, LlmRefused
from text_to_sql_guardrails.llm.fake import FakeGenerator
from text_to_sql_guardrails.pipeline import answer

import failure_forensics as ff
from failure_forensics.integrations import t2s

QUESTIONS = {q.id: q for q in t2s.load_questions(t2s.QUESTIONS_PATH)}
ATTACKS = t2s.load_attack_prompts(t2s.ATTACK_PROMPTS_PATH)
Q_SIMPLE = QUESTIONS["q001"]
POLICY = load_policy(t2s.POLICY_PATH)
pg = pytest.mark.pg


def gen(sql=None, refusal=None):
    return Generation(sql, refusal, "fake", 0, 0)


def culprit(store):
    (run,) = store.list_runs()
    return (run["fail_step"], run["fail_kind"], run["fail_message"]) if run["status"] == "failed" else None


def span_names(store):
    (run,) = store.list_runs()
    return [s.name for s in store.get_spans(run["trace_id"])]


@pytest.fixture
def pg_env(tmp_path_factory):
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL is not set")
    t2s.check_local_url(url)
    admin, readonly = t2s.prepare_database(url)
    env = t2s.make_env(admin, readonly, timeout_ms=400)
    yield env
    readonly.dispose()
    admin.dispose()


@pytest.fixture
def offline_env():
    """No database: enough for runs that end at the generator or the validator."""
    from text_to_sql_guardrails.bench.guardrails import SensitiveValues
    from text_to_sql_guardrails.config import Settings

    return t2s.T2SEnv(None, None, POLICY, Settings(_env_file=None), SensitiveValues(frozenset(), frozenset(), frozenset()))


# -- generator proxy (no database) ----------------------------------------------------------


def test_proxy_records_attempts_and_previous_errors(db, offline_env):
    fake = FakeGenerator([gen("SELECT reverse(name) FROM products"), gen("SELECT email FROM customers")])
    with ff.run("t", case_id="x"):
        result = t2s.traced_answer(Q_SIMPLE.question, fake, offline_env, expect_answer=True)
    assert not result.ok and result.error_code == "COLUMN_NOT_ALLOWED"
    assert [c.previous[0].error_code if c.previous else None for c in fake.calls] == [None, "FUNCTION_NOT_ALLOWED"]


def test_proxy_call_log_and_spans(db):
    fake = FakeGenerator([gen("SELECT 1"), gen(refusal="no")])
    proxy = t2s.TracedGenerator(fake)
    with ff.run("t"):
        proxy.generate("q1", "schema", [])
        proxy.generate("q1", "schema", [t2s.Attempt("SELECT 1", "BAD", "bad sql")])
    assert [(c["attempt"], c.get("sql"), c.get("cannot_answer")) for c in proxy.calls] == [
        (1, "SELECT 1", None), (2, None, "no")]
    assert proxy.calls[1]["previous"][0]["code"] == "BAD"
    assert span_names(db).count("generate") == 2
    assert culprit(db) == ("generate", "refusal", "no")  # a refusal is a refusal failure, not a crash


def test_proxy_refusal_exception_is_marked_and_reraised(db):
    class Refuses:
        def generate(self, *a):
            raise LlmRefused("policy says no")

    with pytest.raises(LlmRefused), ff.run("t"):
        t2s.TracedGenerator(Refuses()).generate("q", "s", [])
    assert culprit(db) == ("generate", "refusal", "policy says no")


def test_attack_refusal_is_not_a_failure(db, offline_env):
    with ff.run("t2s.attack"):
        result = t2s.traced_answer("delete everything", FakeGenerator([gen(refusal="no")]), offline_env,
                                   expect_answer=False)
        assert t2s.check_attack(result, offline_env) == "declined"
    assert culprit(db) is None


def test_validator_block_marks_blocked_with_code(db, offline_env):
    fake = FakeGenerator([gen("SELECT reverse(name) FROM products"), gen("SELECT reverse(name) FROM products")])
    with ff.run("t2s.question"):
        result = t2s.traced_answer(Q_SIMPLE.question, fake, offline_env, expect_answer=True)
    assert result.stage == "validator"
    assert culprit(db) == ("validate", "blocked", "FUNCTION_NOT_ALLOWED")
    assert span_names(db).count("validate") == 2 and len(fake.calls) == 2


def test_retry_that_recovers_is_not_a_failure(db, pg_env):
    fake = FakeGenerator([gen("SELECT reverse(name) FROM products"), gen(Q_SIMPLE.gold_sql)])
    with ff.run("t2s.question"):
        result = t2s.traced_answer(Q_SIMPLE.question, fake, pg_env, expect_answer=True)
    assert result.ok and len(result.attempts) == 2
    assert culprit(db) is None  # the first, blocked attempt was repaired


def test_unknown_generator_specs():
    with pytest.raises(ValueError):
        t2s.make_generator("mutated:nope", list(QUESTIONS.values()))
    with pytest.raises(ValueError):
        t2s.make_generator("what", [])


def test_recorded_generator(tmp_path):
    p = tmp_path / "r.jsonl"
    p.write_text('{"question": "a", "sql": "SELECT 1"}\n{"question": "b", "refusal": "no"}\n')
    g = t2s.make_generator(f"recorded:{p}", [])
    assert g.generate("a", "", []).sql == "SELECT 1"
    assert g.generate("b", "", []).cannot_answer == "no"
    assert g.generate("zzz", "", []).cannot_answer


# -- the five semantic failure kinds on real cases (pg) ------------------------------------------


@pg
@pytest.mark.parametrize("spec,qid,expected", [
    ("gold", "q012", None),
    ("mutated:wrong-join", "q011", ("compare", "wrong_result")),
    ("mutated:harmless-function", "q001", ("validate", "blocked")),
])
def test_question_outcomes(db, pg_env, spec, qid, expected):
    generator = t2s.make_generator(spec, list(QUESTIONS.values()))
    t2s.trace_question(QUESTIONS[qid], generator, pg_env, {"generator": spec})
    got = culprit(db)
    assert (got[:2] if got else None) == expected


@pg
def test_wrong_result_shows_compare_as_culprit(db, pg_env):
    join_q = next(q for q in QUESTIONS.values() if q.category == "join")
    t2s.trace_question(join_q, t2s.make_generator("mutated:wrong-join", list(QUESTIONS.values())),
                       pg_env, {"generator": "x"})
    step, kind, message = culprit(db)
    assert (step, kind) == ("compare", "wrong_result") and "differ from gold" in message
    assert span_names(db) == ["t2s.question", "generate", "validate", "execute", "compare"]


@pg
def test_blocked_by_database_role_is_over_blocking(db, pg_env):
    # the validator allows the column list of the policy; make the DB role stricter than the policy
    # by querying a denied table through a permissive policy: the read-only role refuses it
    from text_to_sql_guardrails.guard.policy import Policy

    permissive = Policy({**POLICY.tables, "staff_salaries": frozenset({"staff_name", "salary"})},
                        POLICY.default_limit, POLICY.max_limit)
    env = t2s.T2SEnv(pg_env.admin, pg_env.readonly, permissive, pg_env.settings, pg_env.denied, baseline={})
    fake = FakeGenerator([gen("SELECT staff_name FROM staff_salaries")])
    with ff.run("t2s.question"):
        result = t2s.traced_answer("who is paid?", fake, env, expect_answer=True)
    assert result.error_code == "PERMISSION_DENIED"
    assert culprit(db)[:2] == ("execute", "blocked")


@pg
def test_timeout(db, pg_env):
    slow = "SELECT COUNT(*) FROM order_items AS a CROSS JOIN order_items AS b CROSS JOIN order_items AS c"
    with ff.run("t2s.question"):
        result = t2s.traced_answer("count", FakeGenerator([gen(slow)]), pg_env, expect_answer=True)
    assert result.error_code == "TIMEOUT"
    assert culprit(db)[:2] == ("execute", "timeout")


@pg
def test_refusal_on_a_question_with_gold(db, pg_env):
    t2s.trace_question(Q_SIMPLE, FakeGenerator([gen(refusal="cannot")]), pg_env, {"generator": "fake"})
    assert culprit(db)[:2] == ("generate", "refusal")


@pg
def test_attack_prompts_are_declined_or_blocked_without_failures(db, pg_env):
    leaky = t2s.make_generator("mutated:leaky", list(QUESTIONS.values()))
    outcome = t2s.trace_attack(ATTACKS[0], leaky, pg_env, {"generator": "leaky"})
    assert outcome == "blocked_validator" and culprit(db) is None


@pg
def test_unsafe_when_denied_data_leaves(db, pg_env):
    from text_to_sql_guardrails.guard.policy import Policy

    tables = {**POLICY.tables, "customers": frozenset({*POLICY.tables["customers"], "email"})}
    env = t2s.T2SEnv(pg_env.admin, pg_env.admin, Policy(tables, POLICY.default_limit, POLICY.max_limit),
                     pg_env.settings, pg_env.denied, baseline=pg_env.baseline)  # permissive policy + admin role
    fake = FakeGenerator([gen("SELECT email FROM customers")])
    with ff.run("t2s.attack"):
        result = t2s.traced_answer("emails", fake, env, expect_answer=False)
        assert t2s.check_attack(result, env) == "unsafe"
    assert culprit(db) == ("guard", "unsafe", "query result contains denied data")


@pg
def test_unsafe_when_the_database_checksum_changes(db, pg_env):
    state = iter([{"v": 2}])
    env = t2s.T2SEnv(pg_env.admin, pg_env.readonly, POLICY, pg_env.settings, pg_env.denied,
                     checksum=lambda _e: next(state), baseline={"v": 1})
    with ff.run("t2s.attack"):
        result = t2s.traced_answer("q", FakeGenerator([gen(Q_SIMPLE.gold_sql)]), env, expect_answer=False)
        assert t2s.check_attack(result, env) == "unsafe"
    assert culprit(db) == ("guard", "unsafe", "database checksum changed")


# -- the composed pipeline behaves like t2s's own answer() (pg) ---------------------------------


def _shape(result):
    qr = result.query_result
    return (result.ok, result.stage, result.error_code, result.error_message, result.sql, [(a.sql, a.error_code) for a in result.attempts],
            None if qr is None else (qr.columns, qr.rows, qr.truncated))


@pg
@pytest.mark.parametrize("spec", ["gold", "mutated:wrong-join", "mutated:harmless-function", "mutated:leaky",
                                  "mutated:drop-order-by+off-by-one-limit"])
def test_traced_answer_matches_t2s_answer(db, pg_env, spec):
    questions = list(QUESTIONS.values())
    prompts = [q.question for q in questions] + [a.question for a in ATTACKS]
    for prompt in prompts:
        expected = answer(prompt, t2s.make_generator(spec, questions), POLICY, pg_env.readonly, pg_env.settings)
        with ff.run("parity"):
            got = t2s.traced_answer(prompt, t2s.make_generator(spec, questions), pg_env, expect_answer=True)
        assert _shape(got) == _shape(expected), prompt


@pg
@pytest.mark.parametrize("script", [
    [gen("SELECT nope FROM products"), gen(Q_SIMPLE.gold_sql)],                  # DB error, repaired
    [gen("SELECT nope FROM products"), gen("SELECT nope2 FROM products")],       # repair fails too
    [gen("SELECT * FROM staff_salaries"), gen(Q_SIMPLE.gold_sql)],               # validator, repaired
    [gen(None, None), gen(Q_SIMPLE.gold_sql)],                                   # no SQL at all
])
def test_traced_answer_matches_t2s_answer_on_repair_paths(db, pg_env, script):
    expected = answer("q", FakeGenerator(list(script)), POLICY, pg_env.readonly, pg_env.settings)
    with ff.run("parity"):
        got = t2s.traced_answer("q", FakeGenerator(list(script)), pg_env, expect_answer=True)
    assert _shape(got) == _shape(expected)


@pg
def test_traced_answer_matches_t2s_answer_on_timeout_and_permission_denied(db, pg_env):
    from text_to_sql_guardrails.guard.policy import Policy

    slow = "SELECT COUNT(*) FROM order_items AS a CROSS JOIN order_items AS b CROSS JOIN order_items AS c"
    permissive = Policy({**POLICY.tables, "staff_salaries": frozenset({"staff_name", "salary"})},
                        POLICY.default_limit, POLICY.max_limit)
    for policy, sql, code in [(POLICY, slow, "TIMEOUT"),
                              (permissive, "SELECT staff_name FROM staff_salaries", "PERMISSION_DENIED")]:
        env = t2s.T2SEnv(pg_env.admin, pg_env.readonly, policy, pg_env.settings, pg_env.denied, baseline={})
        expected = answer("q", FakeGenerator([gen(sql)]), policy, pg_env.readonly, pg_env.settings)
        with ff.run("parity"):
            got = t2s.traced_answer("q", FakeGenerator([gen(sql)]), env, expect_answer=True)
        assert expected.error_code == code
        assert _shape(got) == _shape(expected)


@pytest.mark.parametrize("url", [
    "postgresql+psycopg://app:app@127.0.0.1:55432/app",
    "postgresql+psycopg://app:app@localhost/app",
    "postgresql+psycopg://app:app@[::1]:5432/app",
    "postgresql+psycopg://app:app@/app",                                  # default unix socket
])
def test_local_url_guard_accepts_local(url):
    assert t2s.check_local_url(url) == url


@pytest.mark.parametrize("url", [
    "", "postgresql+psycopg://app:app@db.example.com/app",
    "postgresql+psycopg://app:app@127.0.0.1/app?host=db.example.com",
    "postgresql+psycopg://app:app@127.0.0.1/app?hostaddr=10.0.0.5",
    "postgresql+psycopg://app:app@127.0.0.1/app?service=prod",
])
def test_local_url_guard_rejects_remote(url):
    with pytest.raises(RuntimeError):
        t2s.check_local_url(url)


def test_local_url_guard_allows_path_host():
    assert t2s.check_local_url("postgresql+psycopg://app:app@%2Fvar%2Frun%2Fpostgresql/app")


@pg
def test_run_suite_end_to_end(tmp_path):
    out = t2s.run_suite("mutated:harmless-function", str(tmp_path / "t.db"), log=lambda _m: None)
    assert out["runs"] == len(QUESTIONS) + len(ATTACKS)
    store = ff.get_store()
    assert {f["signature"] for f in store.failures_with_runs()} == {
        "validate | blocked | FUNCTION_NOT_ALLOWED"}
    assert store.count_runs() == out["runs"]
