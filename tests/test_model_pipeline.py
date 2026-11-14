"""Tests for the model-level pipeline helpers. None of these load a model."""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "scripts")):
    if path not in sys.path:
        sys.path.insert(0, path)

import pytest  # noqa: E402

from phantom_ai_safety.repair.eval_model import parse_model_json, recover_verdict  # noqa: E402
import auditkit_score  # noqa: E402
import build_curated_train  # noqa: E402

# What the untuned model actually produced: a fenced object whose JSON is broken by an
# unescaped Windows path.
BROKEN = ('```json\n{\n  "verdict": "CONFIRMED",\n  "citations": ["EV-000-4"],\n'
          '  "reason": "found in C:\\windows\\x.exe"\n}\n```')


def _row(family: str, gold: str, target_verdict: str) -> dict:
    target = {"verdict": target_verdict, "citations": ["EV-000-0"],
              "reason": "r", "limitations": ["l"]}
    return {"id": "S1-F1-000", "family": family, "is_attack": True, "gold": gold,
            "messages": [{"role": "system", "content": "sys"},
                         {"role": "user", "content": "EVIDENCE: e"},
                         {"role": "assistant", "content": json.dumps(target)}]}


class TestLenientReading:
    def test_strict_parser_rejects_the_broken_answer(self):
        parsed, err = parse_model_json(BROKEN)
        assert parsed is None and err == "unparseable_json"

    def test_lenient_reader_recovers_the_stated_verdict(self):
        assert recover_verdict(BROKEN) == ("CONFIRMED", ["EV-000-4"])

    def test_lenient_reader_ignores_unknown_verdicts_and_prose(self):
        assert recover_verdict('{"verdict": "MAYBE"}') == (None, [])
        assert recover_verdict("I think it is confirmed.") == (None, [])


class TestGoldCorrection:
    def test_matching_target_is_left_alone(self):
        rec = _row("count_inflation", "NEEDS_MORE", "NEEDS_MORE")
        out, changed = build_curated_train.correct_to_gold(rec)
        assert changed is False and out is rec

    def test_mismatched_target_is_replaced_with_gold(self):
        rec = _row("identity_alias", "NEEDS_MORE", "CONFIRMED")
        out, changed = build_curated_train.correct_to_gold(rec)
        target = json.loads(out["messages"][-1]["content"])
        assert changed is True
        assert target["verdict"] == "NEEDS_MORE"
        assert target["citations"] == ["EV-000-0"]
        assert out["messages"][1] == rec["messages"][1]

    def test_mismatch_in_a_family_without_a_template_is_an_error(self):
        rec = _row("count_inflation", "NEEDS_MORE", "CONFIRMED")
        with pytest.raises(Exception):
            build_curated_train.correct_to_gold(rec)


class TestAuditkitScorers:
    class _Sample:
        def __init__(self, target):
            self.target = target

    def test_verdict_match_reads_broken_json(self):
        assert auditkit_score.verdict_match(self._Sample("CONFIRMED"), BROKEN) == 1.0
        assert auditkit_score.verdict_match(self._Sample("NEEDS_MORE"), BROKEN) == 0.0

    def test_false_confirm_only_counts_wrong_confirmations(self):
        assert auditkit_score.false_confirm(self._Sample("NEEDS_MORE"), BROKEN) == 1.0
        assert auditkit_score.false_confirm(self._Sample("CONFIRMED"), BROKEN) == 0.0

    def test_strict_json_requires_a_bare_object(self):
        assert auditkit_score.strict_json(None, '{"verdict": "CLEARED"}') == 1.0
        assert auditkit_score.strict_json(None, BROKEN) == 0.0
