import unittest
from pathlib import Path

from cyberwatchtower.advisor.context import build_advisor_context
from cyberwatchtower.advisor.questions import (
    QuestionIntent,
    answer_question,
    classify_question,
)
from cyberwatchtower.advisor.service import generate_advisory


def _context_and_advisory():
    current = {
        "security_score": {"score": 80, "risk_level": "MODERATE", "counts": {}},
        "findings": [
            {
                "finding_id": "current-risk",
                "title": "Exposed SSH service",
                "description": "SSH is listening on all interfaces.",
                "severity": "MEDIUM",
                "recommendation": "Restrict SSH to trusted networks.",
                "confidence": 90,
                "kind": "RISK",
                "assessment_state": "CONFIRMED",
                "evidence": ["Process: sshd", "Port: 22"],
            }
        ],
    }
    previous_finding = {
        "finding_id": "resolved-risk",
        "title": "Resolved Telnet service",
        "severity": "HIGH",
    }
    comparison = {
        "previous_score": 70,
        "change": 10,
        "trend": "IMPROVED",
        "new_findings": [current["findings"][0]],
        "resolved_findings": [previous_finding],
    }
    context = build_advisor_context(current, comparison, None)
    return context, generate_advisory(context)


class AdvisorQuestionTests(unittest.TestCase):
    def test_supported_questions_are_classified(self):
        self.assertEqual(
            classify_question("Why is this dangerous?"),
            QuestionIntent.WHY_DANGEROUS,
        )
        self.assertEqual(classify_question("What changed?"), QuestionIntent.WHAT_CHANGED)
        self.assertEqual(
            classify_question("What should I fix first?"),
            QuestionIntent.FIX_FIRST,
        )

    def test_why_answer_is_grounded_in_selected_finding(self):
        context, advisory = _context_and_advisory()

        answer = answer_question(
            "Why is this dangerous?",
            context,
            advisory,
            finding_id="current-risk",
        )

        self.assertEqual(answer.finding_ids, ("current-risk",))
        self.assertEqual(len(answer.action_ids), 1)
        self.assertIn("confirmed", answer.answer)

    def test_changed_answer_uses_new_and_resolved_records(self):
        context, advisory = _context_and_advisory()

        answer = answer_question("What changed?", context, advisory)

        self.assertIn("IMPROVED", answer.answer)
        self.assertIn("Exposed SSH service", answer.answer)
        self.assertIn("Resolved Telnet service", answer.answer)
        self.assertEqual(set(answer.finding_ids), {"current-risk", "resolved-risk"})

    def test_fix_first_returns_existing_action_and_finding_ids(self):
        context, advisory = _context_and_advisory()

        answer = answer_question("What should I fix first?", context, advisory)

        self.assertEqual(answer.action_ids, (advisory.actions[0].action_id,))
        self.assertEqual(answer.finding_ids, advisory.actions[0].finding_ids)
        self.assertIn(advisory.actions[0].action, answer.answer)

    def test_unsupported_question_does_not_speculate(self):
        context, advisory = _context_and_advisory()

        answer = answer_question("Who attacked this host?", context, advisory)

        self.assertEqual(answer.intent, QuestionIntent.UNKNOWN)
        self.assertFalse(answer.finding_ids)
        self.assertIn("cannot answer", answer.answer)

    def test_advisor_package_has_no_shell_execution_imports(self):
        advisor_dir = Path(__file__).parents[1] / "src" / "cyberwatchtower" / "advisor"
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in advisor_dir.rglob("*.py")
        )

        self.assertNotIn("import subprocess", source)
        self.assertNotIn("os.system", source)
        self.assertNotIn("from cyberwatchtower.scanner", source)


if __name__ == "__main__":
    unittest.main()
