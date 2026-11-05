"""Regression checks for false readiness/completion and broken task traceability."""

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from validate_project import check_graph


class TaskGraphTests(unittest.TestCase):
    def setUp(self):
        self.task = dict(id="TASK-001", status="backlog", milestone="M1", approved=False,
                         approval_ref=None, owner="owner", reviewer="reviewer", requirement_ids=["REQ-001"],
                         source_refs=["Demo p1"], skills=["kapit-demo@1.0.0"], objective="Serve scoped variants",
                         acceptance_criteria=["Wrong scope denied"], verification_commands=[],
                         verification_procedure="Inspect actual API results", attempt_count=0,
                         dependencies=[], artifacts=[])
        self.requirements = [dict(id="REQ-001", task_ids="TASK-001")]
        self.state = dict(milestone_approvals={"M1": False}, max_repair_attempts=2,
                          completed_tasks=[], in_review_tasks=[], blocked_tasks=[])

    def check(self, tasks=None):
        return check_graph(tasks or [self.task], self.requirements, self.state,
                           {"owner", "reviewer"}, {"kapit-demo@1.0.0"})

    def test_unapproved_backlog_can_be_planned(self):
        self.assertEqual(self.check(), [])

    def test_unapproved_work_cannot_be_ready_or_done(self):
        for status in ("ready", "in_progress", "in_review", "done"):
            with self.subTest(status=status):
                self.task["status"] = status
                self.assertTrue(any("unapproved" in error for error in self.check()))

    def test_done_without_evidence_rejected(self):
        self.state["milestone_approvals"]["M1"] = True
        self.task.update(status="done", approved=True, approval_ref="Explicit scope")
        self.state["completed_tasks"] = ["TASK-001"]
        self.assertTrue(any("done requires" in error for error in self.check()))

    def test_missing_reciprocal_requirement_link_rejected(self):
        self.task["requirement_ids"] = ["REQ-002"]
        errors = self.check()
        self.assertTrue(any("unknown linked requirement" in error for error in errors))
        self.assertTrue(any("reciprocal" in error for error in errors))

    def test_dependency_cycle_is_not_ready_work(self):
        second = copy.deepcopy(self.task)
        second["id"] = "TASK-002"
        self.task["dependencies"] = ["TASK-002"]
        second["dependencies"] = ["TASK-001"]
        self.assertTrue(any("cycle" in error for error in self.check([self.task, second])))

    def test_checkpoint_cannot_invent_completion(self):
        self.state["completed_tasks"] = ["TASK-001"]
        self.assertTrue(any("disagrees" in error for error in self.check()))

    def test_ready_requires_completed_dependency(self):
        second = copy.deepcopy(self.task)
        second["id"] = "TASK-002"
        self.state["milestone_approvals"]["M1"] = True
        self.task.update(status="ready", approved=True, approval_ref="Scope approval", dependencies=["TASK-002"])
        second.update(approved=True, approval_ref="Scope approval")
        self.assertTrue(any("dependency is not done" in error for error in self.check([self.task, second])))

    def test_duplicate_task_and_requirement_ids_rejected(self):
        self.requirements.append(dict(self.requirements[0]))
        errors = self.check([self.task, dict(self.task)])
        self.assertTrue(any("duplicate task" in error for error in errors))
        self.assertTrue(any("duplicate requirement" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
