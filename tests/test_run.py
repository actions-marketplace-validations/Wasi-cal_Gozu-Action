import os
import unittest
from unittest.mock import patch

from gozu_scan import run
from gozu_scan.contract import branch_label, issue_label
from gozu_scan.jira import AUTO_CLOSED_LABEL, Issue, JiraClient, jql_quote
from gozu_scan.models import Finding, JiraError, Severity


def finding(rule: str, line: int | None = 1, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        key=rule,
        title=rule,
        severity=severity,
        component="app.py",
        line=line,
        message="m",
        finding_type="vulnerability",
        deep_link="https://example.invalid",
        source_tool="semgrep",
        repo_full_name="acme/app",
        branch="feature/login",
        rule_key=rule,
    )


class FakeJira:
    """Records every call. `issues` is {issue label: Issue}, `open_tickets` is what the branch search returns."""

    def __init__(self, issues=None, open_tickets=None, oldest=None):
        self.issues = issues or {}
        self.open_tickets = open_tickets or []
        self.oldest = oldest
        self.calls = []
        self.next_key = 100

    def existing_issues(self, findings):
        return self.issues

    def open_tickets_of_branch(self, label, tools):
        self.calls.append(("open_tickets_of_branch", label, tuple(tools)))
        return self.open_tickets

    def oldest_with_label(self, label):
        return self.oldest

    def create_ticket(self, f):
        self.next_key += 1
        key = f"VT-{self.next_key}"
        self.calls.append(("create", key, f.rule_key))
        return key

    def add_comment(self, key, text):
        self.calls.append(("comment", key, text))

    def attach_png(self, key, name, content):
        self.calls.append(("attach", key))

    def transition(self, key, category):
        self.calls.append(("transition", key, category))
        return True

    def change_labels(self, key, add=(), remove=()):
        self.calls.append(("labels", key, tuple(add), tuple(remove)))

    def made(self):
        return [c[2] for c in self.calls if c[0] == "create"]


OPTS = run.Options(auto_close=False, attach_snippet=False)


class SkipRules(unittest.TestCase):
    def test_the_default_branch_is_always_skipped(self):
        self.assertIn("default branch", run.skip_reason("develop", "develop", []))

    def test_a_veil_branch_is_skipped_by_the_default_pattern(self):
        self.assertIsNotNone(run.skip_reason("veil/gr-7", "main", ["veil/*"]))

    def test_a_sister_branch_is_scanned(self):
        self.assertIsNone(run.skip_reason("feature/login", "main", ["veil/*"]))

    def test_the_fix_branches_of_veil_are_skipped_with_no_pattern_at_all(self):
        for branch in ("veil/fix-vt-1", "gozu/fix-vt-1"):
            self.assertIsNotNone(run.skip_reason(branch, "main", []), branch)

    def test_a_pull_request_from_a_fork_is_skipped(self):
        reason = run.skip_reason("feature/login", "main", [], head_repo="eve/app", repo="acme/app")

        self.assertIn("fork", reason)

    def test_a_pull_request_from_the_same_repository_is_scanned(self):
        self.assertIsNone(run.skip_reason("feature/login", "main", [], head_repo="acme/app", repo="acme/app"))

    def test_an_event_with_no_pull_request_is_scanned(self):
        self.assertIsNone(run.skip_reason("feature/login", "main", [], head_repo="", repo="acme/app"))

    def test_patterns_split_on_newlines_and_commas(self):
        self.assertEqual(run.split_list("veil/*\n develop ,release/*"), ["veil/*", "develop", "release/*"])


class NoRepeats(unittest.TestCase):
    def test_only_findings_without_a_ticket_get_one_and_a_repeat_in_the_scan_is_made_once(self):
        a, b = finding("a"), finding("b")
        jira = FakeJira(issues={issue_label(a): Issue("VT-9", [issue_label(a)], done=False)})

        out = run.sync(jira, [a, b, finding("b")], "feature/login", OPTS)

        self.assertEqual(jira.made(), ["b"])
        self.assertEqual((len(out.created), out.existing), (1, 1))

    def test_a_finding_whose_ticket_is_done_is_not_ticketed_again(self):
        a = finding("a")
        jira = FakeJira(issues={issue_label(a): Issue("VT-9", [issue_label(a)], done=True)})

        run.sync(jira, [a], "feature/login", OPTS)

        self.assertEqual(jira.made(), [])
        self.assertNotIn("transition", [c[0] for c in jira.calls])

    def test_a_ticket_that_this_action_closed_is_reopened_when_the_finding_returns_on_its_branch(self):
        a = finding("a")
        labels = [issue_label(a), branch_label("feature/login"), AUTO_CLOSED_LABEL]
        jira = FakeJira(issues={issue_label(a): Issue("VT-9", labels, done=True)})

        out = run.sync(jira, [a], "feature/login", OPTS)

        self.assertEqual(out.reopened, ["VT-9"])
        self.assertIn(("transition", "VT-9", "new"), jira.calls)
        self.assertIn(("labels", "VT-9", (), (AUTO_CLOSED_LABEL,)), jira.calls)
        self.assertEqual(jira.made(), [])

    def test_a_closed_ticket_of_another_branch_stays_closed_when_the_finding_shows_on_this_branch(self):
        a = finding("a")
        labels = [issue_label(a), branch_label("gozu-veil-integration"), AUTO_CLOSED_LABEL]
        jira = FakeJira(issues={issue_label(a): Issue("VT-9", labels, done=True)})

        out = run.sync(jira, [a], "veil-test", OPTS)

        self.assertEqual(out.reopened, [])
        self.assertEqual(out.existing, 1)
        self.assertEqual(jira.made(), [])
        self.assertEqual(jira.calls, [])

    def test_a_ticket_that_a_person_closed_stays_closed(self):
        a = finding("a")
        jira = FakeJira(issues={issue_label(a): Issue("VT-9", [issue_label(a)], done=True)})

        out = run.sync(jira, [a], "feature/login", OPTS)

        self.assertEqual(out.reopened, [])
        self.assertNotIn("transition", [c[0] for c in jira.calls])

    def test_two_runs_at_once_leave_the_oldest_ticket_open_and_close_the_newer(self):
        a = finding("a")
        jira = FakeJira(oldest=Issue("VT-50", [issue_label(a)], done=False))

        out = run.sync(jira, [a], "feature/login", OPTS)

        self.assertEqual(out.created, [])
        self.assertEqual(out.duplicates, ["VT-101"])
        self.assertIn(("transition", "VT-101", "done"), jira.calls)

    def test_the_newer_ticket_stays_when_it_is_the_oldest(self):
        a = finding("a")
        jira = FakeJira(oldest=Issue("VT-101", [issue_label(a)], done=False))

        out = run.sync(jira, [a], "feature/login", OPTS)

        self.assertEqual([key for key, _ in out.created], ["VT-101"])


class AutoClose(unittest.TestCase):
    OPTS = run.Options(auto_close=True, attach_snippet=False)

    def test_a_ticket_of_this_branch_whose_finding_is_gone_is_closed(self):
        still, gone = finding("still"), finding("gone")
        jira = FakeJira(
            issues={issue_label(still): Issue("VT-1", [issue_label(still)], done=False)},
            open_tickets=[Issue("VT-1", [issue_label(still)], False), Issue("VT-2", [issue_label(gone)], False)],
        )

        out = run.sync(jira, [still], "feature/login", self.OPTS)

        self.assertEqual(out.closed, ["VT-2"])
        self.assertIn(("transition", "VT-2", "done"), jira.calls)
        self.assertIn(("labels", "VT-2", (AUTO_CLOSED_LABEL,), ()), jira.calls)
        self.assertNotIn(("transition", "VT-1", "done"), jira.calls)

    def test_only_this_branch_and_the_scanners_that_ran_are_searched(self):
        jira = FakeJira()

        run.sync(jira, [], "feature/login", run.Options(auto_close=True, attach_snippet=False, scanners=["trivy"]))

        self.assertIn(("open_tickets_of_branch", branch_label("feature/login"), ("trivy",)), jira.calls)

    def test_a_ticket_without_an_issue_label_is_left_alone(self):
        jira = FakeJira(open_tickets=[Issue("VT-3", ["manual"], False)])

        self.assertEqual(run.sync(jira, [], "feature/login", self.OPTS).closed, [])

    def test_a_ticket_with_no_done_transition_stays_open(self):
        jira = FakeJira(open_tickets=[Issue("VT-2", ["issue-x"], False)])
        jira.transition = lambda key, category: False

        self.assertEqual(run.sync(jira, [], "feature/login", self.OPTS).closed, [])


class Environment(unittest.TestCase):
    ENV = {
        "GOZU_HEAD_REF": "feature/login",
        "GITHUB_REPOSITORY": "acme/app",
        "GOZU_JIRA_URL": "https://jira.example.com",
        "GOZU_JIRA_EMAIL": "bot@example.com",
        "GOZU_JIRA_TOKEN": "tok",
        "GOZU_JIRA_PROJECT": "VT",
        "GOZU_SCANNERS": "semgrep",
        "GOZU_FULL_SCAN": "true",
    }

    def setUp(self):
        patcher = patch.dict(os.environ, self.ENV, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        # No test of the run may reach a real Jira.
        todo = patch.object(JiraClient, "todo_ticket_keys", return_value=[])
        todo.start()
        self.addCleanup(todo.stop)


class Main(Environment):
    def test_the_findings_are_stamped_with_the_repo_and_the_branch(self):
        found = [finding("a")]
        with patch.object(run, "collect", return_value=found), patch.object(run, "sync") as sync:
            sync.return_value = run.Outcome()
            self.assertEqual(run.main(), 0)

        self.assertEqual((found[0].repo_full_name, found[0].branch), ("acme/app", "feature/login"))

    def test_a_skipped_branch_needs_no_credentials(self):
        with patch.dict(os.environ, {"GOZU_HEAD_REF": "veil/gr-7", "GOZU_SKIP_BRANCHES": "veil/*", "GOZU_JIRA_TOKEN": ""}):
            with patch.object(run, "collect", side_effect=AssertionError("No scan may run.")):
                self.assertEqual(run.gate(), 0)

    def test_a_fork_pull_request_is_skipped_by_the_gate(self):
        with patch.dict(os.environ, {"GOZU_HEAD_REPO": "eve/app"}):
            with patch.object(run, "_write") as write:
                self.assertEqual(run.gate(), 0)

        write.assert_any_call("GITHUB_OUTPUT", "skip=true\n")

    def test_the_variable_lists_the_new_tickets_and_the_to_do_tickets_of_the_branch(self):
        outcome = run.Outcome(created=[("VT-1", finding("a")), ("VT-2", finding("b"))])
        with patch.object(run, "collect", return_value=[]), patch.object(run, "sync", return_value=outcome):
            with patch.object(JiraClient, "todo_ticket_keys", return_value=["VT-2", "VT-5"]) as todo:
                with patch.object(run, "_write") as write:
                    self.assertEqual(run.main(), 0)

        write.assert_any_call("GITHUB_ENV", "GOZU_TICKET_KEYS=VT-1,VT-2,VT-5\n")
        todo.assert_called_once_with(branch_label("feature/login"))

    def test_older_to_do_tickets_keep_the_variable_filled_when_the_run_made_none(self):
        with patch.object(run, "collect", return_value=[]), patch.object(run, "sync", return_value=run.Outcome()):
            with patch.object(JiraClient, "todo_ticket_keys", return_value=["VT-7"]):
                with patch.object(run, "_write") as write:
                    run.main()

        write.assert_any_call("GITHUB_ENV", "GOZU_TICKET_KEYS=VT-7\n")

    def test_the_variable_says_none_when_nothing_is_left_to_do(self):
        with patch.object(run, "collect", return_value=[]), patch.object(run, "sync", return_value=run.Outcome()):
            with patch.object(JiraClient, "todo_ticket_keys", return_value=[]):
                with patch.object(run, "_write") as write:
                    run.main()

        write.assert_any_call("GITHUB_ENV", "GOZU_TICKET_KEYS=none\n")

    def test_the_variable_holds_at_most_200_keys(self):
        many = [f"VT-{n}" for n in range(1, 301)]
        with patch.object(run, "collect", return_value=[]), patch.object(run, "sync", return_value=run.Outcome()):
            with patch.object(JiraClient, "todo_ticket_keys", return_value=many):
                with patch.object(run, "_write") as write:
                    run.main()

        value = next(c.args[1] for c in write.call_args_list if c.args[0] == "GITHUB_ENV")
        self.assertEqual(len(value.strip().split("=", 1)[1].split(",")), 200)

    def test_a_jira_failure_fails_the_job(self):
        with patch.object(run, "collect", return_value=[]), patch.object(run, "sync", side_effect=JiraError("down")):
            self.assertEqual(run.main(), 1)

    def test_a_missing_input_fails_the_job(self):
        del os.environ["GOZU_JIRA_TOKEN"]

        self.assertEqual(run.main(), 1)

    def test_auto_close_is_off_when_only_part_of_the_repository_is_scanned(self):
        os.environ["GOZU_FULL_SCAN"] = "false"
        with patch.object(run, "collect", return_value=[]), patch.object(run, "sync") as sync:
            sync.return_value = run.Outcome()
            run.main()

        self.assertFalse(sync.call_args.args[3].auto_close)


class JiraSearch(unittest.TestCase):
    def test_one_search_covers_many_findings_pages_are_followed_and_the_oldest_ticket_wins(self):
        client = JiraClient("https://jira.example.com", "e", "t", "VT")
        a = finding("a")
        label = issue_label(a)

        def raw(key, labels, category="new"):
            return {"key": key, "fields": {"labels": labels, "status": {"statusCategory": {"key": category}}}}

        pages = [
            {"issues": [raw("VT-7", [label, "x"])], "isLast": False, "nextPageToken": "n"},
            {"issues": [raw("VT-3", [label], "done")], "isLast": True},
        ]
        with patch.object(client, "_request", side_effect=pages) as request:
            found = client.existing_issues([a, finding("b")])

        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args.args[2]["nextPageToken"], "n")
        self.assertEqual((found[label].key, found[label].done), ("VT-3", True))

    def test_the_to_do_tickets_of_a_branch_are_searched_by_the_branch_label(self):
        client = JiraClient("https://jira.example.com", "e", "t", "VT")

        def raw(key):
            return {"key": key, "fields": {"labels": [], "status": {"statusCategory": {"key": "new"}}}}

        with patch.object(client, "_request", return_value={"issues": [raw("VT-3"), raw("VT-1")]}) as request:
            keys = client.todo_ticket_keys("branch-feature/login")

        self.assertEqual(keys, ["VT-1", "VT-3"])
        jql = request.call_args.args[2]["jql"]
        self.assertIn('labels = "branch-feature/login"', jql)
        self.assertIn('statusCategory = "To Do"', jql)

    def test_a_branch_name_cannot_break_out_of_the_query(self):
        self.assertEqual(jql_quote('x" OR project = Y OR labels = "'), '"x\\" OR project = Y OR labels = \\""')
        self.assertEqual(jql_quote("a\\b"), '"a\\\\b"')


if __name__ == "__main__":
    unittest.main()
