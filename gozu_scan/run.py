"""Entrypoint of the action: scan the branch, then keep Jira in step with what the scan found.

Everything comes in through environment variables that action.yml sets from the action inputs.
"""

from __future__ import annotations

import fnmatch
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import llm, log, semgrep, snippet, trivy
from .contract import branch_label, finding_identity, issue_label
from .jira import AUTO_CLOSED_LABEL, Issue, JiraClient, key_number
from .models import Finding, JiraError, ScanError

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def split_list(value: str) -> list[str]:
    """Newlines and commas both separate items. Empty items are dropped."""
    return [item.strip() for item in value.replace(",", "\n").splitlines() if item.strip()]


# The most keys that GOZU_TICKET_KEYS holds. The variable only has to be filled to tell the later steps there is work.
MAX_TICKET_KEYS = 200

# The Fix branches of veil. A scan of one would only find the work of veil again. They are always skipped.
VEIL_BRANCH_PATTERNS = ("veil/*", "gozu/fix-*")


def skip_reason(
    head_ref: str, default_branch: str, skip_patterns: list[str], head_repo: str = "", repo: str = ""
) -> str | None:
    """Why this branch is not scanned, or None when it is.

    The default branch, the Fix branches of veil and a pull request from a fork are always skipped.
    GitHub gives a fork no secrets, so a scan of a fork cannot reach Jira.
    """
    if head_repo and repo and head_repo != repo:
        return f"the pull request comes from the fork {head_repo}, and GitHub gives a fork no secrets"
    if default_branch and head_ref == default_branch:
        return f"{head_ref} is the default branch of the repository"
    for pattern in (*VEIL_BRANCH_PATTERNS, *skip_patterns):
        if fnmatch.fnmatchcase(head_ref, pattern):
            return f"{head_ref} matches the skip pattern {pattern}"
    return None


def collect(scanners: list[str], workdir: str, trivy_skip_dirs: str, semgrep_config: str) -> list[Finding]:
    """Runs the chosen scanners at the same time and joins their findings."""
    jobs = {
        "trivy": lambda: trivy.scan(workdir, trivy_skip_dirs),
        "semgrep": lambda: semgrep.scan(workdir, semgrep_config),
    }
    unknown = [name for name in scanners if name not in jobs]
    if unknown:
        raise ScanError(f"Unknown scanner {unknown[0]}. The scanners are: {', '.join(jobs)}.")
    with ThreadPoolExecutor(max_workers=len(scanners) or 1) as pool:
        futures = [pool.submit(jobs[name]) for name in scanners]
        return [finding for future in futures for finding in future.result()]


@dataclass
class Options:
    workdir: str = "."
    scanners: list[str] = field(default_factory=lambda: ["trivy", "semgrep"])
    attach_snippet: bool = True
    auto_close: bool = True
    anthropic_key: str = ""
    anthropic_model: str = ""


@dataclass
class Outcome:
    created: list[tuple[str, Finding]] = field(default_factory=list)
    existing: int = 0
    reopened: list[str] = field(default_factory=list)
    closed: list[str] = field(default_factory=list)
    duplicates: list[str] = field(default_factory=list)


def _bonus(action: str, key: str, step) -> None:
    """A step after the ticket exists. Its failure is logged, and the ticket stays."""
    try:
        step()
    except Exception as e:
        log.warning(f"{action} failed for {key}: {e}")


def _create(jira: JiraClient, finding: Finding, opts: Options) -> str:
    snippet.attach_window(finding, opts.workdir)
    if opts.anthropic_key and finding.severity in llm.ELIGIBLE:
        try:
            finding.llm_explanation = llm.explain(finding, opts.anthropic_key, opts.anthropic_model)
        except Exception as e:
            log.warning(f"The explanation failed for {finding.key}: {e}")
    key = jira.create_ticket(finding)
    _bonus("The comment", key, lambda: jira.add_comment(key, finding.message))
    if opts.attach_snippet and finding.code_snippet:
        name = f"{finding.source_tool}-{finding_identity(finding)}.png"
        _bonus("The code snippet", key, lambda: jira.attach_png(key, name, snippet.render_png(finding)))
    return key


def _drop_if_duplicate(jira: JiraClient, key: str, finding: Finding, out: Outcome) -> bool:
    """Two runs at the same time can both find no ticket and both make one. The oldest ticket stays, the newer closes."""
    oldest = jira.oldest_with_label(issue_label(finding))
    if oldest is None or oldest.key == key or oldest.number > key_number(key):
        return False
    _bonus("The duplicate close", key, lambda: _close(jira, key, f"Duplicate of {oldest.key}. Closed automatically."))
    out.duplicates.append(key)
    return True


def _close(jira: JiraClient, key: str, comment: str) -> bool:
    if not jira.transition(key, "done"):
        log.warning(f"{key} has no transition to a done status, so it stays open.")
        return False
    jira.add_comment(key, comment)
    jira.change_labels(key, add=[AUTO_CLOSED_LABEL])
    return True


def _reopen(jira: JiraClient, issue: Issue, branch: str, out: Outcome) -> None:
    """A ticket that this action closed, for a finding that is back on the branch of the ticket.

    A ticket that a person closed stays closed. A ticket of another branch stays as it is (see `_belongs_to`).
    """

    def step() -> None:
        if not jira.transition(issue.key, "new"):
            log.warning(f"{issue.key} has no transition to a to-do status, so it stays closed.")
            return
        jira.change_labels(issue.key, remove=[AUTO_CLOSED_LABEL])
        jira.add_comment(issue.key, f"Reopened automatically. The finding is back on branch {branch}.")
        out.reopened.append(issue.key)

    _bonus("The reopen", issue.key, step)


def _belongs_to(issue: Issue, branch: str) -> bool:
    """A ticket is bound to the branch of its `branch-<name>` label, the branch of the scan that made it.

    A scan changes the status of the tickets of its own branch only. A finding can show on two branches with
    one ticket. A scan of the other branch cannot know if the finding is fixed on the branch of the ticket.
    """
    return branch_label(branch) in issue.labels


def sync(jira: JiraClient, found: list[Finding], branch: str, opts: Options) -> Outcome:
    """One ticket for each finding, ever: create the missing ones, reopen the returned ones, close the fixed ones.

    A ticket is bound to its branch. A scan reopens and closes the tickets of its own branch only.
    """
    out = Outcome()
    known = jira.existing_issues(found)
    seen: set[str] = set()
    for finding in found:
        label = issue_label(finding)
        # The same issue can come twice in one scan, and Jira's search can lag behind a ticket made seconds ago.
        if label in seen:
            continue
        seen.add(label)
        issue = known.get(label)
        if issue:
            out.existing += 1
            if issue.done and AUTO_CLOSED_LABEL in issue.labels and _belongs_to(issue, branch):
                _reopen(jira, issue, branch, out)
            continue
        key = _create(jira, finding, opts)
        if not _drop_if_duplicate(jira, key, finding, out):
            out.created.append((key, finding))
    if opts.auto_close:
        out.closed = auto_close(jira, seen, branch, opts.scanners)
    return out


def auto_close(jira: JiraClient, present: set[str], branch: str, scanners: list[str]) -> list[str]:
    """Closes the open tickets that a scan of this branch made and that this scan no longer reports.

    Only tickets with this branch's label count. A ticket of another branch, or of gozu on main, is left alone,
    because this scan cannot see those branches.
    """
    closed: list[str] = []
    for issue in jira.open_tickets_of_branch(branch_label(branch), scanners):
        labels = [label for label in issue.labels if label.startswith("issue-")]
        if not labels or any(label in present for label in labels):
            continue
        _bonus(
            "The auto-close",
            issue.key,
            lambda: _close(jira, issue.key, f"Closed automatically. The scan of branch {branch} no longer reports this finding.")
            and closed.append(issue.key),
        )
    return closed


def _write(path_variable: str, text: str) -> None:
    path = os.environ.get(path_variable)
    if path:
        with open(path, "a") as f:
            f.write(text)


def _summary(found: list[Finding], out: Outcome) -> str:
    counts = {s: sum(1 for f in found if f.severity.value == s) for s in _SEVERITY_ORDER}
    rows = "\n".join(f"| {s} | {n} |" for s, n in counts.items() if n)
    lines = [
        "## Gozu scan",
        f"{len(found)} findings: {len(out.created)} new tickets, {out.existing} already had a ticket, "
        f"{len(out.reopened)} reopened, {len(out.closed)} closed as fixed.",
        "",
        ("| Severity | Findings |\n|---|---|\n" + rows) if rows else "No findings.",
    ]
    if out.created:
        lines += ["", "| Ticket | Finding |\n|---|---|"] + [f"| {key} | {f.title} |" for key, f in out.created]
    return "\n".join(lines) + "\n"


def gate() -> int:
    """Runs first, before any scanner is installed, so a skipped branch costs almost nothing."""
    env = os.environ
    head_ref = env.get("GOZU_HEAD_REF", "").strip()
    reason = skip_reason(
        head_ref,
        env.get("GOZU_DEFAULT_BRANCH", "").strip(),
        split_list(env.get("GOZU_SKIP_BRANCHES", "")),
        env.get("GOZU_HEAD_REPO", "").strip(),
        env.get("GITHUB_REPOSITORY", "").strip(),
    )
    if reason:
        log.notice(f"Gozu scan skipped: {reason}.")
        _write("GITHUB_STEP_SUMMARY", f"## Gozu scan\nSkipped: {reason}.\n")
    _write("GITHUB_OUTPUT", f"skip={'true' if reason else 'false'}\n")
    return 0


def _flag(name: str, default: str = "true") -> bool:
    return os.environ.get(name, default).strip().lower() == "true"


def main() -> int:
    env = os.environ
    head_ref = env.get("GOZU_HEAD_REF", "").strip()
    repo = env.get("GITHUB_REPOSITORY", "").strip()
    if not repo or not head_ref:
        log.error("The repository or the branch is not known, so no ticket can be made.")
        return 1

    opts = Options(
        workdir=env.get("GOZU_WORKDIR", "."),
        scanners=split_list(env.get("GOZU_SCANNERS", "trivy,semgrep")),
        attach_snippet=_flag("GOZU_ATTACH_SNIPPET"),
        auto_close=_flag("GOZU_AUTO_CLOSE"),
        anthropic_key=env.get("GOZU_ANTHROPIC_KEY", "").strip(),
        anthropic_model=env.get("GOZU_ANTHROPIC_MODEL", "").strip(),
    )
    # A scan of one subdirectory cannot tell a fixed finding from a finding outside the directory.
    if opts.auto_close and not _flag("GOZU_FULL_SCAN"):
        log.notice("Auto-close is off, because only part of the repository is scanned.")
        opts.auto_close = False

    try:
        jira = JiraClient(env["GOZU_JIRA_URL"], env["GOZU_JIRA_EMAIL"], env["GOZU_JIRA_TOKEN"], env["GOZU_JIRA_PROJECT"])
        found = collect(opts.scanners, opts.workdir, env.get("GOZU_TRIVY_SKIP_DIRS", ""), env.get("GOZU_SEMGREP_CONFIG", "auto"))
        for finding in found:
            finding.repo_full_name = repo
            finding.branch = head_ref
            finding.commit_sha = env.get("GOZU_HEAD_SHA", "")
        out = sync(jira, found, head_ref, opts)
        # The new tickets first. A search can miss them for a few seconds, so they are added by name.
        todo_keys = list(dict.fromkeys([key for key, _ in out.created] + jira.todo_ticket_keys(branch_label(head_ref))))[:MAX_TICKET_KEYS]
    except KeyError as e:
        log.error(f"The input for {e.args[0]} is empty.")
        return 1
    except (ScanError, JiraError) as e:
        log.error(str(e))
        return 1

    _write("GITHUB_STEP_SUMMARY", _summary(found, out))
    # The steps after this one in the same job, such as veil, get the tickets to work on from this variable: the new
    # tickets and the other To Do tickets of this branch. Jira search can trail a new ticket by a few seconds,
    # so the new keys are listed by name. The word `none` means that nothing is left to do, so they can skip.
    keys = ",".join(todo_keys) or "none"
    _write("GITHUB_ENV", f"GOZU_TICKET_KEYS={keys}\n")
    _write(
        "GITHUB_OUTPUT",
        f"findings={len(found)}\ntickets-created={len(out.created)}\ntickets-existing={out.existing}\n"
        f"tickets-reopened={len(out.reopened)}\ntickets-closed={len(out.closed)}\n",
    )
    print(
        f"{len(found)} findings, {len(out.created)} tickets created, {out.existing} already ticketed, "
        f"{len(out.reopened)} reopened, {len(out.closed)} closed."
    )
    return 0


if __name__ == "__main__":
    sys.exit(gate() if sys.argv[1:] == ["gate"] else main())
