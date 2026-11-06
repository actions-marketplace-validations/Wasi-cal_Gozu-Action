# Gozu Scan to Jira

A GitHub Action that scans a pull request's branch with **Trivy** (vulnerabilities, secrets, misconfigurations) and **Semgrep**, then creates a Jira ticket for every finding. It is the CI version of gozu: no Docker, no Temporal, no Postgres, and no gozu install. The code uses only the Python standard library.

## Usage

```yaml
name: Gozu scan
on:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    concurrency:
      group: gozu-scan-${{ github.event.pull_request.number }}
      cancel-in-progress: false
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: calfus/gozu-action@v1
        with:
          jira-url: https://your-team.atlassian.net
          jira-email: ${{ secrets.JIRA_EMAIL }}
          jira-api-token: ${{ secrets.JIRA_API_TOKEN }}
          jira-project-key: GR
```

To fix the tickets with [veil](https://github.com/Wasi-cal/veil), add a step that runs `Wasi-cal/veil@v1` after this action, in the same job. The action gives veil the To Do tickets of the branch, with the ones it just made, so veil needs no wait and no setting. When no ticket of the branch is left to do, veil skips its run. When you merge a Fix PR, the next run of this scan closes the tickets whose finding is gone.

## Which branches are scanned

The action skips a run, before it installs anything, when:

- the head branch is the default branch of the repository,
- the head branch is a Fix branch of veil (`veil/*` or `gozu/fix-*`),
- the pull request comes from a fork (GitHub gives a fork no secrets), or
- the head branch matches a pattern in `skip-branches`.

## Inputs

| Input | Default | |
|---|---|---|
| `jira-url`, `jira-email`, `jira-api-token`, `jira-project-key` | required | Jira Cloud connection. Pass the token from a secret. |
| `skip-branches` | empty | Extra glob patterns to skip, one per line or comma separated. |
| `scanners` | `trivy,semgrep` | Which scanners run. |
| `working-directory` | `.` | Directory to scan, relative to the checkout. |
| `trivy-skip-dirs` | `.git,node_modules` | Directories Trivy does not read. |
| `semgrep-config` | `auto` | Semgrep rules. `auto` sends metrics to semgrep.dev. Use `p/security-audit` for a fixed pack. |
| `attach-code-snippet` | `true` | Attach a PNG of the flagged code to each new ticket. |
| `auto-close` | `true` | Close fixed tickets and reopen returned ones (see below). Off when `working-directory` is not `.`. |
| `anthropic-api-key` | empty | Optional. New CRITICAL and HIGH tickets get a plain-English explanation and fix. |
| `anthropic-model` | `claude-opus-5-5` | Model for the explanations. |
| `trivy-version`, `semgrep-version` | pinned | Tool versions to install. |

Outputs: `findings`, `tickets-created`, `tickets-existing`, `tickets-reopened`, `tickets-closed`.

## What it does

**One ticket for each finding, ever.**
- Every finding gets a ticket, at every severity. There is no cap per run.
- Before it creates a ticket, the action looks in the whole Jira project, in any status, for the finding's `issue-<id>` label (Gozu ticket contract). A re-run, a later push, another branch and tickets from gozu all find the same ticket, so none repeats.
- Two runs at the same time can both miss a ticket that is being made. Each run checks after it creates one. The oldest ticket stays, and the newer one closes as a duplicate. Run the job with a `concurrency` group per repository to make this rare.
- The same issue twice in one scan makes one ticket.

**A ticket is bound to its branch.**
- A ticket has the label `branch-<name>` of the branch of the scan that made it. This is the branch of the ticket for its whole life.
- A scan changes the status of the tickets of its own branch only. It closes them and reopens them. A scan never closes or reopens a ticket of another branch, or a ticket that gozu made on `main`.
- The reason: the finding id has no branch, so one ticket can stand for the same finding on two branches. A scan of one branch cannot see if the finding is fixed on the other branch. A reopen or a close of that ticket would be a false alarm.
- When a scan finds a finding that has a ticket of another branch, the ticket stays as it is. The scan counts it as "already ticketed" and makes no new ticket.
- Example: the finding is fixed on `feature-a` and the ticket closes. Later a scan of the older branch `feature-b`, which has no fix, reports the finding again. The ticket stays closed.

**Auto-close and reopen.**
- When a scan of a branch no longer reports a finding, the open ticket that a scan of that branch made closes. It gets a comment and the label `gozu-auto-closed`. The transition goes to whatever "done" status the project's workflow has.
- Only tickets with this branch's `branch-<name>` label and one of the scanners that ran are considered.
- If a finding comes back on the same branch, the ticket that this action closed reopens, so the finding still has one ticket. A ticket that a person closed (no `gozu-auto-closed` label) stays closed.

**Tickets.**
- They follow the contract exactly: title `repo | file | line | title`, labels `issue-<id>`, `<tool>` and `branch-<branch>`, the same Details list, issue type Bug. veil can read them.
- Each new ticket gets a comment with the scanner's message, a PNG of the code around the finding, a link to the finding, and a place in the active sprint when the project has one. Each of these is best effort: a failure is a warning and the ticket stays.
- With `anthropic-api-key`, CRITICAL and HIGH tickets get an explanation that replaces the raw message.
- A finding that may hold a secret (every Trivy secret, and Semgrep rules with "secret" or "hardcoded" in the name) never has its code attached to Jira or sent to the LLM.

**Speed.** The action caches the Semgrep venv (by tool versions, operating system and Python version) and the Trivy vulnerability database (for one day). A run after the first one installs nothing and downloads only a database that is out of date.

**The job.** It runs on Linux and macOS runners (it needs `bash` and `python3`). It fails only when something is broken (a scanner cannot run, Jira refuses a request). Findings never fail it. A step summary lists what was created. Pull requests from forks are not supported: GitHub gives them no secrets.

## Develop

```bash
python3 -m unittest discover -s tests -t .
```

`tests/contract/golden_tickets.json` is a copy of the golden file that gozu, Gozurion and veil share. Keep it equal to theirs.

## Publish to Marketplace

1. Make the repository public. Marketplace takes one action per repository, with `action.yml` at the root.
2. Accept GitHub's Marketplace Developer Agreement on the repository (Releases, then "Publish this Action").
3. Tag a release (`v1.0.0`) and move the `v1` tag to it.
