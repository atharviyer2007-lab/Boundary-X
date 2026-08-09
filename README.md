# BOUNDARY-X

Minimum-causal-change security and resilience analysis for cloud DevOps.

Given a batch of infrastructure changes (Terraform, Kubernetes, IAM, CI/CD,
networking), BOUNDARY-X doesn't just flag every risky-looking change — it
isolates the *one* change that actually created a new security boundary
crossing, shows its blast radius, and proposes the smallest fix.

Point-in-time scanners (AWS Security Hub, Resilience Hub, IAM Access
Analyzer) tell you what's risky right now. BOUNDARY-X tells you *which
change, across a diff, caused the risk* — causal attribution, not just
detection.

## How it works

1. Model the relevant slice of infrastructure as a directed graph:
   identity → IAM trust boundary → role → services → data.
2. Apply a proposed batch of changes to build the "after" graph and compare
   it against the unmodified "before" graph.
3. If the "after" graph exposes a path from an untrusted identity to a
   sensitive resource that didn't exist "before," search for the minimum
   causal change: the smallest subset of the proposed changes that, if
   reverted, restores the safe state. This uses leave-one-out (then
   leave-N-out) counterfactual testing rather than just flagging the
   highest-severity change — that's the actual differentiator.
4. Compute blast radius by BFS downstream of the boundary crossing.
5. Emit the smallest remediation: reverting exactly the causal change.

## Demo scenario

17 synthetic infrastructure changes are submitted in one batch. Only one —
change #7, a GitHub OIDC trust condition widened from `repo:trusted-org/*`
to `repo:*` — lets any GitHub repository assume `prod-deploy-role` and
reach `customer-data`. The engine finds this by counterfactual search, not
a hardcoded lookup.

## Project structure

| File | What it is |
|---|---|
| `app.py` | Flask backend: models the infrastructure as a graph, runs the counterfactual search for the minimum causal change, computes blast radius, persists each analysis to SQLite, and serves the frontend + JSON API |
| `index.html`, `styles.css`, `script.js` | Frontend: landing page, 17-change input screen, analyzing sequence, funnel reveal, before/after attack-path graph, blast radius counters, remediation flow, dashboard |
| `requirements.txt` | Python dependencies |
| `boundaryx.db` | SQLite file created on first run (gitignored) — one row per completed analysis |

The frontend and backend are wired together: `script.js` calls
`/api/changes` and `/api/analyze` and renders every number, diff, and graph
node from the live response — nothing in the analysis flow (funnel counts,
attack path, blast radius, remediation diff) is hardcoded on the client.
The "Recent analyses" list on the dashboard is likewise real: every call to
`/api/analyze` or `/api/ingest-diff` is written to a local SQLite database
(`boundaryx.db`, created automatically on first run), so the dashboard and
report downloads reflect actual past runs and survive a server restart.

## Running it

```bash
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000` in a browser.

To run the analysis engine standalone from the terminal, without the web
server:

```bash
python app.py --demo
```

## API

- `GET /api/changes` — the list of proposed changes in this batch (id, domain, description)
- `POST /api/analyze` — full analysis: before/after safety, attack path, graph, minimum causal change(s), blast radius, remediation diff, and `search_truncated`. Persists the result and returns it under `analysis_id`.
- `POST /api/ingest-diff` — parse a pasted unified diff into changes and run the same analysis. Also persists the result.
- `GET /api/recent?limit=10` — summary of the most recent persisted analyses (status, blast radius, causal change), newest first
- `GET /api/report/<analysis_id>` — the full stored result for a past analysis, for regenerating its report
- `GET /api/snapshot` — live infra snapshot compared against the known-good baseline
- `GET /api/health` — health check

## Notes on the engine

- `find_minimum_causal_changes` tests subsets up to size 3 by default and is
  unbounded — an exhaustive `O(n^k)` search, fine for the demo's 17 changes
  or the unit tests, but not something you'd want to run unguarded on
  arbitrary user-submitted input. `run_analysis()` (and therefore both
  `/api/analyze` and `/api/ingest-diff`) instead uses
  `find_minimum_causal_changes_bounded()`, which gives up gracefully once it
  exceeds a time budget (2s by default) or a combination-count budget
  (20,000 by default) and reports `search_truncated: true` in the result
  rather than continuing to grind. In practice the true minimum cause is
  usually small (subset size 1), so this resolves in milliseconds even for
  batches of 50+ changes — the budget only bites on the genuinely hard case
  of a boundary crossing that requires several changes acting together in a
  large batch.
- The baseline graph (`build_baseline_graph()`) models one illustrative
  slice (the OIDC trust edge from the demo scenario). Diffs that touch that
  exact edge reuse it directly. Any *other* IAM condition widened to `"*"`,
  or a network CIDR widened to `0.0.0.0/0`/`::/0`, is handled generically:
  `changes_from_diff()` detects the widening and `make_generic_widening_effect()`
  models the affected resource as a new node reachable from an untrusted
  identity, wired to whatever sensitive data exists in the graph — so
  causal attribution, blast radius, and remediation all work on diffs
  outside the demo scenario too, not just the one hardcoded edge. It's
  still a simplification (real topology would come from actual Terraform/
  K8s/IAM plan output rather than the diff text alone), but pasting an
  arbitrary security-relevant diff now produces a real finding instead of
  a flag with no graph behind it.
