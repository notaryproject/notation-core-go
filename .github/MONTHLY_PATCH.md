# Monthly patch release setup (notation-core-go)

This runbook lists the repository settings a maintainer must configure before the monthly patch release worker in this repository is activated. The design proposal lives only in the [notation](https://github.com/notaryproject/notation) CLI repository.

Core has no cross-Notation release prerequisite, but it still owns its own source and artifact quality gates. The central monthly timer and agent run only in the notation CLI repository. This repository contains only a thin caller workflow (`.github/workflows/monthly-patch-release.yml`) that accepts a dispatch from an authorized controller and runs the shared reusable worker in notaryproject/notation, pinned to an exact commit SHA. No shared scripts or tests are copied here. It holds no Copilot credential and has no assessment or controller schedule.

Nothing runs until `MONTHLY_PATCH_ENABLED` is set to `true`. Leave it `false` or unset until activation.

## Settings

1. **Actions and issues.** Enable GitHub Actions and Issues for the repository. In Settings > Actions > General, allow the public reusable workflow `notaryproject/notation/.github/workflows/monthly-patch-worker.yml` at the pinned SHA (add it to the allowed actions and reusable workflows list if the organization restricts them).
2. **Dependabot.** Keep Dependabot version updates for `gomod` and `github-actions` enabled on `main` (see `.github/dependabot.yml`).
3. **Merge settings.** Allow merge commits. The release flow merges exact reviewed heads with normal merge commits.
4. **Release branch.** Maintain the selected latest stable `release-X.Y` branch with a verified signed stable baseline. Protect it and `main` with the required status checks (the `Build`, `CodeQL`, and license checker workflows) and required reviews. Do not grant bypass to the automation identity.
5. **Secrets** (Settings > Secrets and variables > Actions > Secrets):
   - `MONTHLY_PATCH_TOKEN`: a token that authenticates (`GET /user`) as the user named by `MONTHLY_PATCH_ACTOR`. GitHub App installation tokens are not supported. Scope it to the three Notation repositories (notation, notation-go, notation-core-go) with contents, pull requests, issues, and actions write. Add workflows write only if GitHub Actions updates are in scope. The actor must have no branch-protection bypass.
   - `MONTHLY_PATCH_SIGNING_KEY`: the private signing key used to sign automation commits.
6. **Variables** (Settings > Secrets and variables > Actions > Variables):
   - `MONTHLY_PATCH_ACTOR`: the automation GitHub login.
   - `MONTHLY_PATCH_SIGNER_LOGIN`, `MONTHLY_PATCH_SIGNER_EMAIL`, and optionally `MONTHLY_PATCH_SIGNER_NAME`.
   - `MONTHLY_PATCH_ENABLED`: keep `false` or unset until activation.
7. **Signing key.** Register only the PUBLIC key on the automation account. The token, the signing key, and the signer identity must all belong to the same actor (`MONTHLY_PATCH_ACTOR`).

## Manual-first release lifecycle

The first releases are published by a maintainer, not by automation. There is no auto-approval flag to set.

1. **Plan review.** Each repository has one release issue with its month, current/proposed versions, own changes, dependencies, status, and maintainer action. The CLI issue also provides overall status and links to the library issues without copying their changes. A current active CLI maintainer approves the overall plan with the exact, unedited comment `/approve`. The approval binds the displayed scope, immutable plan, and maintainer roster. Later writes revalidate it; a changed plan requires fresh approval. Closing the issue, a manual dispatch, or an old auto-approval flag does not bypass this gate.
2. **Qualified draft.** After Core's own source and artifact quality gates pass, the worker stages a real GitHub draft release. Once native draft checks pass, it posts the review request and evidence to Core's existing release issue, not a second review issue.
3. **Manual publish.** A maintainer reviews the draft and uses Publish release. Automation records the release ID and assets, observes that the same ID, tag, and assets were published manually, then runs anonymous public verification.
4. **Downstream wait.** Consumers of the release stay blocked until public verification succeeds.

Core's own branch reviews and required checks still apply. Reading draft releases needs a token with sufficient permission; this has been validated only with fixtures, not a live read, so it may block until maintainers finish setup. Automatic publishing is a separate future opt-in and is not implemented.

Assessment also reviews new `main` commits for possible bug fixes applicable to the stable release line. It presents evidence-backed candidates separately for maintainer review, not as automatically approved backports. Features are excluded, and adding a fix to an approved scope requires a new approval.

The current worker creates the signed tag before draft review. A GitHub draft does not hide that tag or prevent Go module downloads. The required maintainer approval before final stable-tag creation is not implemented; official stable releases must remain disabled until that separate gate is implemented and validated.

## Failure notifications

The controller reports errors and blockers in the affected repository's release
issue, mentions its maintainers, and links the failed stage/run and evidence.
Dependent issues receive only a concise blocker and a link to the affected issue.
The same issue receives the draft-ready review request. Routine progress does not
generate comments. Reconciliation deduplicates alerts; a new failed retry can
produce a new alert without changing approved scope.

Subscribe to Core's release issue for GitHub notifications; email delivery
depends on account settings. A failure before a trusted issue exists remains
visible in Actions. Notifications never bypass checks or publish a draft.

## Activation

The pin in the caller is a draft commit. Before this caller is merged or activated, rebind both the `uses:` ref and `worker_sha` to the final merged upstream notaryproject/notation commit. Keep official stable releases disabled until the pre-tag approval gap above is resolved. After that gate and all settings are verified and maintainers approve activation, set `MONTHLY_PATCH_ENABLED=true`. Set it to `false` to disable future execution.
