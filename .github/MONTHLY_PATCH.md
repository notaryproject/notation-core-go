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

1. **Plan review.** The controller stages the plan in the existing cycle issue in notaryproject/notation, which is the review surface. A current active maintainer of the notation CLI repository approves the plan with the exact, unedited comment `/approve-plan <plan_id>`. The approval binds the current issue body, the immutable plan, and the maintainer roster. Closing the issue, a manual approval input, or an old auto-approval flag does not bypass it. Later writes revalidate the comment, and a new plan needs a new approval.
2. **Qualified draft.** After Core's own source and artifact quality gates pass, the worker stages the release as a real GitHub draft release and opens a draft review issue only after the draft passes native quality checks. The signed tag may already be public before the draft is visible, so a draft does not hide the tag.
3. **Manual publish.** A maintainer reviews the draft and uses Publish release. Automation records the release ID and assets, observes that the same ID, tag, and assets were published manually, then runs anonymous public verification.
4. **Downstream wait.** Consumers of the release stay blocked until public verification succeeds.

Core's own branch reviews and required checks still apply. Reading draft releases needs a token with sufficient permission; this has been validated only with fixtures, not a live read, so it may block until maintainers finish setup. Automatic publishing is a separate future opt-in and is not implemented.

## Failure notifications

The controller comments on the shared CLI release-plan issue when a gate fails,
mentions maintainers, and links the repository, failed stage/run, evidence, and
blocked consumers. Reconciliation deduplicates alerts; failed retries get a new
comment. Approved scope stays unchanged. Subscribe to the issue for GitHub
notifications; email delivery depends on account settings. A failure before a
trusted issue exists remains visible in Actions. Notification never bypasses
checks or publishes a draft.

## Activation

The pin in the caller is a draft commit. Before this caller is merged or activated, rebind both the `uses:` ref and `worker_sha` to the final merged upstream notaryproject/notation commit. After all settings are verified in every repository and maintainers have approved, set `MONTHLY_PATCH_ENABLED=true`. Disabling is the reverse: set it to `false`.
