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

## Activation

The pin in the caller is a draft commit. Before this caller is merged or activated, rebind both the `uses:` ref and `worker_sha` to the final merged upstream notaryproject/notation commit. After all settings are verified in every repository and maintainers have approved, set `MONTHLY_PATCH_ENABLED=true`. Disabling is the reverse: set it to `false`.
