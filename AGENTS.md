# Repository Working Rules

These instructions apply to the entire repository.

## Commits

- Commit completed work automatically at logical, independently reviewable
  checkpoints.
- Keep each commit focused on one coherent change. Do not mix unrelated fixes,
  refactors, generated artifacts, or formatting churn.
- Before committing, run the checks relevant to the files changed and review
  the staged diff for secrets, generated artifacts, and unrelated changes.
- Use Conventional Commits:

  ```text
  <type>[(optional scope)][!]: <imperative description>
  ```

- Encouraged scopes include `client`, `server`, `protocol`, `viewer`, `capture`,
  `browser`, `scripts`, `docs`, `build`, and `ci`. A scope is encouraged when it
  makes the affected area clearer, but it is not required.
- Use these commit types:
  - `feat`: user-visible functionality
  - `fix`: defect correction
  - `perf`: performance improvement
  - `refactor`: behavior-preserving restructuring
  - `test`: test-only changes
  - `docs`: documentation-only changes
  - `build`: build system or dependency changes
  - `ci`: continuous-integration changes
  - `chore`: repository maintenance that fits no other type
  - `revert`: revert of an earlier commit
- Write the subject in the imperative mood, keep it concise, and omit a trailing
  period.
- Mark breaking changes with `!` and explain them in a `BREAKING CHANGE:` footer
  when the subject alone is insufficient.
- Do not include AI attribution, AI-assistance statements, generated-by notices,
  or AI co-author trailers in commit messages.
- Commit signing and `Signed-off-by` trailers are not currently required.

## Versioning

- Use Semantic Versioning.
- Derive release impact from Conventional Commits:
  - `fix` increments the patch version.
  - `feat` increments the minor version.
  - A breaking change increments the major version at or above `1.0.0`.
  - A breaking change increments the minor version below `1.0.0`.
- Other commit types do not require a version increment unless they contain a
  breaking change.
- Do not generate a changelog, create a release commit, or create a version tag
  unless explicitly requested.
