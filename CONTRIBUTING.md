## Contributing to AudioReach Graph Service

Hi there!
We’re thrilled that you’d like to contribute to this project.
Your help is essential for keeping this project great and for making it better.

## Branching Strategy

In general, contributors should develop on branches based off of `master` and pull requests should be made against `master`.

## Submitting a pull request

1. Please read our [code of conduct](CODE-OF-CONDUCT.md) and [license](LICENSE).
1. Fork and clone the repository.
1. Create a new branch based on `master`: `git checkout -b <my-branch-name> master`.
1. Make your changes, add tests, and make sure the tests still pass.
1. Commit your changes using the [DCO](http://developercertificate.org/). You can attest to the DCO by commiting with the **-s** or **--signoff** options or manually adding the "Signed-off-by":
1. Push to your fork and submit a pull request from your branch to `master`.
1. Pat yourself on the back and wait for your pull request to be reviewed.

Here are a few things you can do that will increase the likelihood of your pull request to be accepted:

- Follow the existing style where possible. We try and adhere to [pep8](https://www.python.org/dev/peps/pep-0008/).
- Write tests.
- Keep your change as focused as possible.
  If you want to make multiple independent changes, please consider submitting them as separate pull requests.
- Write a [good commit message](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html).
- It's a good idea to arrange a discussion with other developers to ensure there is consensus on large features, architecture changes, and other core code changes. PR reviews will go much faster when there are no surprises.

## CI/CD Gating

Every PR runs through a few automated checks before it can merge — think of them as a helpful safety net that keeps `master` stable for everyone.

### Pre-flight Checks

Runs automatically on every PR and push to `master`. This step performs static analysis and security scanning to catch common issues early, including:
- **Semgrep Scan** — static analysis for common code-quality and security issues.
- **Repolinter Check** — verifies the repo follows required file and structure conventions.
- **Copyright and License Check** — confirms new/changed files carry the correct copyright and license headers.
- **Commit Email Check** — validates that commit author emails meet project requirements.
- **Commit Message Check** — validates commit message format (subject/body length, etc.).

Separately, **ARMOR API/ABI Compatibility Checkers** run as their own required gate to catch breaking API/ABI changes.

### Build Gating

Kicks off whenever a PR is opened, updated, or reopened against `master`. The pipeline runs through below stages:
1. **Build** — compiles across all targets to make sure nothing is broken.
2. **Process image** — validates and packages the build artifacts.

### Run-time Validation

Runs automatically after a successful build gate. Applicable targets are dispatched to a LAVA board-farm for on-device testing, so we catch issues that only surface at runtime. Results are posted back to the PR. If the build gate fails or is skipped, run-time validation won't run.

### If a Check Fails

If any of these checks fail, review the corresponding job logs in the pull request's **Checks** tab and push fixes to the same branch to re-trigger the pipeline.
