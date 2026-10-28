# Contributing

We warmly welcome and greatly appreciate contributions from the
community. By participating you agree to the [code of
conduct](https://github.com/warehouse-pg/whpg-pgaudit/blob/WHPG_6/CODE-OF-CONDUCT.md).
Overall, we follow WHPG's comprehensive contribution policy. Please
refer to it [here](https://github.com/warehouse-pg/warehouse-pg/blob/main/CONTRIBUTING.md)
for details.

## Getting Started

* Fork the `whpg-pgaudit` repository on GitHub
* Clone the forked repository
* Follow the README to set up your environment and run the tests

## Creating a change

* Create your own feature branch (e.g. `git checkout -b
  my_feature_branch`) and make changes on this branch.
* Try and follow similar coding styles as found throughout the code
  base.
* Make commits as logical units for ease of reviewing.
* Rebase on `origin/WHPG_6` often to stay in sync. Changes for
  WarehousePG 7 and 19 go to the `WHPG_7` branch.
* Add or update tests to cover your code. Regression tests live under
  [`sql`](sql) and [`expected`](expected). Build
  and run them as described in the README; the suite must pass with
  both `PGOPTIONS='-c optimizer=off'` and `PGOPTIONS='-c optimizer=on'`,
  as the packaging smoke test runs it both ways.
* Ensure a well written commit message as explained
  [here](https://chris.beams.io/posts/git-commit/).
* Push your local branch to the fork (e.g. `git push <your_fork>
  my_feature_branch`)

## Submitting a Pull Request

* Create a [pull request from your
  fork](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request-from-a-fork).
* Address PR feedback with fixup and/or squash commits:
```
git add .
git commit --fixup <commit SHA>
  -- or --
git commit --squash <commit SHA>
```
* Once approved, before merging into `WHPG_6` squash your fixups with:
```
git rebase -i --autosquash origin/WHPG_6
git push --force-with-lease <your_fork> my_feature_branch
```

Your contribution will be analyzed for product fit and engineering
quality prior to merging. Your pull request is much more likely to be
accepted if it is small and focused with a clear message that conveys
the intent of your change.
