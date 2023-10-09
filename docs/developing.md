---
title: How to develop
nav_order: 3
---

Install YLS in development mode with all necessary dependencies.

```bash
poetry install
```

### Tests

You can run tests with the following command:

```bash
poetry run pytest
```

Run tests including pylint and the Black code formatter like the CI workflow of the repo. Useful before PRs:

```bash
poetry run pytest -vvv  --black --pylint --pylint-rcfile=pyproject.toml --cov=yls --cov-report=term-missing -l ./yls ./tests
```
