# YLS

![PyPI](https://img.shields.io/pypi/v/yls?label=yls)
![Visual Studio Marketplace Version](https://img.shields.io/visual-studio-marketplace/v/avast-threatlabs-yara.vscode-yls?label=vscode)

[Language server](https://microsoft.github.io/language-server-protocol/) for
[YARA](https://yara.readthedocs.io/en/stable/) language.

:rocket: Features:
- Code completion of all available modules (including function parameters)
- Function documentation for hovers and code completion
- Opinionated code formatting
- Signature help
- Linting
- Go-to definition and references
- Symbol highlighting under the cursor
- Debugging? Stay tuned...
- ...

![Showcase](https://github.com/avast/yls/raw/master/docs/assets/yls.png)

For more information, check out:
- [Blog post](https://engineering.avast.io/yls-first-step-towards-yara-development-environment/)
- [Wiki](https://www.github.com/avast/yls/wiki)

:snake: Minimal supported version of Python is `3.8`.

## Installation

To setup your environment please follow instructions on
[wiki](https://github.com/avast/yls/wiki/How-to-setup).

## How to develop

Install YLS in development mode with all necessary dependencies.

```bash
poetry install
```

### Tests

You can run tests with the following command:

```bash
poetry run pytest
```

## License

Copyright (c) 2022 Avast Software, licensed under the MIT license. See the
[`LICENSE`](https://github.com/avast/yls/blob/master/LICENSE) file for more
details.

YLS and its related projects uses third-party libraries or other resources
listed, along with their licenses, in the
[`LICENSE-THIRD-PARTY`](https://github.com/avast/yls/blob/master/LICENSE-THIRD-PARTY)
file.

## FAQ

### Why are you using `pluggy`?

Some parts depend on our internal services, however we are working on making
most of the code available. This is just the first piece.
