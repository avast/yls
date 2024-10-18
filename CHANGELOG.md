# Changelog
All notable changes to this project will be documented in this file.

# 1.4.3 (2024-10-18)

* chore(deps): update yara-python to v4.5.1
* chore(deps): update yaramod to v3.23.0
* chore(deps): Update other dependencies
* chore(dependabot): Update dependabot configuration

# 1.4.2 (2024-03-30)

* fix: Handle the case where samples_dir has no value
* Changed security notice
* chore(deps): Update pygls to v1.3.0
* chore(deps): Update black to v24.3.0
* chore(deps): Bump semver from 5.7.1 to 5.7.2 in /editors/vscode

# 1.4.1 (2024-01-11)

* chore: Expand python compatibility to ^3.8
* chore(deps): Update typing-extensions to v4.9.0
* chore(deps): Update yari-py to v0.2.1
* chore(deps): Update yaramod to v3.21.0
* chore(deps): Update pylint to v3.0.3
* chore(deps): Update pytest-pylint to v0.21.0
* chore: Fix pylint arguments-renamed error in visitors
* ci: Enable testing for python3.12
* ci: Force python version in tests

# 1.4.0 (2023-11-03)

* feat(debugger): Select hash for context and SHA1 & MD5 (#137)
* feat(debugger): Enable debug hovers in strings section (#138)
* feat(debugger): Normalize the `samples_dir` path (#139)
* fix(syntax): Incorrect syntax on regexp end
* fix(utils): Return range for first line on exception in range_from_line
* chore(deps): Update pygls to v1.1.2
* chore(deps): Remove unused bandit dependency

# 1.3.4 (2023-06-21)

* chore(deps): Update yaramod to v3.20.1
* chore(deps): Bump yara-python from 4.3.0 to 4.3.1 in /plugins/yls-yara
* chore(deps): Update pygls to v1.0.1
* chore(deps-dev): Bump pytest from 7.2.2 to 7.3.1 in /plugins/yls-yara
* chore: Add pre-commit configuration
* chore: Remove unused configuration code
* docs: Mention YARI in README.md
* docs: Add instructions how to use YLS in nvim-lsp

# 1.3.3 (2023-03-29)

* chore: Update yaramod to v3.19.1
* chore: Update pytest to v7.2.2

# 1.3.2 (2023-03-06)

- ci: Create dependabot.yml
- chore: Update yaramod to v3.19.0
- chore: Dependency updates

# 1.3.1 (2023-02-22)

- fix: Pygls imports in yls-yara

# 1.3.0 (2023-02-22)

- feat: Update to pygls v1.0.0
- chore: Update yari-py to v0.1.6
- chore: Update yaramod to v3.18.0
- chore: Update yaramod to v3.17.0
- chore: Update yari-py to v0.1.5

# 1.2.5 (2023-01-10)

- fix: Don't show YARI error popup when debugging is not setup

# 1.2.4 (2022-12-07)

- fix: Revert the python requirement to >=3.8,<3.12

# 1.2.3 (2022-12-07)

- fix: Set the python requirement to >=3.8,<4.0

# 1.2.2 (2022-12-07)

- fix: Update the version string
- feat: Downgrade the vscode-languageclient for better compatibility

# 1.2.1 (2022-10-21)

- chore: Update yaramod to 3.16.0

# 1.2.0 (2022-10-21)

- feat: Autocomplete YARA keywords (#24)
- feat: Remove `set_samples_dir`
- chore: Display less popup notifications from debuggers

# 1.1.0 (2022-09-21)

- feat: debugger integration
- feat: improved syntax highlighting for VsCode

# 1.0.0

- Initial release
