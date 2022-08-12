# YARA Language Server for Visual Studio Code

Visual Studio Code wrapper for [YLS](https://www.github.com/avast/yls). Provides
YARA language configuration, code completion, linting, formatting, and many
more features.

![Showcase](https://github.com/avast/yls/raw/master/assets/yls.png)

You can install it from:
- Visual Studio Code Extensions UI tab
- [Visual Studio Code Marketplace](https://marketplace.visualstudio.com/items?itemName=avast-threatlabs-yara.vscode-yls)
- [Open-vsx Marketplace](https://open-vsx.org/extension/avast-threatlabs-yara/vscode-yls)

To use it you also need to have `yls` installed on your system.

```
pip install yls-yara
```

For more detailed information on how to install `yls`, please check out the
[wiki](https://github.com/avast/yls/wiki/How-to-setup).

## Syntax

The syntax specification is based on
[infosec-intern/vscode-yara](https://github.com/infosec-intern/vscode-yara/blob/cc5e2d2372449329c4eb3167538592a7d378e5f5/yara/syntaxes/yara.tmLanguage.json).

## License

Copyright (c) 2022 Avast Software, licensed under the MIT license. See the
[`LICENSE`](https://github.com/avast/yls/blob/master/editors/vscode/LICENSE)
file for more details.

YARA Language Server for Visual Studio Code uses third-party libraries or other
resources listed, along with their licenses, in the
[`LICENSE-THIRD-PARTY`](https://github.com/avast/yls/blob/master/editors/vscode/LICENSE-THIRD-PARTY)
file.
