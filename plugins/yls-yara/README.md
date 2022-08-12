# yls-yara

![PyPI](https://img.shields.io/pypi/v/yls-yara)

An [YLS](https://www.github.com/avast/yls) plugin adding
[YARA](https://github.com/VirusTotal/yara) linting capabilities.

This plugin runs `yara.compile` on every save, parses the errors, and returns
list of diagnostic messages.

## License

Copyright (c) 2022 Avast Software, licensed under the MIT license. See the
[`LICENSE`](https://github.com/avast/yls/blob/master/plugins/yls-yara/LICENSE)
file for more details.
