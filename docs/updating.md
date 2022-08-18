---
title: Updating
nav_order: 2
---

**If you don't have YLS installed yet. Please follow the installation steps
described [here]({{ site.baseurl }}{% link installation.md %}) instead.**

This document will guide how to update your `yls` installation.

# YLS - update

## Global installation

```bash
pip install -U yls-yara
```

## Virtual Environment installation

### Windows

```batchfile
:: Source venv where you previously installed yls
yls\env\Scripts\activate.bat
pip install -U yls-yara
```

### Linux

```bash
# Source venv where you previously installed yls
. /home/user/yls/env/bin/activate
pip install -U yls-yara
```

# Extensions - update

This section will provide instructions how to update editor extensions linked with yls.
## [VsCode](https://code.visualstudio.com/)
- TBD
## [Vim](https://www.vim.org/)/[NeoVim](https://neovim.io/)
- if not specified otherwise, no action is required
