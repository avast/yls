---
title: Installation
nav_order: 1
---

This document will guide you through installation of **yls** onto your system.
The whole process is divided into 2 parts:

1. `yls` binary installation
2. Editor configuration

For a quick tutorial checkout the following video:

<video width="960" height="540" controls>
    <source src="https://user-images.githubusercontent.com/26434056/183893630-b3474a51-9a44-4998-a7a6-10fb87da5139.mp4" type="video/mp4">
</video>

## Installation

The goal of this step is to ensure you have yls installed on your machine.

- you must ensure that you have a supported python version: **python 3.8+**
- you must ensure that you have [requirements](https://github.com/VirusTotal/yara-python#installation) to install `yara-python`
- you must ensure that you have [requirements](https://yaramod.readthedocs.io/en/latest/installation.html#requirements) to install `Yaramod` on Linux (Windows packages are pre-built wheels)

### Global installation - `yls` must be present in `PATH`

```bash
pip install -U yls-yara
```

NOTE:
- since the installation is global it can interfere with your current version of [yara-python](https://pypi.org/project/yara-python/) and YARA
- if you have currently installed yara-python and you would like to keep the version, please follow the steps bellow and install YLS into virtual environment

### Virtual Environment installation

*NOTE:* In the configuration steps you will need to provide an absolute path to
the `yls` executable either in the editor plugin (VsCode) or in the editor LSP
client configuration (vim). In the Linux example the absolute path was
`/home/user/yls/env/bin/yls`.

Following snippets show example installation steps.

#### Windows

```Batchfile
:: Pick and create a suitable directory for your yls installation
mkdir yls
cd yls
python -m venv env
env\Scripts\activate.bat
pip install -U yls-yara

:: To get the absolute path of the yls executable
dir /S /b "env\Scripts\yls.exe"
```

#### Linux

```bash
# Pick and create a suitable directory for your yls installation
mkdir -p ~/yls
cd ~/yls
python -m venv env
. env/bin/activate
pip install -U yls-yara

# To get the absolute path of the yls executable
realpath env/bin/yls
```

## Editor configuration

The goal of this step is to configure your favorite editor to support yls. This
procedure is typically required only for the first time and the new updates are
rare.

### [Vscode](https://code.visualstudio.com/)

Install the following extension, depending on the used marketplace. You can search it directly from the Visual Studio Code UI.

- [Visual Studio Code Marketplace](https://marketplace.visualstudio.com/items?itemName=avast-threatlabs-yara.vscode-yls)
- [Open-vsx](https://open-vsx.org/extension/avast-threatlabs-yara/vscode-yls)

### [Vim](https://www.vim.org/)/[NeoVim](https://neovim.io/)

- associate `yara` filetype with file extensions

```vim-script
autocmd BufNewFile,BufRead *.yar,*.yara setlocal filetype=yara
```

- in order to install syntax highlighting declare it with your plugin manager (for example [vim-plug](https://github.com/junegunn/vim-plug))

```vim-script
Plug 's3rvac/vim-syntax-yara'
```

#### [nvim-lsp](https://neovim.io/doc/user/lsp.html)
```lua
-- use 'neovim/nvim-lspconfig'

local configs = require('lspconfig.configs')
if not configs.yls then
 configs.yls = {
   default_config = {
     cmd = {'yls', '-vvv'},
     filetypes = {'yara'},
     root_dir = util.find_git_ancestor,
     settings = {},
   },
 }
end

-- you can provide on_attach method or other settings here
require('lspconfig')['yls'].setup{}
```

#### [coc.vim](https://github.com/neoclide/coc.nvim)

vimrc:
```vim-script
Plug 'neoclide/coc.nvim', {'branch': 'release'}
```

coc-settings.json:
```json
{
	"languageserver": {
		"yara": {
			"command": "yls",
			"args": ["-vv"],
			"filetypes": ["yara"]
		}
	}
}
```

#### [vim-lsp](https://github.com/prabirshrestha/vim-lsp)

```vim-script
Plug 'prabirshrestha/vim-lsp'
```

```vim-script
autocmd User lsp_setup call lsp#register_server({
    \ 'name': 'yls',
    \ 'cmd': {server_info->['yls']},
    \ 'whitelist': ['yara'],
})
```

### [Sublime](https://www.sublimetext.com/)

Will be ready in future releases.

### [Emacs](https://www.gnu.org/software/emacs/)

Will be ready in future releases.
