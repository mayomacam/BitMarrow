# Building CryptoPass Standalone

This guide explains how to package CryptoPass into a standalone executable for distribution. We use `PyInstaller` to bundle the Python interpreter, dependencies, and resources.

## 📋 Prerequisites

Ensure you have all dependencies installed:
```bash
pip install -r requirements.txt
pip install pyinstaller
```

## 🛠️ Build Steps (Windows)

To create a single portable `.exe` file:

```bash
pyinstaller --noconsole --onefile --add-data "gui;gui" --add-data "core;core" --add-data "database;database" --add-data "generators;generators" --add-data "utils;utils" --add-data "config.py;." --icon="NONE" --name "CryptoPass" main.py
```

### Argument Breakdown:
- `--noconsole`: Prevents a terminal window from opening in the background.
- `--onefile`: Bundles everything into a single executable.
- `--add-data`: Ensures the Python modules and configurations are included in the bundle.
- `--name`: Sets the final filename to `CryptoPass.exe`.

The final executable will be located in the `dist/` folder.

## 🐧 Build Steps (Linux)

Similar to Windows, but without the `.exe` extension:

```bash
pyinstaller --noconsole --onefile --add-data "gui:gui" --add-data "core:core" --add-data "database:database" --add-data "generators:generators" --add-data "utils:utils" --add-data "config.py:." --name "cryptopass" main.py
```
*Note: On Linux, use a colon `:` instead of a semicolon `;` for `--add-data`.*

## ⚠️ Important Notes

1. **Permissions:** The `.exe` may trigger Windows Defender "SmartScreen" because it is an unsigned executable. Users will need to click "Run anyway".
2. **Database Path:** By default, CryptoPass creates a `data/` folder in the same directory as the executable. Ensure the application has write permissions in its folder.
3. **Icons:** If you have a `.ico` file, replace `--icon="NONE"` with `--icon="your_icon.ico"`.
