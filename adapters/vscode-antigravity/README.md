# Multiplayer Party Chat — Antigravity IDE / VS Code Extension

Adds a one-click **`$(broadcast) Party Chat`** button to the bottom-right Status Bar (and **`Cmd+Alt+M`** / **`Ctrl+Alt+M`** shortcut) in Antigravity IDE and VS Code to launch `mp-outpost chat` natively.

## Features

- **Status Bar Button (`$(broadcast) Party Chat`):** Click to open or focus a dedicated integrated terminal running `mp-outpost chat` directly inside the IDE.
- **Detached `phux` Window (`Multiplayer: Open Party Chat (Detached phux Window)`):** Starts or reuses a detached `phux` session (`multiplayer-chat`) running `mp-outpost chat`, with one-click buttons to **Attach in Terminal**, **Copy `phux attach`**, or **Copy `phux native attach`**.
- **Zero external runtime dependencies** and strictly `shell: false` subprocess execution.

## Install Locally

Package with `vsce` (or load directly in an Extension Development Host):

```sh
npx @vscode/vsce package
code --install-extension multiplayer-party-chat-0.7.1.vsix
```
