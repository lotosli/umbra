# macOS private migration packaging

`client-control.zsh` is a generic stock-zsh controller for a private migration bundle. It requires macOS 11+, runs as the destination desktop user and provides `install`, `start`, `stop`, `status`, `uninstall` and `menu` actions. It does not require Python, Homebrew or Rust on the destination.

The local bundle layout is:

```text
Umbra-Mac-迁移包-1.0.0-alpha/
  安装.command
  启动.command
  停止.command
  状态.command
  卸载.command
  程序/
    control.zsh
    umbra                     # ad-hoc signed arm64/x86_64 universal executable
  配置/
    Umbra-client.toml          # PRIVATE: current client's complete configuration
    Clash-Umbra.yaml           # PRIVATE: selected self-contained local profile
    Clash-QCloud.yaml          # PRIVATE: selected self-contained local profile
  使用说明.txt
  SHA256SUMS
```

Each entry-point script resolves its own directory and invokes `程序/control.zsh` with the matching action. The universal binary is assembled from the existing 1.0.0-alpha distribution slices. The controller installs under the destination user's home, creates a `com.umbra.client` launch agent and saves a control shortcut under `~/Applications`. The client and profiles use the paired loopback SOCKS listener at port 1080. Installation checks for unrelated listeners instead of terminating them. Configuration, owned service files and replaced executable/control files are backed up before changes; a failed installation restores previous state. Uninstall retains configuration, logs and backups.

Configuration exports and final archives must stay outside the repository and public release assets. Preserve all required credentials in the authorized private exports; do not print them while assembling the package. Copy only the requested profiles/client configuration, without unrelated profiles, SSH keys or global account state.

This packaging change does not modify Rust sources or restart the current local service. The user's no-additional-testing instruction limits assembly validation to shell syntax, binary architecture/signing metadata, exact-copy comparison and archive integrity. Installation on the destination Mac has not been exercised here.
