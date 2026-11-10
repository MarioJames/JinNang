# 构建与发布

[返回 README](../README.md)

## 本地构建

在仓库根目录运行。当前 CI 使用 Rust 1.98.0；按已提交的 `Cargo.lock` 解析依赖：

```bash
cargo build --locked --release
cargo install --locked --path .
```

前一条生成 `target/release/jinnang`，后一条安装到 Cargo 的 bin 目录（通常是 `~/.cargo/bin`）。只运行自己需要的一条即可；安装后用 `command -v jinnang` 核对实际命中的路径。

## 检查

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
bash -n install.sh
shellcheck install.sh
```

测试使用隔离的临时凭证库。涉及用户级 systemd 加密凭证的用例，在该能力不可用时跳过；其余命令测试不依赖 systemd 封存。

## GitHub Actions

[CI and release](../.github/workflows/ci.yml) 在 PR、`main` push 和手动触发时执行检查。两个原生 Linux runner 分别构建并测试：

| 架构 | Rust target | 产物 |
| --- | --- | --- |
| x86_64 | `x86_64-unknown-linux-musl` | `jinnang-x86_64-unknown-linux-musl.tar.gz` |
| ARM64 | `aarch64-unknown-linux-musl` | `jinnang-aarch64-unknown-linux-musl.tar.gz` |

产物静态链接 musl，无需目标机器提供对应版本的 glibc。工作流执行常规测试、release 模式安装测试和二进制试运行，并检查 ELF 不依赖动态解释器。

仅本仓库 `main` 上的 push 或手动运行可以发布，且必须等格式、Clippy、脚本检查及两个架构的测试和构建全部通过。PR 不发布。

## Release 规则

- 每次发布使用 `main-<完整提交SHA>` tag，指向被测试的提交，并将成功发布的版本标为 Latest。
- Release 包含两个架构的 `.tar.gz`、`install.sh` 和 `SHA256SUMS`。每个压缩包中只有 `jinnang` 二进制。
- 使用 GitHub 自带的 `GITHUB_TOKEN`；只有发布 job 获得 `contents: write`，不需要额外发布密钥。
- 先创建草稿并上传产物，再公开并标记 Latest。上传失败时，缺产物的版本不会公开；可能留下需要检查的草稿。
- 同一 tag 已存在时，创建操作会失败，不覆盖或重复发布。重跑前先检查已有 release 或草稿，不要删除已公开的历史产物来规避冲突。
- `jinnang --version` 取自 `Cargo.toml`，自动构建不修改该版本号。区分主线构建应使用 release tag 和提交 SHA。

安装脚本先将 Latest 解析为固定 tag，再下载校验和与对应架构的压缩包。它验证 SHA-256、提取二进制并试运行，最后在安装目录内原子替换旧文件；失败时清理临时文件并保留旧版本。
