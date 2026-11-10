# 使用指南

[返回 README](../README.md) · [Agent 操作技能](../skills/jinnang/SKILL.md)

本文对应当前 CLI。查看每个命令的完整参数可用 `jinnang --help` 和 `jinnang <命令> --help`。示例中的系统名、主机、路径和引用需要换成自己的实际值；使用外部工具的示例也需要先安装相应工具。

## 安装与数据目录

按 README 下载并运行安装脚本后，可用 `JINNANG_INSTALL_DIR` 指定绝对安装路径。升级时沿用原目录，并用 `command -v jinnang` 确认实际命中的文件。

安装指定版本时，从 [Releases](https://github.com/MarioJames/JinNang/releases) 复制完整 tag：

```bash
read -r -p 'Release tag: ' release_tag
JINNANG_VERSION="$release_tag" bash jinnang-install.sh
```

卸载时删除安装目录中的 `jinnang` 即可。安装、升级和卸载二进制不删除凭证数据。

| 配置 | 作用与默认值 |
| --- | --- |
| `--vault PATH` / `JINNANG_VAULT` | 凭证库路径，命令行参数优先；默认 `$XDG_DATA_HOME/jinnang/vault`，未设置 XDG 时为 `~/.local/share/jinnang/vault` |
| `JINNANG_STATE_DIR` | 信任状态与封存口令目录；默认 `$XDG_STATE_HOME/jinnang`，未设置时为 `~/.local/state/jinnang` |
| `JINNANG_TASK` | 为使用记录附加任务名称 |
| `JINNANG_PASSPHRASE_FILE` | 从文件读取主口令，供隔离测试或 CI 使用；优先于封存口令和终端输入。日常 Agent 不应读取、寻找或设置口令文件 |

凭证库保存密文、签名清单和 `audit.jsonl`。信任状态记录已钉住的签名公钥和最高序号；不要为消除报错而删除信任状态。

## 引用、标签与查找

引用名称为 `jn://<path>`，路径 1–8 段，允许小写字母、数字和 `. _ -`。名称按自己的习惯组织，环境、租户、角色等分类可放进标签：

```bash
jinnang set jn://acme/app-db --type dsn -l env=prod -l team=platform --desc 'acme 生产库应用角色'
jinnang find acme prod
jinnang ls -l 'env=prod,team in (platform,data)'
jinnang inspect jn://acme/app-db --json
```

`find` 在名称、标签、说明、公开字段值和字段名中匹配，所有关键词都命中才列出；秘密值不参与搜索。`ls`、`find` 和 `inspect` 不需要主口令，秘密字段显示占位标记，公开字段显示值。

标签选择器支持 `k=v`、`k!=v`、`k`、`!k`、`k in (a,b)`、`k notin (a,b)`，逗号表示「且」。`run` 和 `inspect` 中的选择器必须恰好命中一个条目，零个或多个都会报错，不会自动选取：

```bash
jinnang inspect -l env=prod,team=platform
```

`run` 的引用可加 `@vN` 选择历史版本。引用格式还可包含 `#field`，但 `set`、`inspect`、`run` 等条目命令要求完整条目引用，不接受字段片段；注入字段由 `run` 的选项指定。

## 录入与生成

已有凭证由用户在自己的终端录入，秘密字段不回显：

```bash
jinnang set jn://acme/api --type api_token -l env=dev --desc 'acme 开发环境 API'
jinnang set jn://acme/ops-otp --type totp
jinnang set jn://acme/notion --field api_key --field workspace --public workspace
```

TOTP 的 `seed` 可直接粘贴 base32 种子或 `otpauth://` URI；当前没有专用的验证码生成命令。`generic` 是 `set` 的默认类型，交互录入时用 `--field` 声明字段，`--public` 将自定义字段标为公开。

新账号可由 Jinnang 生成秘密字段，避免值进入对话或命令行：

```bash
jinnang gen jn://dev/acme/qa-01 --set username=qa-01 -l env=dev --desc 'acme 开发环境 QA 账号'
jinnang gen jn://dev/acme/hook --type generic --gen signing_secret --length 48 --charset alnum
```

`gen` 默认类型为 `account`，默认生成 24 位密码，含大小写字母、数字和符号；还支持 `--charset alnum` 或 `hex`。默认生成类型的必填秘密字段，其他秘密字段用 `--gen FIELD` 指定；`--set` 只接收非秘密值。TOTP 种子使用独立的 base32 生成方式。

`gen` 只创建本地记录。需要在外部系统注册账号时，再用 `run` 注入生成的字段；注册失败后可将本次生成的条目移入回收站。

### 整包环境变量与文件

```bash
jinnang import-env ./app.env jn://acme/app-env --public PORT,NODE_ENV -l env=dev
jinnang set jn://acme/signing/cert --from-file p12=./cert.p12 --field password
```

文件存入的是内容。UTF-8 文本原样保存，其他内容以 base64 保存并标为二进制字段；`run --file` 和 `--stdin` 还原原始字节，`--env`、`--env-file` 和 `--all-env` 使用 base64。导入不会删除原文件，原文件仍需由所有者妥善处理。

## 将凭证交给命令

`jinnang run <引用或 -l 选择器> [注入选项] -- <命令>`。注入选项可以组合：

| 方式 | 写法 | 子进程得到 |
| --- | --- | --- |
| 环境变量 | `--env NAME=field` | 名为 `NAME` 的环境变量 |
| 全部字段 | `--all-env` | `env_bundle` / `generic` 保持原键名，其他类型使用 `JN_<大写字段名>` |
| 标准输入 | `--stdin field` | 字段原始字节，不自动添加换行 |
| 私有文件 | `--file NAME=field` | 0600 临时文件；环境变量 `$NAME` 与独立参数 `{NAME}` 指向文件路径 |
| dotenv 文件 | `--env-file NAME` | 全部字段组成的 dotenv 临时文件，路径传递方式同上；多行字段需改用 `--file` |

临时文件在正常结束和受控错误返回时清理；强制终止进程等情况不能保证清理。默认会过滤 stdout 和 stderr，子进程退出码原样返回。

### 数据库与 SSH

```bash
jinnang run jn://acme/app-db --env PGPASSWORD=password -- \
  psql -h db.internal -U app_rw app -c 'select 1'

jinnang run jn://acme/deploy-key --file KEY=private_key -- \
  ssh -i {KEY} -o IdentitiesOnly=yes ops@web1 uptime

jinnang run jn://acme/app-db@v1 --env PGPASSWORD=password -- \
  psql -h db.internal -U app_rw app -c 'select 1'
```

这里由 `psql`、`ssh` 消费凭证，Jinnang 负责注入和记录，当前不托管数据库或 SSH 会话。

### 标准输入、dotenv 与二进制文件

```bash
jinnang run jn://acme/api --stdin token -- mycli login --token-stdin
jinnang run jn://acme/app-env --env-file CREDS -- ./deploy.sh --credentials {CREDS}
jinnang run jn://acme/signing/cert --file P12=p12 -- cp {P12} ./restored.p12
```

最后一个示例会主动导出原始文件；导出文件不在 Jinnang 的临时清理范围内，需要自行保护。

### 管道应放在消费命令内部

不要先打印秘密，再从 `run` 的外部输出把它交给另一个程序：过滤后，下游拿到的是 `[jinnang:redacted]`。发生替换时，stderr 会提示 `got the placeholder`。

需要组合命令时，把管道放在 `--` 后的子进程内。例如，经标准输入把认证头交给 curl，避免秘密进入参数：

```bash
jinnang run jn://acme/api --env T=token -- \
  sh -c 'printf "Authorization: Bearer %s\n" "$T" | curl -fsS -H @- https://api.example.com/v1/me'
```

交互程序可能需要 `--no-redact` 才能正常工作；该选项会关闭输出过滤，让原始输出直接通过。Agent 不应用它导出秘密或绕过过滤。

## 免交互解锁与待激活写入

用户在自己的终端输入一次现有口令，将其封存：

```bash
jinnang unlock enroll
jinnang unlock status
```

也可用 `jinnang unlock enroll --generate` 将现有主口令替换为 Jinnang 生成并自持的 256 位随机口令。旧口令随即失效；本机凭证密钥丢失后需要恢复包。封存依赖用户级 systemd 加密凭证，绑定本机和当前用户，`status` 显示实际使用的绑定方式；这不是同用户进程隔离。

不再需要免交互解锁时，可用 `jinnang unlock remove` 删除封存口令；使用自持口令的库，删除后需要依靠恢复包恢复，不能改回提示一个自己不知道的口令。

写入只需要公钥。没有可用的主口令且没有交互终端时，或显式加上 `--pending` 时，写入成为加密候选，不直接发布为正式版本：

```bash
jinnang gen jn://demo/pending --set username=demo --pending
jinnang pending ls
jinnang pending activate --all
```

`activate` 需要解锁并校验候选。也可按候选 id 激活或用 `jinnang pending reject <id>` 丢弃指定候选；已有正式条目换值时使用 `rotate`。

## 整理、更新与删除

```bash
jinnang label jn://acme/api owner=alice team=platform
jinnang label jn://acme/api team-
jinnang describe jn://acme/api 'acme 开发环境 API，只供服务连通性检查'
jinnang mv jn://acme/api jn://acme/dev/api
jinnang rotate jn://acme/dev/api
```

`key=value` 添加或更新标签，`key-` 删除已有标签，删除不存在的键会报错。改标签、说明或名称不产生凭证新版本；`rotate` 新增版本，标签默认沿用，也可以覆盖。

```bash
jinnang rm jn://acme/dev/api
jinnang trash ls
jinnang trash restore jn://acme/dev/api
```

删除先进入回收站，`ls`、`find` 和 `run` 不再可见，名称可以被新条目使用。7 天内可恢复；同名删除过多次时，用 `trash ls` 中的 id（至少 8 位的唯一前缀）定位。原名称被占用时恢复会拒绝，需先整理重名条目。

到期后由下一次解锁写操作清除密文、版本和该条目的 pending 候选。没有后台清理进程，也没有立即硬删除命令；过期清除失败时给出警告，不中断当前写入。

## 备份、校验与恢复

```bash
jinnang verify --deep
jinnang backup --out vault.backup
jinnang --vault "$HOME/restored-vault" restore --from vault.backup \
  --recovery-kit "$HOME/jinnang-recovery.json" --rekey
```

`verify` 检查签名、摘要与信任状态；`--deep` 还会解密校验全部版本。备份是加密归档，可以使用设备密钥或恢复包解开；恢复包不是备份，二者都需要妥善保管。

`restore` 要求目标凭证库目录为空，`--rekey` 为恢复后的设备密钥设置新主口令。恢复后如需免交互使用，再运行 `unlock enroll`。遇到身份变化或回滚告警时先核实来源，不要删状态或直接加 `--accept-rollback` 来跳过检查。

## 给 Agent 的录入指引与使用追踪

缺少凭证时，让 Agent 生成录入指引，由用户在自己的终端执行输出的命令：

```bash
jinnang need jn://acme/api --type api_token -l env=dev --desc 'acme 开发环境 API' --reason '检查服务连通性'
```

`need` 不替用户录入值。名称、标签和说明写清系统、环境、角色与用途；从旧文件迁移时，可把原文件名或变量名记在说明中，便于从历史线索找到引用。

`run` 在凭证库的 `audit.jsonl` 记录引用、版本、字段名、脱敏后的命令参数、工作目录、调用进程、会话和结果；写入开始记录失败时拒绝执行命令。`gen`、删除、恢复回收站条目和过期清除也会留记录。会话标识来自 `CLAUDE_CODE_SESSION_ID`、`CODEX_THREAD_ID`、`HERDR_PANE_ID`、`WEAVER_RUN_ID`，可以用 `JINNANG_TASK` 附加任务名。这些记录用于追踪，当前不提供防篡改或不可伪造的会话身份保证。

## 条目类型与字段

`*` 表示秘密字段。内置类型是字段模板；每种类型都支持额外的自定义字段，默认视为秘密，只有自定义字段可通过 `--public` 标为公开。内置字段的公开性固定。

| 类型 | 字段 |
| --- | --- |
| `password` | `password*` |
| `account` | `username`、`password*`、`login_url`、`totp_ref` |
| `totp` | `seed*`、`algorithm`、`digits`、`period`、`issuer`、`account` |
| `ssh` | `host`、`port`、`user`、`host_key`、`private_key*`、`passphrase*`、`password*` |
| `cloud_key` | `provider`、`region`、`access_key_id*`、`secret_access_key*`、`session_token*` |
| `dsn` | `driver`、`host`、`port`、`database`、`username`、`password*`、`sslmode` |
| `kubeconfig` | `kubeconfig*`、`context`、`namespace` |
| `api_token` | `token*`、`base_url`、`audience` |
| `env_bundle` | `.env` 中的键，默认全部为秘密 |
| `generic` | 自定义字段，默认全部为秘密 |
