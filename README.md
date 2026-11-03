![Jinnang 品牌标识](docs/assets/brand/jinnang-lockup.png)

# Jinnang 锦囊

**让编码 Agent 用引用代替明文，每次使用都留下记录。**

> 凭证入囊，用过留痕。

Jinnang 是一个面向 AI agent 的本地凭证库。agent 只持有 `jn://` 引用，不接触明文；凭证在本机以 age 非对称加密保存，使用时由工具注入目标命令或托管连接，每次使用都留下不含明文的审计记录。

名字取自「锦囊妙计」：锦囊密封交付，持有人事先不知道内容，到了约定的时机、按约定的用途才能拆开。

[品牌素材](docs/assets/brand/README.md)

> 状态：**M1（加密存储与录入）+ L1 出口 `jinnang run`**。独立 UID broker、按策略签发的一次性授权、SSH 会话托管和防篡改审计在 M2 实现，见 [设计文档](docs/design.md)。

## 它解决什么

多个编码 agent 在同一台工作站上并行工作时，凭证通常散落在各处：

- `.env` 文件和私有配置文件；
- 用户粘贴到对话里的密码与 AK/SK，事后还会被写进记忆系统；
- 报错信息和测试输出里打印出来的连接串。

一旦进入 agent 的上下文，明文就会留在会话记录里，也说不清是谁、在什么任务里用过它。

Jinnang 的做法：

- **引用代替明文**：agent 用 `jn://acme/app-db` 这样的名称或 `-l env=prod,role=app` 这样的标签选择器指代凭证，`ls` 和 `inspect` 只显示字段名、标签和非秘密字段。
- **旁路录入**：缺凭证时，agent 运行 `jinnang need` 生成一条录入命令交给用户，用户在自己的终端里输入，值不经过对话。
- **公钥写入、私钥激活**：只用公钥就能写入候选（pending），无需解锁。用户解锁后，工具校验候选再发布为正式版本。
- **防篡改**：每个版本的密文绑定 vault、条目、版本和类型；清单由 Ed25519 签名，并在本地记录已见的最高序号，用来发现回滚。
- **可恢复**：离线恢复包可以解开所有条目，也能在新机器上换一把新的设备密钥。

## 安装

```sh
cargo install --path .
```

需要 Linux 与 Rust 1.88+。

## 使用

```sh
# 创建 vault，口令至少 12 个字符；恢复包请转移到离线位置
jinnang init --recovery-kit ~/jinnang-recovery.json

# 录入：非秘密字段明文回显，秘密字段不回显；-l 打标签，--desc 写一句用途
jinnang set jn://acme/app-db --type dsn -l env=prod -l team=platform --desc 'acme 生产库应用角色'
jinnang set jn://acme/ops-otp --type totp            # 可直接粘贴 otpauth:// URI
jinnang set jn://notion --field api_key --field workspace --public workspace   # generic 类型，自定义字段
jinnang import-env ./app.env jn://acme/app-env --public PORT,NODE_ENV -l env=dev

# 查看（不含秘密值，不需要口令）；-l 按标签过滤，find 按关键词检索
jinnang find acme prod
jinnang ls
jinnang ls -l 'env=prod,team in (platform,data)'
jinnang inspect jn://acme/app-db --json

# 使用（L1）：把字段注入命令；输出里出现的值会被替换为 [jinnang:redacted]，每次使用写入 audit.jsonl
jinnang run jn://acme/app-db --env PGPASSWORD=password -- psql -h db.internal -U app_rw app
jinnang run -l env=prod,team=platform --env PGPASSWORD=password -- psql ...   # 选择器必须恰好命中一个条目
jinnang run jn://acme/deploy-key --file KEY=private_key -- ssh -i {KEY} -o IdentitiesOnly=yes root@host true
jinnang run jn://acme/app-env --env-file CREDS -- ./deploy.sh --credentials {CREDS}
jinnang run jn://acme/token --stdin token -- mycli login --token-stdin

# 整理：改标签（key- 删除）、改说明、改名；都不产生新版本
jinnang label jn://acme/app-db owner=alice team-
jinnang describe jn://acme/app-db 'acme 生产库应用角色，只读查询用 reader 账号'
jinnang mv jn://acme/app-db jn://acme/prod/app-db

# 新版本 / 删除
jinnang rotate jn://acme/prod/app-db              # 标签沿用，-l 可覆盖
jinnang rm jn://acme/prod/app-db

# 免交互解锁：输入一次口令，校验后用 systemd 用户级加密凭证封存；之后 jinnang 自行解封，调用方（agent）不传口令
jinnang unlock enroll
jinnang unlock status

# 不解锁的写入先进入 pending，之后由用户激活
jinnang set jn://acme/token --type api_token --stdin-json --pending < values.json
jinnang pending ls
jinnang pending activate --all

# 校验、备份、恢复
jinnang verify --deep
jinnang backup --out vault.backup
jinnang --vault ~/new-vault restore --from vault.backup --recovery-kit ~/jinnang-recovery.json --rekey

# agent 缺凭证时
jinnang need jn://acme/cf-token --type api_token -l env=prod --reason "部署 DNS"
```

### 命名与标签

名称是自由路径 `jn://<path>[#field][@vN]`（1–8 段，小写字母、数字和 `. _ -`），工具不规定各段含义。环境、租户、角色这类分类放在标签里，按需组合查询。例如：

```sh
# 个人：几个独立账号
jinnang set jn://github --type account -l kind=saas
jinnang set jn://bank/otp --type totp

# 团队：同一 SaaS 租户下的多个账号，靠标签区分和挑选
jinnang set jn://work/poc/sales --type account -l env=prod -l tenant=poc -l role=sales -l pool=poc-qa
jinnang set jn://work/poc/owner --type account -l env=prod -l tenant=poc -l role=owner
jinnang run -l tenant=poc,role=sales --env PW=password -- ./login.sh
```

选择器语法与 Kubernetes 相同：`k=v`、`k!=v`、`k`、`!k`、`k in (a,b)`、`k notin (a,b)`，逗号表示「且」。在 `run`、`inspect` 中使用时必须恰好命中一个条目，命中零个或多个都会报错，不会替你挑一个。

条目类型（内置类型是字段模板；任何类型都可以用 `--field` 或 `--stdin-json` 加自定义字段，自定义字段默认是秘密，用 `--public` 标为公开）：

| 类型 | 字段（`*` 为秘密） |
| --- | --- |
| `password` | `password*` |
| `account` | `username`、`password*`、`login_url`、`totp_ref` |
| `totp` | `seed*`、`algorithm`、`digits`、`period`、`issuer`、`account` |
| `ssh` | `host`、`port`、`user`、`host_key`、`private_key*`、`passphrase*`、`password*` |
| `cloud_key` | `provider`、`region`、`access_key_id*`、`secret_access_key*`、`session_token*` |
| `dsn` | `driver`、`host`、`port`、`database`、`username`、`password*`、`sslmode` |
| `kubeconfig` | `kubeconfig*`、`context`、`namespace` |
| `api_token` | `token*`、`base_url`、`audience` |
| `env_bundle` | 任意 `KEY`，默认全部为秘密，用 `--public` 标出非秘密的键 |
| `generic`（默认） | 无预设字段，全部自定义 |

环境变量：

| 变量 | 作用 |
| --- | --- |
| `JINNANG_VAULT` | vault 目录，默认 `$XDG_DATA_HOME/jinnang/vault` |
| `JINNANG_PASSPHRASE_FILE` | 从文件读取口令，供测试和 CI 使用；日常用 `jinnang unlock enroll` 封存口令，未封存时从终端读取 |
| `JINNANG_STATE_DIR` | 信任状态目录，记录钉住的签名公钥和最高清单序号；默认 `$XDG_STATE_HOME/jinnang` |

## 给 Agent 用

仓库自带一个 agent 技能 [`skills/jinnang`](skills/jinnang/SKILL.md)，写明查找账号、注入各类凭证、存入新凭证和出错处理的做法。安装后，支持技能的 agent（Claude Code、Codex 等）遇到账号、token、SSH、数据库连接这类任务时会自动加载它：

```sh
ln -s "$PWD/skills/jinnang" ~/.agents/skills/jinnang     # Codex 等读取 ~/.agents/skills
ln -s ~/.agents/skills/jinnang ~/.claude/skills/jinnang  # Claude Code
```

没装技能的 agent 运行 `jinnang --help` 会看到提示，`jinnang --skill` 直接打印同一份技能。

**agent 怎么知道该用哪个账号**：agent 手里通常只有任务描述（「用 poc 租户的销售账号验收」「连 web1 看日志」），不知道库里有什么。Jinnang 的清单不需要口令就能查，且只含元数据：

- `jinnang find <关键词...>` 在名称、标签、用途说明、公开字段（用户名、主机、URL）和字段名里检索，所有关键词都命中才列出；秘密值不参与检索；
- `jinnang ls -l <选择器>` 按标签精确筛选，`jinnang inspect` 查看单个条目；
- 用 `run`、`inspect` 时，选择器必须恰好命中一个条目，否则报错并列出候选，agent 不能「挑一个差不多的」。

所以录入时值得多写一点元数据：用 `--desc` 说明系统、租户、角色和用途；从旧明文文件迁移时，把原文件名和变量名写进说明，读到旧记忆的 agent 也能按文件名找到对应条目。

## 安全边界（M1）

- 能保证：
  - 磁盘、备份和仓库里的密文没有私钥就无法解开；
  - 篡改、换位、改清单都会被发现；
  - 输出与错误信息不含秘密值。
- 不能保证：
  - **M1 没有进程隔离**，vault 目录与 agent 同属一个用户。`unlock enroll` 封存的口令绑定本机和当前用户，磁盘上不再有明文口令，但同一用户的进程仍能请 systemd 解封它；真正把 agent 挡在口令之外需要 M2 的独立 UID broker。
  - **整盘快照回滚无法检测**：纯本地模式只能发现「vault 目录回滚而信任状态没回滚」的情况，要发现整盘回滚，需要把清单序号外部锚定。
  - **已经泄露的凭证必须在源系统轮换**：撤销设备不会让旧备份失效。

独立 UID 的 broker、按策略签发的一次性授权、SSH 会话托管和审计在 M2 实现；完整的威胁模型见设计文档。

## 许可

[Apache-2.0](LICENSE)
