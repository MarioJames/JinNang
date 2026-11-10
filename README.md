![Jinnang 品牌标识](docs/assets/brand/jinnang-lockup.png)

# Jinnang 锦囊

**让编码 Agent 用引用代替明文，每次使用都留下记录。**

> 凭证入囊，用过留痕。

Jinnang 是面向编码 Agent 的本地凭证库。你在自己的终端录入凭证，Agent 用 `jn://` 引用找到它，由 Jinnang 把需要的字段交给目标命令。密码、token 和私钥不必粘贴进对话，也不必由 Agent 读取 `.env` 文件。

```text
你在终端录入 → 本地加密保存 → Agent 选择引用 → 注入目标命令 → 记录使用
                               jn://acme/api
```

- **按用途找凭证**：名称、标签和说明可检索，秘密字段不会出现在查询结果中。
- **按命令使用**：通过环境变量、标准输入或私有临时文件注入字段，默认过滤输出中的秘密值。
- **保留使用记录**：记录引用、版本、字段、调用进程、会话和执行结果，便于追溯。
- **本地运行**：age 加密存储，签名清单校验完整性，支持历史版本、备份与恢复。

「锦囊」取自「锦囊妙计」：事先封好，需要时才打开，取出准备好的内容。[品牌与素材](docs/assets/brand/README.md)

## 安装

支持 **Linux x86_64 / ARM64**。下载预编译二进制，无需 Rust 或 sudo：

```bash
curl -fsSLo jinnang-install.sh https://github.com/MarioJames/JinNang/releases/latest/download/install.sh && bash jinnang-install.sh
```

默认安装到 `~/.local/bin`，升级时重跑同一行。需要 Bash、curl、tar、awk 和 GNU coreutils；脚本自动选择架构、校验 SHA-256，试运行成功后再替换旧二进制。安装和升级保留已有凭证库。

如果提示找不到命令，将下面一行加入 `~/.bashrc` 或 `~/.zshrc`，重新打开终端：

```bash
export PATH="$HOME/.local/bin:$PATH"
jinnang --version
```

已有版本装在其他目录时，指定原目录升级，避免 `PATH` 继续命中旧文件：

```bash
JINNANG_INSTALL_DIR="$HOME/.cargo/bin" bash jinnang-install.sh
```

[指定版本、卸载与数据目录](docs/usage.md#安装与数据目录) · [从源码构建](docs/development.md)

## 快速上手

以下命令由你在自己的终端执行。已经初始化过的凭证库可直接从第 2 步开始。

### 1. 创建凭证库

```bash
jinnang init --recovery-kit "$HOME/jinnang-recovery.json"
```

按提示设置至少 12 个字符的主口令。恢复包能够解密全部条目，请妥善转移到离线位置，与日常工作环境分开保管。

如果希望从一开始就由 Jinnang 生成并自持主口令，可改用下面这条初始化命令；需要 **systemd 256+ 且用户级加密凭证可用**：

```bash
jinnang init --self-held --recovery-kit "$HOME/jinnang-recovery.json"
```

自持口令不显示，也无需记忆；本机凭证密钥丢失后，只能依靠恢复包恢复。

### 2. 添加一条凭证

先生成一条演示账号记录，不需要准备现成凭证：

```bash
jinnang gen jn://demo/account --set username=demo -l env=dev --desc '本机上手演示账号'
```

默认生成 24 位随机密码，值直接存入凭证库，不显示在输出中。这只创建本地凭证记录，不会在外部系统注册账号。

保存已有 token 时，使用下面的命令，在终端提示中输入，秘密字段不会回显：

```bash
jinnang set jn://acme/api --type api_token -l env=dev --desc 'acme 开发环境 API'
```

`jn://acme/api` 是引用名称，`env=dev` 是标签，`--desc` 帮助 Agent 判断该选哪个条目。

### 3. 查找并使用

```bash
jinnang find demo
jinnang inspect jn://demo/account
jinnang run jn://demo/account --env APP_PASSWORD=password -- \
  sh -c 'test -n "$APP_PASSWORD" && printf "凭证已注入\n"'
```

最后一条命令让子进程拿到密码，终端只显示 `凭证已注入`。没有配置免交互解锁时，使用凭证仍会提示输入主口令；查找和查看元数据不需要口令。

## 交给 Agent 使用

### 开启免交互解锁

已有主口令的凭证库，在自己的终端执行一次：

```bash
jinnang unlock enroll
jinnang unlock status
```

Jinnang 用 systemd 用户级加密凭证封存主口令，之后自行解封，Agent 无需传入口令。需要 systemd 256+ 及可用的用户级加密凭证；用 `--self-held` 初始化过的库已完成封存。

### 安装 Agent 技能

二进制内置完整技能，无需克隆仓库。以读取 `~/.agents/skills` 的 Agent 为例：

```bash
mkdir -p "$HOME/.agents/skills/jinnang"
jinnang --skill > "$HOME/.agents/skills/jinnang/SKILL.md"
```

Claude Code 可将同一份内容导出到 `~/.claude/skills/jinnang/SKILL.md`。升级 Jinnang 后重新导出技能，使说明与二进制保持一致；也可以让 Agent 直接运行 `jinnang --skill` 阅读。

之后可以给 Agent 这样的任务：

> 用 acme 开发环境的 API 凭证检查服务，先查用途和标签，再通过 `jinnang run` 注入 token。

Agent 先用 `find`、`ls` 和 `inspect` 选定引用，再用 `run`。缺凭证时，用 `jinnang need` 生成录入指引交给你，不要求你把值粘贴进对话。

## 常用操作

| 需求 | 命令 |
| --- | --- |
| 按关键词查找 | `jinnang find acme dev` |
| 按标签筛选 | `jinnang ls -l 'env=dev,team=platform'` |
| 查看字段与版本 | `jinnang inspect jn://acme/api --json` |
| 更新凭证，保留历史版本 | `jinnang rotate jn://acme/api` |
| 补充用途 | `jinnang describe jn://acme/api 'acme 开发环境 API'` |
| 添加或更新标签 | `jinnang label jn://acme/api owner=alice` |
| 删除到回收站 | `jinnang rm jn://acme/api` |
| 恢复误删条目 | `jinnang trash restore jn://acme/api` |
| 校验全部密文 | `jinnang verify --deep` |
| 创建加密备份 | `jinnang backup --out vault.backup` |

支持账号密码、API token、SSH、云密钥、数据库、TOTP 种子、kubeconfig、整包 `.env` 和自定义字段。回收站保留 7 天，到期后由下一次解锁写操作清除。

字段注入、文件凭证、历史版本、恢复、待激活写入和全部字段模板见 [使用指南](docs/usage.md)。具体参数可运行 `jinnang <命令> --help` 查看。

## 安全边界

当前版本提供加密存储和防误泄露的命令出口，**没有独立进程身份隔离**：

- 凭证以 age 加密保存；签名清单与密文绑定用于发现篡改、换位及部分回滚。
- 同一用户下的进程仍可能读取本机数据、请求 systemd 解封口令或控制消费命令。它不能阻止主动窃取凭证的同用户程序。
- 默认输出过滤按秘密值匹配，覆盖不少于 4 字节的原始值，不是任意编码、变形或外传的检测器。不要把秘密放进命令行参数，也不要关闭过滤来向其他程序传值。
- 引用、标签、说明、用户名、主机名等公开字段会保存在可查询的清单中；不要在这些位置填秘密。
- 审计用于使用追踪，当前没有防篡改保证；整盘快照回滚也无法只靠本地状态检测。已经泄露的凭证需要到源系统轮换。

独立 UID broker、策略审批、SSH 会话托管和防篡改审计仍在规划中。完整威胁模型与路线见 [设计文档](docs/design.md)。

## 许可

[Apache-2.0](LICENSE)
