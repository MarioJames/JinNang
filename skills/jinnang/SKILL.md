---
name: jinnang
description: "用 Jinnang（`jinnang` CLI，`jn://` 引用）查找和使用凭证：任务需要账号密码、API token、SSH 私钥或密码、数据库 DSN、云 AK/SK、kubeconfig、TOTP、.env 里的秘密值，或要登录某个系统、连接某台主机时使用；也用于把新生成的凭证存起来。不要为此读取、打印或复制明文凭证文件。"
---

# Jinnang

Jinnang 是本机的凭证库。你只持有 `jn://` 引用，由 `jinnang` 把字段注入目标命令；明文不进入你的上下文、输出和日志，每次使用都写入审计记录。

命令语法以已安装的二进制为准：`jinnang --help`、`jinnang <command> --help`。本文件和它的两份参考可用 `jinnang --skill` 一并打印。

## 规则

- 只用引用。不 `cat`、`grep`、`source` 凭证文件或 `.env`，不把值打印、写入文件、记忆、报告、提交或对话。旧记忆里提到的明文文件路径，先用 `jinnang find` 找对应条目。
- 不猜账号。找不到或有多个候选时，先按下文缩小范围；仍不确定就问用户，不换一个「看起来差不多」的账号。
- 缺凭证时运行 `jinnang need`，把它打印的命令交给用户在自己的终端执行；不要让用户把值粘贴进对话。
- 口令不归你管：`jinnang` 自己解封口令，你不传、不找、不设置任何口令或口令文件。
- 不绕过工具：不读取 vault 目录、封存的口令或恢复包，不调用 `systemd-creds` 解密，不用 `--no-redact` 输出秘密，不把注入的值 `echo` 出来。
- 不从 `run` 的输出取值：`jinnang run … -- sh -c 'printf "$K"' | 下一个命令` 里，下一个命令收到的是 `[jinnang:redacted]`，不是秘密；stderr 出现 `got the placeholder` 提示就是这种情况。下游报「令牌无效 / 认证失败」时先排除这一点，不要据此判断凭证或对方系统有问题。管道、远程 shell、`kubectl exec` 都放进 `--` 后的命令里（见下文「交给远端」）。
- 疑似泄露时停下，报告引用，由用户在源系统轮换。

## 找到要用的账号

查找只读清单，不需要口令，也不会输出秘密值。

1. 按任务里的线索搜：系统名、租户、角色、主机名、IP、用途、旧文件名或变量名都可以作为关键词，多个关键词同时命中才算：

   ```bash
   jinnang find poc sales            # 名称、标签、说明、公开字段、字段名里同时含 poc 和 sales
   jinnang find titumng              # 主机名
   jinnang find poc-qa-accounts.env  # 旧明文文件名（若条目说明里记录了来源）
   ```

2. 知道标签时用选择器，语法同 Kubernetes，逗号表示「且」：

   ```bash
   jinnang ls                                   # 全部条目：名称、类型、版本、标签，下一行是用途说明
   jinnang ls -l 'env=prod,tenant=poc'
   jinnang ls -l 'pool=poc-qa,role in (sales,root)'
   ```

3. 用 `jinnang inspect <ref>`（或 `--json`）确认类型、标签、说明和字段名；用户名、主机、URL 等公开字段会显示值，秘密字段只显示 `<secret>`。
4. 选定后在命令里写明完整引用，或写一个**恰好命中一个**条目的选择器（`-l`）；命中零个或多个都会报错，不要放宽条件去凑。
5. 都找不到：

   ```bash
   jinnang need jn://<建议名称> --type account -l env=prod -l tenant=<t> --desc '<用途>' --reason '<为什么需要>'
   ```

## 使用凭证

`jinnang run <ref | -l 选择器> [注入方式] -- <命令>`。注入方式可以组合：

| 方式 | 写法 | 子进程得到 |
| --- | --- | --- |
| 环境变量 | `--env NAME=field` | `$NAME`（二进制字段为 base64） |
| 全部字段 | `--all-env` | env_bundle / generic 的键原样，其他类型为 `JN_<FIELD>` |
| 标准输入 | `--stdin field` | 值从 stdin 读入（二进制字段为原始字节） |
| 私有文件 | `--file NAME=field` | 0600 临时文件，内容是原始文件（二进制字段已解码）；`$NAME` 和参数中的 `{NAME}` 替换为路径，结束即删 |
| dotenv 文件 | `--env-file NAME` | 全部字段写成 dotenv 文件，同上 |

引用末尾加 `@vN`（如 `jn://acme/app-db@v1`）使用历史版本，`inspect` 列出现有版本。输出中出现的秘密值会被替换成 `[jinnang:redacted]`，并在 stderr 提示替换了几处；退出码原样返回。值不要放进命令行参数（其他进程能从 `/proc` 看到）；需要拼接时在子 shell 里用内建命令处理：

```bash
# 数据库
jinnang run jn://acme/app-db --env PGPASSWORD=password -- psql -h db.internal -U app_rw app -c 'select 1'

# HTTP token：请求头经 stdin 交给 curl，不进参数
jinnang run jn://cloudflare/main --env T=token -- \
  sh -c 'printf "Authorization: Bearer %s\n" "$T" | curl -sS -H @- https://api.example.com/v1/me'

# 交给远端（SSH 主机、容器、Pod）：远程命令是子进程，值经它的 stdin 过去
jinnang run jn://acme/api --stdin token -- \
  ssh ops@bastion 'read -r T; curl -sS -H "Authorization: Bearer $T" https://api.example.com/v1/me'
# 远端还要读脚本时，在子 shell 里把值和脚本拼进同一个 stdin
jinnang run jn://acme/api --env T=token -- sh -c '
  { printf "%s\n" "$T"; cat probe.sh; } | ssh ops@bastion "kubectl exec -i deploy/app -- sh -c \"read -r T; export T; sh -s\""'
```

SSH 私钥与密码、整包 `.env`、证书文件、网页登录和 TOTP 的写法见 [更多注入配方](references/recipes.md)。

## 追溯

每次 `run`、`gen`、`rm`、`trash restore` 和回收站过期清除都在审计日志记录引用、字段名、调用进程和会话标识（`CLAUDE_CODE_SESSION_ID`、`CODEX_THREAD_ID`、`HERDR_PANE_ID`、`WEAVER_RUN_ID`），`run` 另记命令和工作目录，都不含值。用 `JINNANG_TASK=<任务名> jinnang run ...` 把这次使用标到具体任务上。

## 存入新凭证

要在环境里注册账号、保存自己生成的密码或证书文件、删除或轮换条目时，读 [存入新凭证](references/store.md)。两条先记住：密码由 `jinnang gen` 生成后直接进 vault，不经过你的输出；换值用 `jinnang rotate`，不删了重建。

## 出错时

| 现象 | 处理 |
| --- | --- |
| `vault is locked` | 还没开启免交互解锁；请用户在自己的终端运行 `jinnang unlock enroll`（或 `--generate` 让 jinnang 自持口令），你不要代为输入或寻找口令 |
| `cannot unseal` / `wrong passphrase` | 封存的口令失效（换过机器或重装系统）；停下报告用户，由用户用恢复包恢复，不要尝试其他口令 |
| `N entries match the selector` | 加条件或改用完整引用 |
| `no entry matches` / `does not exist` | 换关键词 `jinnang find`；仍没有就 `jinnang need` |
| `vault identity ... changed` / `rollback detected` | vault 可能被替换或回滚；停下报告用户，不要删除信任状态 |
