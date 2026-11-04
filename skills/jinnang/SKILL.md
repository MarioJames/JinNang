---
name: jinnang
description: "用 Jinnang（`jinnang` CLI，`jn://` 引用）查找和使用凭证：任务需要账号密码、API token、SSH 私钥或密码、数据库 DSN、云 AK/SK、kubeconfig、TOTP、.env 里的秘密值，或要登录某个系统、连接某台主机时使用；也用于把新生成的凭证存起来。不要为此读取、打印或复制明文凭证文件。"
---

# Jinnang

Jinnang 是本机的凭证库。你只持有 `jn://` 引用，由 `jinnang` 把字段注入目标命令；明文不进入你的上下文、输出和日志，每次使用都写入审计记录。

命令语法以已安装的二进制为准：`jinnang --help`、`jinnang <command> --help`。本文件可用 `jinnang --skill` 重新打印。

## 规则

- 只用引用。不 `cat`、`grep`、`source` 凭证文件或 `.env`，不把值打印、写入文件、记忆、报告、提交或对话。旧记忆里提到的明文文件路径，先用 `jinnang find` 找对应条目。
- 不猜账号。找不到或有多个候选时，先按下文缩小范围；仍不确定就问用户，不换一个「看起来差不多」的账号。
- 缺凭证时运行 `jinnang need`，把它打印的命令交给用户在自己的终端执行；不要让用户把值粘贴进对话。
- 口令不归你管：`jinnang` 自己解封口令，你不传、不找、不设置任何口令或口令文件。
- 不绕过工具：不读取 vault 目录、封存的口令或恢复包，不调用 `systemd-creds` 解密，不用 `--no-redact` 输出秘密，不把注入的值 `echo` 出来。
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

引用末尾加 `@vN`（如 `jn://acme/app-db@v1`）使用历史版本，`inspect` 列出现有版本。输出中出现的秘密值会被替换成 `[jinnang:redacted]`，退出码原样返回。值不要放进命令行参数（其他进程能从 `/proc` 看到）；需要拼接时在子 shell 里用内建命令处理：

```bash
# 数据库
jinnang run jn://acme/app-db --env PGPASSWORD=password -- psql -h db.internal -U app_rw app -c 'select 1'

# SSH 私钥
jinnang run jn://ssh/web1 --file KEY=private_key --env H=host --env U=user -- \
  sh -c 'ssh -i "$KEY" -o IdentitiesOnly=yes "$U@$H" uptime'

# SSH 密码：用 askpass 脚本从环境变量取值
jinnang run jn://ssh/web2 --env SSHPASS_VALUE=password --env H=host --env U=user -- sh -c '
  a=$(mktemp -p "${XDG_RUNTIME_DIR:-/tmp}"); trap "rm -f $a" EXIT
  printf "#!/bin/sh\nprintf %%s \"\$SSHPASS_VALUE\"\n" > "$a"; chmod 700 "$a"
  SSH_ASKPASS="$a" SSH_ASKPASS_REQUIRE=force ssh -o PubkeyAuthentication=no "$U@$H" uptime'

# HTTP token：请求头经 stdin 交给 curl，不进参数
jinnang run jn://cloudflare/main --env T=token -- \
  sh -c 'printf "Authorization: Bearer %s\n" "$T" | curl -sS -H @- https://api.example.com/v1/me'

# 应用配置：整包 .env
jinnang run jn://local/app-env --env-file CREDS -- ./deploy.sh --env-file {CREDS}

# 证书等文件：还原成文件交给需要路径的程序
jinnang run jn://acme/signing/cert --file P12=p12 --env PW=password -- \
  sh -c 'security import "$P12" -k "$KEYCHAIN" -P "$PW" -T /usr/bin/codesign'

# 网页登录：值只在子进程里传给浏览器工具
jinnang run jn://work/poc/qa-sales --env U=username --env P=password -- \
  sh -c 'agent-browser fill "#email" "$U" && agent-browser fill "#password" "$P"'
```

TOTP 验证码：当前没有专用命令；本机装有 `oathtool` 时可以 `jinnang run <ref> --env S=seed -- sh -c 'oathtool --totp -b "$S"'`（只输出 6 位动态码）。

## 追溯

每次 `run`、`gen`、`rm`、`trash restore` 和回收站过期清除都在审计日志记录引用、字段名、调用进程和会话标识（`CLAUDE_CODE_SESSION_ID`、`CODEX_THREAD_ID`、`HERDR_PANE_ID`、`WEAVER_RUN_ID`），`run` 另记命令和工作目录，都不含值。用 `JINNANG_TASK=<任务名> jinnang run ...` 把这次使用标到具体任务上。

## 存入新凭证

### 在环境里创建账号

需要在某个环境里注册测试用户、服务账号时，先让 jinnang 生成并存好凭证，再拿引用去注册；密码从随机源直接进入 vault，不经过你的输出：

```bash
# 1. 生成：用户名等公开字段用 --set 传，密码由 jinnang 生成（默认 24 位，含大小写、数字和符号）
jinnang gen jn://dev/acme/qa-01 --set username=qa-01 --set login_url=https://acme.test/login \
  -l env=dev -l app=acme --desc 'acme dev 环境 QA 测试账号 qa-01（agent 注册）'

# 2. 注册：值只在子进程里
jinnang run jn://dev/acme/qa-01 --env U=username --env P=password -- \
  sh -c 'printf "%s" "$P" | ./admin create-user "$U" --password-stdin'

# 3. 注册失败：删掉这次生成的条目，同名可以重新 gen
jinnang rm jn://dev/acme/qa-01
```

- 默认生成类型的必填秘密字段（`account`/`password`/`dsn` 的 `password`、`api_token` 的 `token`、`totp` 的 base32 `seed`）；其他字段用 `--gen FIELD` 指定，`--type generic` 时必须指定。
- 目标系统限制字符时用 `--charset alnum` 或 `hex`，长度用 `--length N`。
- `--set` 只接受非秘密字段，秘密字段写在命令行会被拒绝；自定义的 `--set` 字段自动标为公开。
- 注册成功后条目保留，供后续登录和清理使用。

### 删除

`jinnang rm` 把条目移进回收站，7 天内可恢复，之后由下一次写操作自动清除；没有立即销毁的命令。

| 情况 | 做法 |
| --- | --- |
| 本任务 `gen` 的条目，注册没成功 | `jinnang rm <ref>` |
| 目标环境里的账号已删除，凭证不再使用 | `jinnang rm <ref>` |
| 误删 | `jinnang trash ls` 找到 id，`jinnang trash restore <ref 或 id>` |
| 其他条目 | 不删；换值用 `jinnang rotate`。删除不是本任务创建的条目只在用户明确要求时做 |

### 其他由你生成的值

部署时新建的数据库角色等，从生成器经管道存入：

```bash
openssl rand -base64 32 | tr -d '\n' | jq -Rs '{password: .}' | \
  jinnang set jn://acme/prod/db-app --type password --stdin-json \
    -l env=prod -l app=acme --desc 'acme 生产库应用角色 app_rw'
```

### 文件类凭证

证书、私钥、kubeconfig 这类文件存内容，不存路径（路径只在这台机器有效，文件本身还留在 vault 外）：

```bash
jinnang set jn://acme/signing/cert --from-file p12=./cert.p12 --field password \
  -l app=acme --desc 'acme 代码签名证书（p12 与导入密码）'
```

`--field` 在终端里提示输入；没有终端时用 `--stdin-json` 提供其余字段，与 `--from-file` 合并。文本文件原样保存；二进制文件以 base64 保存并标为二进制（`inspect` 显示 `<secret, binary>`），`run --file` 还原成逐字节相同的文件。

### 通用

- 给每个条目写 `--desc`：一句话说明系统、租户、角色和用途，让以后的 agent 能用 `jinnang find` 找到它；条目已存在时用 `jinnang describe <ref> '<说明>'` 补写，用 `jinnang label <ref> k=v` 补标签。
- vault 处于锁定状态时写入会成为 pending 候选，告诉用户运行 `jinnang pending activate <id>`。
- 已有条目换新值用 `jinnang rotate`，不要删了重建。

## 出错时

| 现象 | 处理 |
| --- | --- |
| `vault is locked` | 还没开启免交互解锁；请用户在自己的终端运行 `jinnang unlock enroll`（或 `--generate` 让 jinnang 自持口令），你不要代为输入或寻找口令 |
| `cannot unseal` / `wrong passphrase` | 封存的口令失效（换过机器或重装系统）；停下报告用户，由用户用恢复包恢复，不要尝试其他口令 |
| `N entries match the selector` | 加条件或改用完整引用 |
| `no entry matches` / `does not exist` | 换关键词 `jinnang find`；仍没有就 `jinnang need` |
| `vault identity ... changed` / `rollback detected` | vault 可能被替换或回滚；停下报告用户，不要删除信任状态 |
