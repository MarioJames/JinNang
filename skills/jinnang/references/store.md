# 存入新凭证

## 在环境里创建账号

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

## 删除

`jinnang rm` 把条目移进回收站，7 天内可恢复，之后由下一次写操作自动清除；没有立即销毁的命令。

| 情况 | 做法 |
| --- | --- |
| 本任务 `gen` 的条目，注册没成功 | `jinnang rm <ref>` |
| 目标环境里的账号已删除，凭证不再使用 | `jinnang rm <ref>` |
| 误删 | `jinnang trash ls` 找到 id，`jinnang trash restore <ref 或 id>` |
| 其他条目 | 不删；换值用 `jinnang rotate`。删除不是本任务创建的条目只在用户明确要求时做 |

## 其他由你生成的值

部署时新建的数据库角色等，从生成器经管道存入：

```bash
openssl rand -base64 32 | tr -d '\n' | jq -Rs '{password: .}' | \
  jinnang set jn://acme/prod/db-app --type password --stdin-json \
    -l env=prod -l app=acme --desc 'acme 生产库应用角色 app_rw'
```

## 文件类凭证

证书、私钥、kubeconfig 这类文件存内容，不存路径（路径只在这台机器有效，文件本身还留在 vault 外）：

```bash
jinnang set jn://acme/signing/cert --from-file p12=./cert.p12 --field password \
  -l app=acme --desc 'acme 代码签名证书（p12 与导入密码）'
```

`--field` 在终端里提示输入；没有终端时用 `--stdin-json` 提供其余字段，与 `--from-file` 合并。文本文件原样保存；二进制文件以 base64 保存并标为二进制（`inspect` 显示 `<secret, binary>`），`run --file` 还原成逐字节相同的文件。

## 通用

- 给每个条目写 `--desc`：一句话说明系统、租户、角色和用途，让以后的 agent 能用 `jinnang find` 找到它；条目已存在时用 `jinnang describe <ref> '<说明>'` 补写，用 `jinnang label <ref> k=v` 补标签。
- vault 处于锁定状态时写入会成为 pending 候选，告诉用户运行 `jinnang pending activate <id>`。
- 已有条目换新值用 `jinnang rotate`，不要删了重建。
