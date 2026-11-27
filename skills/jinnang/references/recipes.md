# 更多注入配方

`jinnang run` 的注入方式见 SKILL.md 的「使用凭证」。下面是不常用的几种写法。

```bash
# SSH 私钥
jinnang run jn://ssh/web1 --file KEY=private_key --env H=host --env U=user -- \
  sh -c 'ssh -i "$KEY" -o IdentitiesOnly=yes "$U@$H" uptime'

# SSH 密码：用 askpass 脚本从环境变量取值
jinnang run jn://ssh/web2 --env SSHPASS_VALUE=password --env H=host --env U=user -- sh -c '
  a=$(mktemp -p "${XDG_RUNTIME_DIR:-/tmp}"); trap "rm -f $a" EXIT
  printf "#!/bin/sh\nprintf %%s \"\$SSHPASS_VALUE\"\n" > "$a"; chmod 700 "$a"
  SSH_ASKPASS="$a" SSH_ASKPASS_REQUIRE=force ssh -o PubkeyAuthentication=no "$U@$H" uptime'

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
