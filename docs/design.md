# Jinnang 设计

本文描述 Jinnang 的目标、威胁模型、架构与里程碑。M1 已实现的存储格式见 [存储格式](#5-存储格式m1-已实现)。

## 1. 目标与原则

Jinnang 面向在同一台 Linux 工作站上并行运行的多个编码 agent（Claude Code、Codex、Copilot CLI、OpenCode 等），这些 agent 也会 SSH 到远程主机执行操作。

1. **可追溯第一**：每次使用都能回答「哪个会话、哪个任务、对哪个目标、用了哪个凭证版本、结果如何」。审批要少，追溯要全。
2. **agent 尽量不接触明文**：agent 只持有引用。明文要么进入工具控制的消费进程，要么只用于工具托管的已认证连接。
3. **非对称加密**：使用 age（X25519 + ChaCha20-Poly1305）。写入只需公钥，解密只在受信执行域内进行。
4. **会话托管优先**：能由工具保持的连接（SSH 等），由工具建立和持有，agent 只拿受控的操作接口。
5. **单机零依赖**：不需要服务器，单人可用；需要动态凭证或团队共享时，再评估 OpenBao 等成熟后端。

用户设想的「申请 → 拿到 token → 凭 token 兑换 → 管道注入」在 Jinnang 中实现为一个 **operation**：冻结执行计划、按策略授权、单次兑换。其中 `redeem | consumer` 管道是显式的 L1 出口。

## 2. 威胁模型

前提：所有 agent 与用户同属一个 UID；`ptrace_scope` 可能为 0；终端复用器允许一个 pane 向另一个 pane 发送按键。

| 级别 | 对手 | 保证 | 不保证 |
| --- | --- | --- | --- |
| L0 静态 | 磁盘、备份、仓库被读取 | 没有私钥就无法读取；篡改、换位可检测 | 整盘快照回滚（需要外部锚定） |
| L1 防误 | 诚实但粗心的 agent；日志或报错误打印 | 引用代替明文、旁路录入、单次操作、默认不走 env、输出脱敏 | agent 主动读出（`\| cat`、编码、重定向） |
| L2 受控消费 | 被 prompt injection 劫持的同 UID agent | 明文只进入独立执行 UID 中经审查的 adapter，或托管连接 | 已授权的动作本身被滥用；能执行任意代码的消费者主动外传 |
| L3 会话隔离 | 跨 agent 冒用 | 每个 agent 会话由可信启动器放在独立 UID 中运行 | 主机 root、内核失陷、远端管理员 |

要点：

- 消费进程与 agent 分属不同 UID，是 L2 的实现方式；agent 之间也分 UID，属于 L3。普通 user namespace 不等价于宿主 UID 隔离。
- 所有 agent 同 UID 的部署形态下，追溯的定位是「协作环境中的使用追踪」：能确认进程实例和声明的会话，不能证明那就是某个 agent 的本意。
- 防泄漏不等于防滥用。L2 的单位是经过审查的 adapter 与输入契约，不是程序名白名单。

## 3. 架构（M2 起）

```text
人：独立终端 / 配对设备
  │ set / approve / allow / audit / revoke
  ▼
agent ── jinnang CLI ── Unix socket + SO_PEERCRED ──► jinnang-broker（独立系统 UID）
                                                     │ 密钥、策略、operation 状态机
                                                     │ SQLite：operation 与审计（同一事务）
                                                     │ age 密文 + 签名清单
                 ┌───────────────────────────────────┼─────────────────────────┐
                 ▼                                   ▼                         ▼
        jinnang-launch（root 所有的              jinnang-ssh worker            L1 出口
        systemd 模板，独立执行 UID）              每会话一个 ControlMaster      redeem / run / totp / fill
        运行审查过的 adapter                     + passenger 中转
```

- **主口令**：用 `systemd-creds encrypt --with-key=tpm2+host` 封装，broker 通过 `LoadCredentialEncrypted=` 读取，开机即可自动解锁。没有 TPM 时退回 `host` 密钥。钥匙串可作为备选，但已解锁的钥匙串对同 UID 进程可读。
- **审批**：
  - 默认 `auto`：在策略范围内自动批准，完整审计；
  - `notify`：自动批准，同时实时推送；
  - `strict`：需要人工批准。
- **预授权**：用户可以按条目通配、目标、模式、会话或任务、有效期和次数提前放行。创建预授权属于管理操作，需要额外认证（如 polkit），agent 不能给自己授权。
- **operation**：`requested → authorized | pending → dispatched → completed | failed | unknown`。
  - token 默认 60 秒过期、单次兑换；
  - 兑换只引用已冻结的计划；
  - 执行意图先写入 SQLite 事务再派发；
  - 崩溃后标为 `unknown`，不重放。
- **SSH 会话托管**：
  - 复用系统 OpenSSH；worker 使用独立 UID、工具生成的配置和 known_hosts，每个会话一个 ControlMaster；
  - `jinnang ssh <target> -- cmd` 由 worker 启动 passenger 中转，agent 拿不到原始 ControlPath；
  - 审计记录实际提交的命令字符串，它不等于远端最终 argv；
  - 断线重连不重放已提交的命令；`revoke` 会关闭对应的 master。
- **审计关联字段**：
  - 请求与授权：`request_id / operation_id`、`plan_digest / policy_version`；
  - 会话与任务：`broker_session_id / parent_session_id / task_id`；
  - 身份来源与可信度：`identity_source / identity_assurance`，取值为 `kernel`、`launcher` 或 `declared`；
  - 凭证与连接：`credential_version / lease_id / connection_id`；
  - 执行结果：`dispatch_state / result_observation`。

  `value_hmac` 只能检索使用过某个值的候选记录，不能用来证明泄露来源。

## 4. 出口与级别

| 出口 | 级别 | 说明 |
| --- | --- | --- |
| `redeem` 管道 | L1 | stdout 必须是管道；读端是常见回显或编码程序时拒绝。生产或高敏条目默认禁用 |
| `run` | L1 | 通过 fd/stdin 注入，可选 env |
| `totp` | L1 | seed 不可导出；距窗口结束不足 3 秒时等待下一个窗口 |
| `fill`（CDP） | L1 | 校验 origin；主要价值是防误和防串租户 |
| `exec` adapter | L2 | 运行在独立执行 UID 中；首个 adapter 是 psql：强制 `-X`，`PGPASSFILE` 为普通文件 |
| `ssh` 托管 | 认证材料达到 L2 | 能力按会话授予 |
| 后续 | — | sudo 固定动作、git/docker credential helper、kubectl/PG 代理、显式 HTTP 代理 |

## 5. 存储格式（M1 已实现）

```text
<vault>/vault.json             vault_id、设备与恢复接收者、签名公钥
<vault>/identity.age           设备密钥材料（X25519 身份 + Ed25519 种子），用口令（age scrypt）封装
<vault>/manifest.json          {"body": "<清单 JSON>", "signature": "<Ed25519>"}
<vault>/entries/<id>/v<N>.age  每个版本一个 age 文件，加密给设备与恢复两个接收者
<vault>/pending/<pid>.{age,json}  只用公钥写入的候选
$XDG_STATE_HOME/jinnang/<hash>.json  信任状态：钉住的 vault_id、签名公钥、最高清单序号
```

- **密文载荷**：`{"header": {vault_id, entry_id, version, type}, "ref", "labels", "fields": {...}, "public_fields": [...]}`。读取时核对 header，防止密文在条目、版本或 vault 之间换位。header 不含名称，所以条目可以改名而不必重新加密；载荷里的 ref 和标签只记录写入时的状态。
- **清单签名覆盖的内容**：vault_id、两个接收者、签名公钥、每个条目的 ref/类型/标签/用途说明/公开字段/版本/密文摘要/删除状态，以及序号。
- **打开时的校验**：
  - 签名有效；
  - 清单与 `vault.json` 一致；
  - 签名公钥与 vault_id 与信任状态一致；
  - 清单序号不低于已见的最高序号。
- **写入**：先只用公钥生成候选，再经设备私钥解密、校验 header、schema 与版本条件后激活。激活时用 `create_new` 写版本文件，并原子替换清单。
- **恢复包**：离线 JSON，包含恢复用的 X25519 身份和签名种子。用它可以解开备份，并通过 `--rekey` 生成新的设备密钥，同时保留原签名身份。
- **备份**：整个 vault 的 tar 包，加密给设备与恢复两个接收者。恢复时只接受预期路径下的普通文件。

### 命名、标签与选择器

不同用户的组织方式差别很大：有人按环境和租户分，有人按 SaaS 分，有人只有几个个人账号。因此名称不带固定语义，分类交给标签。

- **引用**：`jn://<path>[#field][@vN]`。path 为 1–8 段，每段是小写字母、数字和 `. _ -`；工具不解释各段含义。`#field` 指字段，`@vN` 指历史版本。
- **标签**：任意 `key=value`，写入签名清单，可随时用 `jinnang label` 增删，不产生新版本。常见用法：`env=prod`、`tenant=poc`、`role=sales`、`pool=poc-qa`、`kind=saas`。
- **选择器**：Kubernetes 风格，逗号表示「且」：`k=v`、`k!=v`、`k`、`!k`、`k in (a,b)`、`k notin (a,b)`。
- **解析规则**：凡是接受引用的地方都可以改用 `-l <selector>`，但必须恰好命中一个条目；命中零个或多个都报错并列出候选，不做回退或随机选择。`ls -l` 用于列出多个。
- **字段**：内置类型是字段模板，字段的秘密性固定；任何类型都可以加自定义字段，默认是秘密，用 `--public` 标为公开。`generic` 类型没有预设字段。
- **改名**：`jinnang mv` 只改清单里的名称，密文绑定的是条目 id。
- **多账号池**（M2）：同一组账号用相同的 `pool=` 标签，配合租约（lease）实现互斥借用；在此之前，用选择器指定具体账号。

## 6. 里程碑

- **免交互解锁（已完成）**：`jinnang unlock enroll` 校验口令后用 `systemd-creds --user`（本机凭证密钥，可叠加 TPM2）封存到信任状态目录；`--generate` 与 `init --self-held` 改用 jinnang 生成的 256 位随机口令（先封存并回读校验，再原子替换设备密钥文件），口令不显示、无人知晓，恢复只靠恢复包；解锁顺序为 `JINNANG_PASSPHRASE_FILE`（测试/CI）→ 封存口令 → 终端。调用方不传口令。M1 中同一用户仍可自行解封，M2 改由 broker 的独立 UID 持有该凭证。
- **M1 存储与录入（已完成）**：
  - 命令：`init`、`set`、`rotate`、`import-env`、`need`、`pending`、`ls`、`inspect`、`label`、`mv`、`rm`、`verify`、`backup`、`restore`；
  - 机制：pending 到激活、签名清单、回滚检测、恢复与换密钥。
- **L1 出口 `jinnang run`（已完成）**：按字段注入 env、stdin 或私有临时文件（`{NAME}` 参数替换，结束即删）；对子进程输出做流式脱敏；每次使用在 `audit.jsonl` 记录 start/end（不含值，argv 中出现的值同样脱敏）。
- **M2 追溯闭环与 SSH**：
  - 独立 UID 的 broker、systemd 加密凭证解锁；
  - 策略：auto/notify/strict 加预授权；
  - operation 状态机与 SQLite 审计，`audit`、`watch`、`revoke`、`panic`；
  - 出口：`run`、`redeem`、`totp`、租约；
  - SSH 会话托管。
- **M3 首个 L2 与场景扩展**：
  - `jinnang-launch` 与 psql adapter；
  - `fill`；
  - 经 SSH 送秘密；
  - AGENTS.md 接入。
- **后续**：
  - 可信审批通道（手机或独立账户）；
  - L3 会话隔离（可信启动器）；
  - sudo 固定动作、credential helper、kubectl/PG 代理；
  - TPM/YubiKey 插件、多机同步。

## 7. 给 agent 的约定

完整约定见随仓库发布的技能 [`skills/jinnang/SKILL.md`](../skills/jinnang/SKILL.md)，`jinnang --skill` 打印同一份内容。要点：

- 只用 `jn://` 引用；不读取、打印或复制凭证文件、`.env` 的值、token、验证码、cookie、DSN。
- **发现**：先 `jinnang find <关键词>` 或 `jinnang ls -l <选择器>`，再 `inspect` 核对；清单只含元数据（名称、标签、用途说明、公开字段、字段名），读取不需要口令。选择器必须唯一命中，不猜测、不回退到其他账号。
- 缺凭证时运行 `jinnang need`，把生成的录入指令交给用户；不让用户在对话中粘贴明文。
- agent 生成的新凭证从生成器经管道存入 `jinnang set --stdin-json`，并写 `--desc` 和标签，供以后的 agent 发现。
- 不把凭证或 token 写入记忆、报告、测试快照、日志或提交；疑似泄露时停止相关操作，报告引用，由用户轮换。

用途说明（description）写在签名清单中，可随 `set`/`rotate`/`import-env --desc` 或 `jinnang describe` 修改，不产生新版本。
