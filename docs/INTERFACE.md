# frp-edge 对外接口规范

> 面向第三方接入方:认证系统集成方、管理面板/控制平面实现方、计量采集方。
> 所有接口均在 frp-edge v0.71.0+mcp 补丁集上实测。变更遵循语义化版本;本文即契约。

---

## 1. 认证体系总览

frps 支持三种 per-user 认证形态,经 `[tokenGate]` 配置段**三选一**:

| 形态 | 配置 | 凭证驻留 | 适用 |
|------|------|---------|------|
| 独立运营 | `tokensFile` | frps 本地文件(5s 热加载) | 无外部系统 |
| 快照拉取 | `controlPlane` | frps 内存,每 5s 全量拉取 | 控制平面持有全量表 |
| **在线验证(推荐)** | `verify` | **frps 不存表**,登录时逐次回调 | 第三方认证/计费系统集成 |

不配置 `[tokenGate]` = 上游原版行为(全局共享 token)。

### 1.1 线上凭证协议(三形态共用)

frpc 与 frps 之间只传**派生键**,原始 token 从不上线:

```
PrivilegeKey = md5( rawToken ‖ strconv.FormatInt(timestamp, 10) )
```

- `timestamp` 为 Unix 秒;验证方须校验 `|now − timestamp| ≤ 15min`(防重放)
- 比对必须使用常量时间比较
- 三类消息携带凭证:`Login{user, timestamp, privilegeKey}`、`Ping`(心跳,30s)、`NewWorkConn`(每条新工作连接)
- 后两类消息**不携带 user 字段**,由 frps 会话绑定补齐

**第三方自建验证服务必须实现与上完全一致的派生与校验**,参考实现(12 行):

```go
func GetAuthKey(token string, ts int64) string {
    h := md5.New()
    h.Write([]byte(token))
    h.Write([]byte(strconv.FormatInt(ts, 10)))
    return fmt.Sprintf("%x", h.Sum(nil))
}
// allow := subtle.ConstantTimeCompare([]byte(GetAuthKey(stored, req.Timestamp)), []byte(req.PrivilegeKey)) == 1
```

### 1.2 通道加密约束(集成方必读)

frp 控制通道与 work conn 的加密密钥派生自**该用户的 raw token**(上游不变量)。因此:

- 快照拉取形态:快照响应携带 raw token,frps 自动获得密钥
- 在线验证形态:**验证响应在 allow 时必须回传该用户的 raw token**(见 §2.2);token 仅在 frps 内存按登录用户缓存,供会话期信道加密与心跳本地复检。**allow=true 而 token 缺失/为空是契约违约**:frps 按「验证服务不可达」处理(fail-close 新登录),不会 learn 空 token 去产生信道密钥错配

**时序(在线验证形态)**:raw token 在登录判决那一刻才被 learn,因此控制信道的加密层在登录验证**之后**建立——上游协议顺序(Login/LoginResp 明文传输、其后两端才升级到加密层)天然容纳这一点,frpc 无感知,首个登录即成功。若在验证前就取密钥,VerifyGate 尚无该用户的 token,会回退全局 `[auth] token` 派生的 key,与客户端(用自身 token 派生)不一致,导致首连必败一次再靠重连成功——frps 重启后每个用户都会踩一遍。

---

## 2. 认证集成接口

### 2.1 快照拉取(controlPlane 形态)

frps 每 5s 调用:

```
GET {controlPlane}                      [控制平面实现此端点]
Authorization: Basic {controlPlaneUser}:{controlPlanePassword}
→ 200  {"alice": "<raw-token>", "bob": "<raw-token>"}
```

- 响应即全部允许登录的用户;**移除用户 = 下一周期(≤5s)拒绝**
- 拉取失败 → frps 保留上一份快照;失联超过 `snapshotMaxAge`(默认 5m)→ 新登录 fail-close、存量心跳 fail-open
- 快照响应上限默认 1 MiB(约 1.6 万用户,每条 ~64B);更大用户表须调高 `[tokenGate] snapshotMaxBytes`,否则快照刷新持续失败并按上条语义演进
- `tokensFile` 与此形态语义相同,仅数据源为本地文件
- 码模型下映射为 **{码: 码} 自映射**(key 与 value 都是授权码)——快照形态仍可用于独立运营;mtunnel 平台形态已改用 verify(2026-08-20 用户外迁,ctrl 不再提供快照端点),本节面向自建快照数据源的接入方

### 2.2 在线验证(verify 形态,推荐)

**凭证模型(2026-08-19 起):单一授权码**。用户身份与凭证是同一个字符串(`xun-` + base64url,≈47 字符):frpc 配置 `user = <码>`、`auth.token = <码>`,因此 **`Login.user` 字段携带授权码原文(真透传)**——frps 不做任何翻译,验证方按该字段查表即可,持有码即验证通过。

frps 在**每次登录**时调用:

```
POST {verify}
Authorization: Basic {verifyUser}:{verifyPassword}
Content-Type: application/json

{
  "user":          "xun-<授权码>",   // 即身份本身(原文透传)
  "privilegeKey":  "<md5(码‖ts)>", // frpc 自动生成的派生键;验证方可选校验或忽略
  "timestamp":     1755…,          // Unix 秒
  "kind":          "login"         // login | ping | newworkconn(当前仅 login 远程回调)
}

→ 200
{
  "allow":   true,                  // 判决
  "reason":  "",                    // 拒绝原因码(见下),allow=true 时省略
  "message": "",                    // 人类可读说明,frps 原样透传给客户端
  "token":   "xun-<授权码>"          // 仅 allow=true 时必填(§1.2 通道加密需要;码模型下即回显码)
}
```

**协议铁律:判决是数据,不是 HTTP 状态码**——拒绝也返回 `200 + allow:false`;HTTP 401/5xx/超时一律被 frps 解释为「验证服务不可达」(新登录 fail-close,存量会话不受影响)。

**reason 码(开放集合,frps 透传 message,新增码无需 frps 改动)**:

| reason | 语义 | 客户端可见示例 |
|--------|------|---------------|
| `user_not_found` | 码不存在(错码/已轮换) | `code not recognized (user_not_found)` |
| `auth_failed` | 验证方内部错误(存储不可达等) | `verification unavailable (auth_failed)` |
| `user_banned` | 用户被禁用/码已轮换(墓碑) | `user is banned (user_banned)` |
| `insufficient_balance` | 余额/配额不足(由验证方业务判定) | 自定义 message |
| *(扩展)* | 验证方自定义 | 自定义 message |

> 旧的派生键比对与 ±15min 时窗校验在码模型下已取消(码即凭证,持有即验证)。若接入方仍想校验 `privilegeKey = md5(user 字段的码 ‖ timestamp)`,字段仍在请求中,可自行比对——这是免费的可选加强,不是协议要求。

**安全边界(真透传的代价,接入方须知)**:授权码原文出现在 frpc ↔ frps 的 Login 消息中(TLS 内)。防线 = ①TLS(生产必须 `transport.tls.force = true` + frpc 侧 `trustedCaFile` 证书 pinning,否则主动中间人可截获码)②码高熵(crypto/rand 256bit)③一键轮换(旧码墓碑即刻失效)④封禁秒级(Kick)。心跳/工作连接仍走 frpc 自动生成的派生键 md5(码‖ts),frps 用登录缓存的码本地复检,与码模型自洽。

### 2.3 心跳与工作连接的复检

配置 `auth.additionalScopes = ["HeartBeats", "NewWorkConns"]` 后(frs 与 frpc 双侧):

- 快照形态:每 30s 心跳/每条 work conn 按**当前快照**复检——移除用户后 ≤30s 存量断线
- 验证形态:按**登录时缓存的 token 本地复检**(不回调,保证廉价与服务无关)——存量用户的强制下线走 §3 Kick

### 2.4 frps 侧配置示例(verify 形态)

```toml
bindPort = 7000
auth.token = "占位"
auth.additionalScopes = ["HeartBeats", "NewWorkConns"]
transport.heartbeatTimeout = 90

[tokenGate]
verify = "https://auth.example.com/internal/verify"
verifyUser = "frps-edge-1"
verifyPassword = "…"
```

---

## 3. 管理 API(挂 frps webServer,Basic Auth)

### 3.1 强制下线(P1 补丁)

```
POST /api/v2/users/{user}/kick
→ 200 {"code":200,"data":{"kicked":["<runID>", …]}}     # 空数组也是 200(幂等)

POST /api/v2/clients/{key}/kick     # key = {user}.{clientID},见 GET /api/v2/clients
→ 200 {"code":200,"data":{"kicked":["<runID>"]}}
→ 404 该实例不存在或已离线
```

效果:控制连接断开、代理监听器关闭(**新**访客连接立即失败)、registry 标记 offline。已建立的在途访客连接不被主动切断(自然结束);踢后客户端自动重连,**拒绝回访须由认证层承担**(移出快照 / verify 拒绝)。

**封禁时序契约(实测)**:先移除认证(快照移除 / verify 拒绝)→ **等待 ≥ frps 快照周期(5s)** → 再 Kick。并发执行会被旧快照在 ~2ms 内重连钻窗。此等待仅针对快照/文件形态;**verify 形态判决实时、无快照窗口**——验证方改状态后可直接 Kick,两步紧邻(实测)。

### 3.2 计量采集(v2 API)

```
GET /api/v2/proxies?page=N&pageSize=200    # ≤200/页,翻页至尽
Authorization: Basic {webServer.user}:{webServer.password}
→ {"code":200,"data":{"total":N,"items":[{
     "name":"alice__x","user":"alice",
     "status":{"todayTrafficIn":…,"todayTrafficOut":…,"curConns":…}}]}}
```

消费规范(全部实测):
- **不过滤 status**:离线代理条目保留(7 天),其关闭时一次性入账的末窗口字节必须可读
- `spec` 块(`http.subdomain` / `tcp.remotePort` 等)**仅 online 条目填充**——离线条目的 configurer 不可达,spec 为空对象;消费地址信息的采集方应只依赖 online 条目(控制平面的活跃隧道视图即按此消费)
- `code` 字段为 HTTP 状态码语义(成功 = 200,非 0)
- 归属键 = `user` 字段(由认证层保证不可冒用)
- 计数在**连接关闭时**入账:长连接期间读数为 0 属正常;跨天/重启清零由差值三态处理(`curr < prev` 取 `curr`)
- 逐代理 7 日历史:`GET /api/v2/proxies/{name}/traffic`

---

## 4. 安全边界与部署要求

1. **网络**:webServer 与所有集成接口仅绑内网;verify/snapshot 回调路径不得经公网代理
2. **凭证分级**:verify/snapshot 的 Basic 凭证 ≠ 用户 token,各自独立轮换;raw token 仅存在于验证方存储、frps 内存(会话期)、frpc 本地 0600 文件
3. **失败语义**:认证系统不可达 → 新登录 fail-close(绝不放行),存量 fail-open(业务连续);恢复即自动收敛
4. **审计**:建议集成方记录每次 verify 判决(who/when/reason);frps 侧 kick 与登录失败均有日志
5. **时间**:验证方与 frps 须 NTP 同步(±15min 窗口)

---

## 5. 兼容性承诺

- `[tokenGate]` 三形态的配置字段与上述契约在 mcp patch set v1 内保持稳定
- reason 码为开放集合:新增码对 frps 是透明字符串,无需升级
- 不配置 `[tokenGate]` 时行为与上游 fatedier/frp v0.71.0 完全一致(上游测试套件全绿)
