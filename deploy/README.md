# systemd 部署参考

适用于使用 systemd 的 Linux 主机。`gist-gateway.service` 使用独立系统用户 `gistgw`，应用目录 `/opt/apps/gist-gateway/`，仅监听 `127.0.0.1:4387`；默认数据目录 `data/`，二进制在 `bin/`。这些路径须与实际部署一致。

服务设置 96 MiB `MemoryHigh` 和 128 MiB `MemoryMax`、50% CPU 配额、16 个任务及有限文件描述符；这些是保护额度，不代表应用日常占用。根文件系统只读，仅数据目录可写；禁用额外能力、提权、设备及主目录访问。服务以 SIGINT 停止，匹配程序的优雅退出与统计刷盘逻辑。

## 安装顺序

1. 用 `cargo test --release --locked` 与 `cargo build --release --locked` 验证目标架构的构建；记录工具链、产物 SHA-256 和实际资源限制。不要将 Windows `.exe` 当作 Linux 产物。
2. 检查回环端口、系统用户和应用目录未被其他服务占用。创建 `gistgw` 系统用户，配置不可登录 shell，数据目录归属该用户且权限为 0700；安装二进制至 `bin/gist-gateway`。
3. 以服务用户执行 `init --public-url https://sub.example.com`；通过交互或标准输入设置新的强口令，不使用 `--dev`。初始化会生成 SQLite 和独立 `master.key`，拒绝覆盖旧文件。
4. 独立保存候选服务和反代配置。备份现用反代配置；先运行 `systemd-analyze verify` 与目标反代的配置校验，保持其他站点的规则和访问限制。
5. 安装服务单元，运行 `systemctl daemon-reload`、`systemctl enable --now gist-gateway`，确认回环健康检查成功后平滑加载 HTTPS 反代。
6. 验证真实 HTTPS 的生产 Cookie、登录、导入、正文校验、独立撤销、到期和后台权限；抽查原有服务。保留配置备份和失败回滚路径。

## 反代访问与日志

管理页面和 `/api/admin/*` 可以沿用已有来源白名单；订阅 `/s/*` 使用分享令牌授权。不要为订阅删除其他后台或站点的白名单。不需要把 4387 暴露到公网，也不需要改变 SSH 或防火墙。

若反代设置真实客户端 IP 头，启动服务时加 `--trust-proxy`（或 `GATEWAY_TRUST_PROXY=1`）；反代必须覆盖而不是追加客户端自带值，否则登录限速键可被伪造。未启用时所有直连请求共用一个限速键。

### 可选：订阅路径按来源地区限制

如果订阅只给固定地区或自有节点使用，可以在反代对 `/s/*` 再加一层来源 IP 白名单，应用本身不需要改。做法是生成一个 Caddy 片段并在订阅 handler 里 `import`：

```caddyfile
handle @gist_subscription {
	import /etc/caddy/gist-subscription-allow.caddyfile
	reverse_proxy 127.0.0.1:4387
}
```

片段内容为 `@gist_sub_not_allowed not remote_ip <允许的 IP/CIDR…>` 加 `respond @gist_sub_not_allowed 404`。地区列表可从 APNIC 委派数据生成；脚本、CIDR 和节点清单属于部署专有数据，放在私有运维记录，不放进通用源码。用 `caddy validate` 校验后平滑 reload，并实测允许与拒绝两侧。

注意：

- 地区列表会随 APNIC 委派变化，需定期重新生成并 reload；拒绝时返回 404，与无效分享一致。
- 只对 `/s/*` 生效，管理后台仍用原有白名单，避免把登录页开放给整个地区。
- 若域名没有 AAAA 记录，IPv4 列表即可；以后加 IPv6 时要同时补 IPv6 段。
- 若站点经过 CDN 或其它反代，`remote_ip` 看到的是上一跳地址，需要改用可信转发头并确认来源，否则限制会失效或误伤。

反代访问日志和运行时错误日志是两个通道，必须分别保护：

- 新站点跳过访问日志，或者确保订阅的完整 URI 被删除。
- 上游连接失败可能把原请求 URI 写入反代错误日志；需删除该字段和可能携带完整链接的 Referer。仅关闭访问日志不足以保护令牌。
- 以不含隐私的验收分享触发一次受控失败，检查实际日志没有令牌，而不只检查配置文本。

具体域名、凭据和服务器备份路径应放在私有运维记录，不随应用源码对外发布。

## 一致备份与恢复

停止本服务并等待退出，再复制整个数据目录；同时独立备份原 `master.key`。重新启动服务，确保备份权限受限。不要在运行时只复制 SQLite 主文件。

恢复演练使用独立目录与回环端口；确认 SQLite 完整性、管理员会话/登录、既有分享的解密复制及匿名下载正文完全一致。结束后停止演练进程、移除演练副本，保留受控备份。恢复不能通过重新生成密钥完成。
