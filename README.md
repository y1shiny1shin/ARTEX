# RyAgent Platform

个人单用户、移动优先的 Agent 控制台。ARTEX 是第一个组件（Connector），不是平台本身。

```text
artex/   ARTEX 渗透测试引擎（Go + Next.js）
bff/     RyAgent BFF（Go）：设备认证、能力聚合、事件、通知、主控对话台
app/     Android App（Expo / React Native）
docs/    平台设计文档（本地，已被 .gitignore 排除）
```

- 设计文档：`docs/RyAgent-平台设计.md`
- ARTEX 组件：`artex/README.md`
- BFF / App 尚未落地，按 `docs/RyAgent-平台设计.md` 的 P0 顺序推进。

## 安全

- 服务器地址、密码、API Key 只放本地 `tmp/`、`bff/.env`、环境变量。
- `docs/`、`tmp/`、`keys/`、`.env` 已在 `.gitignore` 中排除。
