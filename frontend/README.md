# bindCacheAnalyze 正式前端

该目录保存递归 DNS 风险监测平台的 React/Vite 前端。当前视觉与交互基准来自用户提供的
`Kimi_Agent_前端功能规划.zip`，生产构建结果由 Go 通过 `embed` 打入单一可执行文件。

## 开发

```bash
pnpm install
pnpm dev
```

默认开发地址为 `http://127.0.0.1:3000/`。页面使用 Hash 路由，示例：

```text
http://127.0.0.1:3000/#/overview
http://127.0.0.1:3000/#/events
http://127.0.0.1:3000/#/settings
```

## 构建

```bash
pnpm build
```

`dist/` 必须随源码保留，因为根目录的 `ns_web.go` 会嵌入：

- `frontend/dist/index.html`
- `frontend/dist/assets/*`

修改前端后需要重新执行构建，再运行根目录 Go 测试：

```bash
GOCACHE=/private/tmp/bind-cache-go-cache go test ./...
```

## 数据接入状态

当前页面仍使用 `src/data/mock.ts` 中的仿真数据作为视觉基准。正式 API、四类统一事件、
处置动作、黑名单导入、审计和配置保存的实现范围见：

```text
docs/kimi-frontend-implementation.md
```
