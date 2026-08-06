# bindCacheAnalyze

这是一个基于 Go 语言（Go 1.24.1）实现的 **BIND DNS 缓存快照（BIND DNS Cache Dump）高性能分析工具**。

该工具能够解析由 `rndc dumpdb -cache` 导出的 BIND 缓存文本文件，在内存中重建高精度的结构化 DNS 记录。它专为安全审计与网络运维设计，可进行权威 NS IP 归属地匹配、父子 NS 解析一致性探测、特殊 DNS 记录（如 TYPE65/SVCB）提取、解析异常检测、黑洞劫持域名识别等。此外，该项目还支持自动将分析数据批量导入 MySQL 数据库，并配备了一个可视化的 Web 监控控制台。

---

## 🚀 核心功能特性

1. **缓存解析与重构**：流式高效解析 BIND 缓存文件（支持大文件，自动禁用 Go 垃圾回收以避免 STW 引起页抖动）。支持常规 DNS 记录和类似 `\-A ;-$nxdomain` 格式的否定缓存，并按规范解析并重构 SVCB/TYPE65 记录的详细参数（如 `alpn`、`ipv4hint` 等）。
2. **多维安全与隐患扫描**：
   * **单一 NS 隐患** (`single-ns`)：统计和扫描仅配置了单条权威名服务器（NS）的潜在隐患二级域名。
   * **NXRRSET 异常响应** (`nxrrset-fail`)：并发探测 `nxrrset` 缓存对应的实际标准 DNS 解析响应，捕获如 `ServFail` 等异常。
   * **父子 NS 一致性** (`parent-child`)：比对父域名授权给子域的 NS 记录与子域权威服务器实际返回的 NS 记录之间的差异，揭示潜在的同步隐患。
   * **权威服务器比对** (`ns-diff`)：并发比对特定权威 NS 响应与公共标准 DNS 解析结果的一致性。
   * **黑洞劫持检测** (`hijack`)：扫描检测将 NS 篡改指向国际网络安全组织黑洞地址（如 `shadowserver.org`）的疑似被劫持域名。
3. **数据导出与落库**：支持批量导出各种解析记录（如 NS、NSIP、MX、SPF、CAA、SOA、NSEC3 等）至本地 CSV/TXT 文件，或自动创建表结构并写入 MySQL 数据库。
4. **生产 Web 控制台**：React 前端嵌入 Go 单二进制，读取 ClickHouse 中的 NS 变化、冗余、父子不一致、黑名单和可用性风险事件，提供筛选分页、证据详情、拨测、告警、域名追溯、角色权限和审计。
5. **NS 可用性复核**：仅对当前 zone 实际引用的 NS 端点提取 BIND ADB/SRTT 遥测；普通 DNS 连续超时或伴随超时的高 SRTT 连续出现两份快照后，才生成候选事件，并经 relay 直连 SOA/NS 拨测确认。EDNS 超时但普通 DNS 成功只标记兼容性降级，不直接告警。

---

## 📂 源码架构与核心模块

本工具由多个 Go 核心源文件构成，分工明确：

* [main.go](main.go)：程序的启动入口和核心分析控制中心。定义了全局的 [BindCache](main.go#L19-L27) 结构体，处理命令行标志并调度不同的检测或导出任务。
* [readDbFile.go](readDbFile.go)：缓存文件的高性能流式状态机解析器，提供行记录正则匹配和复杂的 [TYPE65](readDbFile.go#L378) (SVCB) 多行重组与 HEX 参数解码逻辑。
* [dns.go](dns.go)：网络 DNS 探测层，封装了基于 `github.com/miekg/dns` 的单次解析、全链路解析状态捕获和迭代 trace 解析逻辑。
* [nsNotEqual.go](nsNotEqual.go)：用于并发比较公共 DNS 服务器与域名自身 NS 服务器之间的 A 记录解析结果，识别一致性偏离的域名。
* [belong.go](belong.go)：底层的权威服务器 IP 归属地匹配引擎。支持通过 CIDR 或 IP 范围段批量载入配置（如 `vip.txt`），以匹配解析服务器所属组织。
* `ns_web_db.go`、`ns_api_v1.go`、`ns_operations_api.go`：正式 ClickHouse Web、统一风险 API、拨测/告警/系统/设置接口。
* `frontend/`：Kimi 设计还原后的 React/Vite 前端，生产构建资源嵌入 Go 二进制。
* [config.go](config.go)：系统配置解析器，支持 ClickHouse、Web、递归 dump 目录/账本、GeoIP、拨测 relay、严重告警和 relay SMTP 配置；密码与令牌通过环境变量引用。
* [docs/ns-relay-deployment.md](docs/ns-relay-deployment.md)：递归目录双观察账本、同网段 DNS/邮件 relay 协议、配置和部署步骤。

---

## 🛠️ 参数说明与使用指南

### 命令行选项

| 参数 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `-file` | `cache_dump.db` | 指定待解析的 BIND 缓存快照文件路径 |
| `-query` | `""` | 查询指定域名在内存中的详细解析记录 |
| `-format` | `text` | 查询结果的输出格式，支持 `text`（友好文本）或 `json` |
| `-check` | `""` | 执行缓存状态与安全扫描，支持 `single-ns`, `nxrrset-fail`, `parent-child`, `ns-diff`, `hijack` |
| `-export` | `""` | 执行数据导出，支持 `all`, `type65`, `ns`, `nsip`, `mysql` 等 |
| `-web` | `false` | 启动可视化 Web 监控控制台 |
| `-port` | `8888` | 指定 Web 控制台的监听端口 |

### 常见操作指令示例

#### 1. 查询单条域名的详细内存缓存
```bash
./bindCacheAnalyze -file cache_dump.db -query google.com -format json
```

#### 2. 执行安全隐患与劫持扫描
* **黑洞劫持检测**：
  ```bash
  ./bindCacheAnalyze -check hijack
  ```
  扫描结果将保存至 [hijack.txt](hijack.txt)。
* **单一 NS 隐患探测**：
  ```bash
  ./bindCacheAnalyze -check single-ns
  ```
* **父子 NS 记录不一致探测**：
  ```bash
  ./bindCacheAnalyze -check parent-child
  ```
  差异将被记录到 [deffer.txt](deffer.txt)。

#### 3. 导出全量解析记录并写入 MySQL
通过在配置文件 [config.json](config.json) 中配置正确的 MySQL 连接串后，运行：
```bash
./bindCacheAnalyze -export all
```

#### 4. 启动正式 Web 可视化控制台
```bash
cd frontend
corepack enable
pnpm install --frozen-lockfile
pnpm build
cd ..
go build -o bindCacheAnalyze .
export CLICKHOUSE_DSN='clickhouse://default:URL_ENCODED_PASSWORD@127.0.0.1:19000/bind_cache_analyze'
./bindCacheAnalyze -web-db -config /etc/bind-cache-analyze/config.json
```
服务启动后，通过浏览器访问 `http://127.0.0.1:8888/`。正式部署、角色密码、relay
证书和 systemd 示例见 `docs/ns-relay-deployment.md`；无 ClickHouse 的 `-web` 仅用于调试。

---

## 📊 输出结果文件参考

在运行不同的检测与导出任务时，系统会生成以下报告和数据文件：
* [hijack.txt](hijack.txt)：被安全机构黑洞化的疑似劫持域名清单。
* [deffer.txt](deffer.txt)：父域名指向的子域 NS 与子域本身返回的 NS 不一致的记录。
* [ns.txt](ns.txt)：公共标准 DNS 与自身权威服务器解析出的 A 记录不匹配的域名清单。
* [fail.txt](fail.txt)：探测遭遇解析失败（如 ServFail）的异常域名。
* [ipToDomain.csv](ipToDomain.csv)：各权威服务器 IP 所承载解析域名的汇总与归属说明。

---

## 🧪 单元测试

项目提供了完整的单元测试，覆盖了基础数据结构解析（如 BIND 缓存、多行与否定缓存解析等）与 IP 归属地匹配等核心逻辑。

你可以通过以下命令在本地执行测试：
```bash
go test -v ./...
```

## 🐳 容器化部署与本地运行

项目提供了完整的容器化支持，可以使用 Docker 或 Docker Compose 进行一键式快速拉起与运行：

### 使用 Docker 本地构建与运行
1. 构建镜像：
   ```bash
   docker build -t bind-cache-analyze:latest .
   ```
2. 运行容器（以 Web 模式启动）：
   ```bash
   docker run -d --name bind-cache-app \
     -p 127.0.0.1:8888:8888 \
     -v /etc/bind-cache-analyze:/etc/bind-cache-analyze \
     -v /data/bind-cache:/data/bind-cache \
     -e CLICKHOUSE_DSN \
     bind-cache-analyze:latest -web-db -listen 0.0.0.0 -config /etc/bind-cache-analyze/config.json
   ```

### 使用 Docker Compose 一键启动集成环境
项目配套的 [docker-compose.yml](docker-compose.yml) 已经集成并预配置了本地 ClickHouse 实例，能极大简化部署过程。
1. 拷贝并配置你的 [config.json](config.json) (参考配置模板 [config.json.example](config.json.example))。
2. 运行以下命令拉起服务：
   ```bash
   docker compose up -d
   ```
   启动后程序会自动连接 ClickHouse 并创建所需表结构，同时在 `http://localhost:8888` 暴露 Web 可视化页面。

## 🗄️ 数据库 Schema 说明
对于需要独立在 ClickHouse 服务器中预先建表的生产场景，项目在根目录下提供了完整的 DDL 结构脚本：
* `schema_clickhouse.sql`：旧版日粒度扁平快照与分析表。
* `schema_ns_monitor.sql`：正式 NS 时序监测、风险事件、ADB 端点状态/变化历史、拨测、告警、处置与审计表；生产 Web 使用这一组表。

## ⚙️ 持续集成 (CI)
项目在 [.github/workflows/go.yml](.github/workflows/go.yml) 中配置了 GitHub Actions 自动化工作流。在每次推送（Push）或提交拉取请求（Pull Request）到 `main`/`master` 分支时，都会自动运行代码编译和全部单元测试。
