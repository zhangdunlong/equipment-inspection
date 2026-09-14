# 设备点检巡检系统（开源版）  ·  当前版本 v1.0.0（2026-09-09）

一套**零依赖**的设备点检 / 巡检管理系统：支持设备台账、按日 / 按月考勤式点检、电子签名确认、月度打印与记录归档。前端与后端同源一体，可部署到云端、自有服务器，也可单机离线运行。

> 适用场景：工厂、实验室、物业等仪器的日常点检、月度巡检与签名确认。

## 🚀 在线演示 / Live Demo

**👉 https://equipment-inspection-cp0.pages.dev**

演示数据全部为**虚构脱敏内容**（设备编号 `DEMO-NO-*`、车间/测试室、型号 `设备型号-*`，不含任何真实姓名、设备序列号或手写签名），可直接登录体验全部功能：

| 角色 | 账号 | 密码 | 权限 |
|------|------|------|------|
| 管理员 | `admin` | `admin123` | 全部管理权限 + 点检 |
| 操作员 | `demo-user` | `demo123` | 仅点检与查看 |
| 签名人 | `演示签名人` | `sig123` | 手写签名确认 |

## 三套交付版本

| 目录 | 适用场景 | 运行方式 | 联网需求 |
|------|----------|----------|----------|
| `equipment-inspection/` | **Cloudflare Pages** 部署（Serverless） | `wrangler pages deploy` | 部署后联网 |
| `equipment-inspection-server/` | **自有服务器**（Linux / Windows / macOS） | `node server.js` + PM2 | 局域网 / 公网 |
| `equipment-inspection-win10/` | **单机离线**（车间电脑，双击即用） | 自带便携 Node，**免安装** | 纯本地 |

三套版本**前端页面与后端 API 契约一致**，数据格式互通（均为 `data/kv.json` 顶层结构：`admin / devices / templates / signers / inspections / abnormalRecords`）。

## 功能

- **设备大屏**：实时状态、当月点检进度、异常统计、最近点检记录。
- **点检作业**：按设备 / 按日点检，异常备注，签名密码校验。
- **多用户与角色权限**：独立登录页（`login.html`），管理员可在「用户管理」中增删改查账号并分配 `admin` / `user` 角色；`admin` 拥有全部管理权限（含用户管理、设备批量删除、整月一键点检），`user` 仅可点检与查看；密码经 `PEPPER` 加盐 SHA-256 哈希存储，会话令牌为 `用户名.HMAC(SECRET, 用户名)`。
- **月度点检表 / 整月打印**：A4 排版，含签名缩略图与异常说明，一键打印。
- **管理后台**：设备增删改查（批量生成 / 文本导入 / 批量删除）、点检模板与检查项、签名人管理（手写签名）、整月一键点检、管理员改密、记录查询与删除。
- **房间 / 区域管理**：`/rooms` 维护点检区域（车间），设备按区域归类，大屏与月度表按区域统计设备分布。
- **数据备份与恢复**：管理员可一键导出全量 JSON 备份（`GET /api/admin/backup`），亦可作为迁移 / 灾备手段。
- **巡检记录 CSV 导出**：`GET /api/admin/export-inspections-csv` 将全部巡检记录导出为 CSV（UTF-8 BOM，Excel 直接打开）。

## 快速开始

### Cloudflare Pages
```bash
cd equipment-inspection
npx wrangler pages deploy . --project-name=equipment-inspection
```
数据存于 Cloudflare KV（绑定 `INSPECTION_DATA`），首次访问自动生成随机密钥。

### 自有服务器
```bash
cd equipment-inspection-server
node server.js            # 或 PORT=9000 node server.js
```
生产环境建议 PM2 守护 + Nginx 反代（见 `equipment-inspection-server/README.md`）。

### Win10 便携版
把从 Node 官网下载的 `node.exe` 放入 `equipment-inspection-win10/runtime/`，双击 `启动.bat` 即用。

## 默认账号

| 角色 | 账号 | 密码 | 权限 |
|------|------|------|------|
| 管理员 | `admin` | `admin123` | 全部管理权限 + 点检 |
| 操作员 | `demo-user` | `demo123` | 仅点检与查看 |

> ⚠️ 上线前务必到「管理后台 → 修改密码」或「用户管理」改掉默认口令。仓库自带的脱敏演示数据中，操作员账号为 `demo-user` / `demo123`。

### 首次使用
打开首页后点击「登录」进入 `login.html`：以 `admin` 登录可进行用户管理与全部后台操作；以 `user` 登录仅能完成点检、查看大屏与月度表。

## 数据安全与脱敏

- 签名 / 会话所用的 `PEPPER`、`SECRET` **不硬编码**：Cloudflare 版持久化在 KV 的 `STORE` 单键内；自有服务器 / Win10 版持久化在 `data/config.json`。
- 仓库已附带一份**已脱敏演示** `data/config.json`（演示密钥）与 `data/kv.json`：设备编号（`DEMO-NO-0001…`）、区域名（车间A / 车间B / 测试室）、型号（`设备型号-A…`）、签名人（`演示签名人`）均为虚构占位，**不含任何真实人员姓名、真实设备序列号、真实手写签名或企业内部信息**。克隆即可体验；上线前请替换为你的真实数据并重新生成密钥（删除 `data/config.json` 重启即重置）。
- 示例数据中的表单标准号 `DEMO-QR-001 Rev.A1` 为**通用占位**（点检表版式标识），可按需替换为贵司自有模板编号。
- 如需迁移：直接复制 `data/kv.json` 即可；删除 `data/config.json` 重启可重置密钥。

### 关于 Cloudflare KV 存储上限（签名去重）
Cloudflare KV 单值上限 **25 MB**。原始方案把每张手写签名（base64 PNG）内嵌进每一条点检记录，2424 条记录会撑到 ~41 MB 超限。本仓库采用**签名去重**：
- 每条点检记录**不再**内嵌 `signature_image`，仅保留 `signer_id` / `signed_by`；
- 手写签名只存于**签名人记录**一处；
- 读取月度表 / 大屏时由后端 `signerSignature()` 按 `signer_id` 注入签名图，**前端零改动**。

去重后本仓库演示整库 `STORE` 约 **2.2 MB**（124 台设备 / 3798 条记录），远低于 25 MB 上限，无需引入 R2 对象存储。（若未来数据远超 25 MB，可改走 R2 分片存储。）

## 许可证

[MIT License](../LICENSE) © Equipment Inspection Contributors
