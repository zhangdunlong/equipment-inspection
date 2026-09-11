# 设备点检巡检系统（开源版）

一套基于 **零依赖 Node.js**（仅用内置模块，无需 `npm install`）的通用设备点检 / 巡检管理系统。
前端页面与后端 API 一体打包，数据持久化到本地 `data/kv.json`，可部署到服务器长期运行，
也可做成免安装的 Windows 便携版在单台电脑上离线使用。

> 适用于工厂 / 实验室 / 物业等场景的仪器设备日常点检、月度巡检、签名确认与记录归档。

---

## 一、功能特性

- **设备大屏**：实时状态、当月点检进度、异常统计、最近点检记录。
- **点检作业**：按设备 / 按日点检，异常备注，签名密码校验。
- **月度点检表 / 整月打印**：A4 排版，含签名缩略图与异常说明，一键打印。
- **管理后台**：
  - 设备增删改查（批量生成编号、文本批量导入、批量删除）
  - 点检模板与检查项维护
  - 签名人员管理（含手写电子签名图片）
  - 整月一键点检、管理员改密
  - 点检记录查询与删除
- **电子签名**：操作员在点检 / 月度表上手写签名，签名图片随记录保存（纯本地，不含任何预置真实签名）。

---

## 二、技术亮点

- **零依赖**：服务端只用 Node 内置 `http / fs / path / crypto`，克隆即跑，无需 `npm install`。
- **前后端一体**：`public/` 静态前端 + `server.js` 实现全部 `/api/*`，单进程即可。
- **跨平台**：同一份 `server.js` 在 Linux / macOS / Windows 上运行一致。
- **开源已脱敏**：已移除原项目中的硬编码密钥、企业内部标准号、具体设备型号示例等敏感信息。

---

## 三、目录结构

```
equipment-inspection-server/   ← 仓库根（也是本开源项目）
├── server.js            # 零依赖 Node 服务（前端 + 后端一体）
├── package.json
├── start.sh             # Linux / macOS 启动脚本
├── 启动.bat             # Windows 启动脚本（智能检测 Node 运行时）
├── public/              # 前端页面（index / admin / inspect / monthly / print-all + assets）
├── data/               # 运行时自动生成（kv.json 业务数据、config.json 密钥）
├── LICENSE             # MIT
└── README.md
```

> ⚠️ `data/`、`runtime/`、`*.exe` 已被 `.gitignore` 排除，**不会随源码提交**。

---

## 四、快速开始

### 方式 A：Windows 一键运行（推荐普通用户）

1. 安装 [Node.js LTS](https://nodejs.org)（或把 `node.exe` 放到仓库根 `runtime\` 实现纯离线）。
2. **双击 `启动.bat`** → 自动启动服务并打开浏览器 `http://localhost:8787/`。

> 想做成完全离线的便携版？把从官网下载的 Windows 版 `node.exe` 放进 `runtime\` 文件夹，
> 整个目录拷到任意电脑双击 `启动.bat` 即用，无需安装任何软件。

### 方式 B：命令行运行（服务器 / 开发）

```bash
cd equipment-inspection-server
node server.js
# 自定义端口： PORT=9000 node server.js
```

启动后访问 `http://<服务器IP>:8787/`，管理后台 `http://<服务器IP>:8787/admin`。

---

## 五、生产部署（推荐 PM2 守护 + Nginx 反代）

### 1) PM2 守护（崩溃自启、开机自启）

```bash
npm i -g pm2
cd /path/to/equipment-inspection-server
pm2 start server.js --name inspection -i 1
pm2 save
pm2 startup          # 按提示执行生成的命令实现开机自启
```

### 2) Nginx 反向代理（绑定域名 / HTTPS）

```nginx
server {
    listen 80;
    server_name inspection.example.com;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

HTTPS 证书用 `certbot` 申请后，将 `listen 80` 改为 `listen 443 ssl` 并配置 `ssl_certificate` 即可。

### 3) Windows 服务器

直接 `node server.js` 运行，或用 `nssm` 把 `node server.js` 注册为系统服务。

---

## 六、默认账号与安全

| 角色 | 账号 | 密码 |
|------|------|------|
| 管理员 | `admin` | `admin123` |

> **上线前请务必**到「管理后台 → 修改密码」改掉默认密码。

**密钥安全说明**：本系统签名 / 会话所用的 `PEPPER`、`SECRET` 不再硬编码于源码，
改为**首次启动时随机生成并持久化到 `data/config.json`**（已被 `.gitignore` 排除）。
每次全新部署都会得到不同的密钥，避免源码泄露导致的安全风险。如需重置密钥，删除 `data/config.json` 重启即可。

---

## 七、数据与隐私

- 全部业务数据存于 `data/kv.json`（设备、模板、签名人、点检记录）；密钥存于 `data/config.json`。
- **备份 / 迁移**：直接复制 `data/` 文件夹即可。迁移到新服务器只需把 `data/kv.json` 拷过去。
- **电子签名**：为操作员在页面上手写采集，签名图片随点检记录本地保存；源码中**不含任何预置的真实人员签名或隐私数据**。
- 本仓库**不包含**任何企业名称、内部标准号、真实设备型号、云服务商配置等敏感信息。

---

## 八、开源与脱敏声明

本项目基于一套企业内部设备点检系统的实现重写并开源，已做以下脱敏处理：

- 移除后端硬编码的 `PEPPER` / `SECRET` 密钥（改为随机生成持久化）；
- 移除前端页面中的企业内部标准号水印与具体设备型号示例（替换为通用占位）；
- 不包含任何真实企业的名称、部署域名、云服务商命名空间 ID 等基础设施信息；
- 电子签名相关代码仅保留通用手写采集能力，不含真实签名样本。

如果你将其用于生产，请自行配置企业模板、设备清单与签名人员，并修改默认管理员密码。

---

## 九、许可证

[MIT License](../LICENSE) © Equipment Inspection Contributors
