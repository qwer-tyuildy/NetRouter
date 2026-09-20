# NetRouter

基于 Ubuntu 的一体化路由器 / 家庭服务器管理软件。单文件 Python 应用，通过浏览器统一管理**路由器、防火墙、虚拟机、磁盘、文件共享**等功能。

```
┌─────────────────────────────────────────────────────────────┐
│  NETROUTER                                 [修改密码] [登出] │
├─────────────────────────────────────────────────────────────┤
│  概览 │ 路由器 │ 防火墙 │ 包管理 │ 虚拟机 │ 磁盘管理 │ 文件共享 │
└─────────────────────────────────────────────────────────────┘
```

---

## 目录

- [核心特性](#核心特性)
- [系统要求](#系统要求)
- [快速开始](#快速开始)
- [功能说明](#功能说明)
  - [概览](#1-概览)
  - [路由器](#2-路由器)
  - [防火墙](#3-防火墙)
  - [包管理](#4-包管理)
  - [虚拟机](#5-虚拟机)
  - [磁盘管理](#6-磁盘管理)
  - [文件共享](#7-文件共享)
- [API 参考](#api-参考)
- [配置文件位置](#配置文件位置)
- [安全设计](#安全设计)
- [故障排查](#故障排查)
- [常见问题](#常见问题)
- [卸载](#卸载)

---

## 核心特性

| 模块 | 能力 |
|---|---|
| **概览** | 实时流量图 / CPU / 内存 / 磁盘 / 温度 / 进程 / 网卡 / WiFi 客户端 / WireGuard / DHCP 租约 / 网速测速 / Ping / DNS / 路由表 / 邻居表 |
| **路由器** | WAN（DHCP / 静态 IP / PPPoE）+ LAN 桥接 + DHCP + WiFi AP + WireGuard（客户端/服务器）+ 一键应用 |
| **防火墙** | nftables 区域模型，强制启用；区域 / 转发 / 端口转发 / 端口开放关闭 |
| **包管理** | 5 组环境必备包一键安装（路由 / 虚拟机 / 磁盘 / 文件共享 / 通用）+ 搜索 / 安装 / 卸载 / 升级 |
| **虚拟机** | QEMU/KVM + libvirt，创建 / 启动 / 关机 / 编辑资源 / 添加磁盘 / 挂载 ISO / VNC 端口管理 |
| **磁盘管理** | 块设备浏览 / 挂载 / 格式化（7 种 FS）/ fstab 自动挂载（含校验回滚） |
| **文件共享** | Samba 共享增删改 / 账户管理 / Guest 策略管理 / force user·group |

**通用特性**：

- 单文件部署（`route.py`），除 `fastapi / uvicorn / pyyaml / psutil` 外无额外依赖
- 原子写配置，防截断损坏
- 所有系统配置文件字段严格正则校验，防注入 / RCE
- JWT 鉴权 + token 版本号（改密后旧会话立即失效）
- 登录失败限速（5 次 / 分钟 / IP）
- 审计日志（`/etc/netrouter/audit.log`）
- 关闭 `/docs` `/openapi.json` `/redoc`

---

## 系统要求

| 项目 | 要求 |
|---|---|
| 操作系统 | Ubuntu 20.04 / 22.04 / 24.04（Debian 11+ 亦可） |
| Python | 3.8+ |
| 权限 | **必须 root 启动**（修改网络 / 防火墙 / 系统服务） |
| 网络 | 至少 1 个 WAN 接口 + 1 个 LAN 接口（或 WiFi 网卡） |
| 内存 | ≥ 512 MB（若启用虚拟机建议 ≥ 4 GB） |
| 磁盘 | ≥ 1 GB 可用空间 |

### 依赖安装

```bash
sudo apt update
sudo apt install -y python3-pip
sudo pip3 install fastapi uvicorn pyyaml psutil
```

> Ubuntu 24.04+ 系统 pip 受 PEP 668 保护，可用：
> ```bash
> sudo apt install -y python3-fastapi python3-uvicorn python3-yaml python3-psutil
> ```

---

## 快速开始

### 1. 启动服务

```bash
sudo python3 route.py
```

首次启动会输出：

```
  NetRouter  Ubuntu 一体化路由器软件（安全加固版）
  =====================================
  监听地址 : http://0.0.0.0:8080
  配置目录 : /etc/netrouter
  Root     : 是

  ...

  首次启动，初始密码如下（请登录后立即修改）：
      XXXXXXXXXXXXXXXX
```

**记下这个随机密码**，稍后登录要用。

### 2. 自定义初始密码（推荐）

```bash
sudo NETROUTER_PASSWORD='MyStrongPass123' python3 route.py
```

### 3. 登录

浏览器打开 `http://<服务器IP>:8080`，输入密码登录。

### 4. 首次配置

```
1) 「包管理」→ 一键安装所需环境必备包
2) 「路由器」→ 勾选 WAN / LAN → 保存 → 一键应用
3) 按需配置：
   · 虚拟机（需先在包管理装虚拟机环境）
   · 磁盘管理（需先装磁盘管理必备）
   · 文件共享（需先装文件共享必备）
4) 「修改密码」→ 更改为强密码
```

### 5. 后台运行（systemd）

```bash
sudo tee /etc/systemd/system/netrouter.service > /dev/null <<'EOF'
[Unit]
Description=NetRouter
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/netrouter/route.py
Restart=on-failure
RestartSec=5
Environment=NETROUTER_PASSWORD=ChangeMe123

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now netrouter
sudo systemctl status netrouter
```

---

## 功能说明

### 1. 概览

| 面板 | 说明 |
|---|---|
| **实时流量** | WebSocket 每秒推送，可切换网卡，RX/TX 双线图 |
| **网速测速** | 浏览器 ⇄ 服务器，各持续 ≥ 5 秒，显示 Mbps / 延迟 |
| **CPU / 内存 / 交换** | 百分比 + 直方图 |
| **磁盘 / 温度** | 已挂载分区使用率、温度传感器 |
| **网络接口** | MAC / MTU / 速率 / IP / 累计 RX·TX |
| **WiFi 客户端** | 信号 / 上下行速率 |
| **WireGuard** | 隧道状态 / 对端握手 / 流量 |
| **DHCP 租约** | IP / MAC / 主机名 / 剩余时间 |
| **进程 Top 20** | 按 CPU 或内存排序 |
| **Ping / DNS** | 测试网络连通性 |
| **路由表 / 邻居表** | IPv4 + IPv6 |

---

### 2. 路由器

#### WAN 配置

| 模式 | 说明 |
|---|---|
| **DHCP** | 自动获取 IP / 网关 / DNS |
| **静态 IP** | 手动填写 CIDR + 网关 + DNS |
| **PPPoE** | 宽带账号密码拨号 |

#### LAN 配置

- 勾选多个接口组成桥接 `br-lan`（默认 `192.168.10.1/24`）
- 可开启 DHCP 服务（dnsmasq）
- LAN 中若包含无线接口，自动启用 hostapd 作为 AP

#### WiFi 配置

| 项 | 说明 |
|---|---|
| SSID | 1-32 字符 |
| 密码 | 8-63 字符（WPA2-PSK） |
| 频段 | 2.4 GHz / 5 GHz |
| 信道 | 依频段自动推荐 |
| 带宽 | 20 / 40 / 80 MHz |

#### WireGuard

- **客户端模式**：连接远程服务器
- **服务器模式**：接受客户端连接，支持对端管理（添加 / 删除 / 生成客户端配置）

#### 一键应用

依次执行：

1. 校验配置
2. 写入 Netplan + 应用
3. 写入 hostapd + dnsmasq + PPPoE（按需）
4. 启用 IP 转发
5. 写入 WireGuard 配置
6. **初始化防火墙基础区域**（lan → wan 放行，其余拒绝）
7. **自动放行** SSH（22/tcp）和管理端口（8080/tcp）
8. 加载 nftables
9. 按顺序启动服务

每一步都会返回状态（成功 / 失败），失败会中止后续步骤。

---

### 3. 防火墙

**区域模型**，不可关闭。

| 面板 | 说明 |
|---|---|
| **区域设置** | 名称 / 接口 / 输入策略 / 输出策略 / 转发策略 / NAT |
| **区域转发** | 允许源区域 → 目标区域 |
| **端口转发** | DNAT，将外部端口映射到内网主机 |
| **端口开放 / 关闭** | 按区域和端口控制入向访问 |
| **规则集合** | 展示所有 nftables 表 / 链 / 规则 / 集合 |

**默认安全策略**：

- `input` 默认 **DROP**（除 DHCP / ICMP / 已建立连接）
- `forward` 默认 **DROP**（除 lan→wan 和已建立连接）
- WAN 侧默认放行：`22/tcp`（SSH）、`8080/tcp`（管理端口）
- 需要 WAN 访问的服务需手动加端口规则

---

### 4. 包管理

5 个一键安装面板：

| 面板 | 包含 |
|---|---|
| **路由功能必备** | hostapd / dnsmasq / nftables / wireguard-tools / bridge-utils / iw / rfkill / ppp / pppoe |
| **虚拟机环境必备** | qemu-system-x86 / qemu-utils / libvirt / virtinst / ovmf / cpu-checker |
| **磁盘管理必备** | util-linux / dosfstools / exfatprogs / ntfs-3g / xfsprogs / btrfs-progs / f2fs-tools / e2fsprogs |
| **文件共享必备** | samba / samba-common-bin / smbclient |
| **系统操作** | 更新索引 / 升级系统 / 刷新已安装 |

每个包的安装状态实时显示（✓ 已安装 / ✗ 未安装）。安装任务在后台运行，实时输出 apt 日志。

搜索框支持包名关键字（≥2 字符），结果可一键安装。

---

### 5. 虚拟机

#### 前置条件

1. 包管理 → **虚拟机环境必备** → 一键安装
2. BIOS 开启 CPU 虚拟化（Intel VT-x / AMD-V）

#### 存储设置

可自定义默认存储目录，每台虚拟机拥有独立子目录：

```
<存储目录>/<虚拟机名>/<虚拟机名>.qcow2
```

#### 新建虚拟机

| 项 | 说明 |
|---|---|
| 名称 | 字母/数字开头，1-64 位 |
| vCPU / 内存 | 1-64 核 / 128-262144 MB |
| **磁盘模式** | 新建 / **导入已有 QCOW2** / 不创建 |
| 安装 ISO | **可选**，不选也能创建（后续挂载） |
| 网络桥接 | 默认 `br-lan` |
| VNC 端口 | 留空自动分配（5901-5999） |

**导入模式**：选择已有 QCOW2 文件，会自动**移动**到虚拟机专属目录，并从该磁盘启动（跳过安装）。

#### 虚拟机详情

- 修改 vCPU / 内存（热更新 + 持久化）
- 修改自启动
- 修改 VNC 端口 / 监听 / 密码（重启生效）
- 添加新磁盘（自动分配槽位 + qemu-img 创建）
- 挂载 / 卸载 ISO
- 移除磁盘设备（可选删除文件）
- 手动放行 / 撤销 WAN → VNC 端口

#### VNC 连接

用 TigerVNC / RealVNC 等客户端连接 `路由器IP:VNC端口`。

---

### 6. 磁盘管理

#### 块设备列表

展示所有磁盘 / 分区，含：

- 设备名 / 大小 / 文件系统 / 标签 / UUID / 挂载点
- 系统盘标记（自动检测，禁止操作）
- 只读 / 可移动设备标记
- NetRouter 管理标记

#### 挂载

| 类型 | 说明 |
|---|---|
| **临时挂载** | 只执行 `mount`，重启失效 |
| **自动挂载** | 写入 `/etc/fstab` 的 NetRouter 管理块，含 `nofail` |

#### 格式化

支持 7 种文件系统：

```
ext4 / xfs / btrfs / vfat(exFAT 兼容) / exfat / ntfs / f2fs
```

格式化需要二次确认（输入 `FORMAT` 字样）。

#### fstab 安全机制

- 使用标记块隔离，**原 fstab 内容不动**：

  ```
  # >>> NetRouter Managed Mounts BEGIN (do not edit)
  UUID=xxxx  /mnt/data  ext4  defaults,nofail  0  2
  # <<< NetRouter Managed Mounts END
  ```

- 写入前用 `findmnt --verify` 校验，**失败拒绝写入**
- 校验失败自动回滚挂载
- 首次修改前自动备份到 `/etc/fstab.netrouter.bak`
- 默认添加 `nofail`，设备缺失不阻塞启动

---

### 7. 文件共享

#### Samba 服务状态

- 运行状态
- 配置文件路径
- 重启服务按钮
- **认证失败策略**（map to guest）

| 策略 | 行为 |
|---|---|
| **Never** | 认证失败立即拒绝，Windows 弹窗重输（**推荐**） |
| **Bad User** | 用户名不存在 → 降级 Guest |
| **Bad Password** | 密码错误 → 降级 Guest |
| **Bad Uid** | UID 无效 → 降级 Guest |

#### 共享列表

| 字段 | 说明 |
|---|---|
| 名称 | 1-32 位字母数字 _ - . |
| 路径 | 绝对路径 |
| 只读 | yes / no |
| 访客 | 允许免密码访问 |
| force user | 以指定系统用户身份访问文件（解决权限问题） |
| 编辑 / 删除 | 编辑现有共享 / 删除 |

#### 账户管理

| 操作 | 说明 |
|---|---|
| 添加用户 | 用户名（小写字母/数字/_/-）+ Samba 密码；可自动创建无登录权限的系统账户 |
| 修改密码 | 通过 smbpasswd 独立于系统密码 |
| 启用 / 禁用 | 临时禁止访问 |
| 删除 | 可选同时删除系统账户 |

**使用流程**：

1. 添加 Samba 用户（例如 `alice`）
2. 添加共享，`force user = alice`，`valid users = alice`
3. Windows 客户端连接 `\\路由器IP\共享名`，用户名 `路由器IP\alice`，密码 = Samba 密码

**强制指定用户的 Windows 命令行方式**：

```cmd
net use * /delete /y
cmdkey /delete:192.168.0.***
net use \\192.168.0.***\home /user:192.168.0.***\user *
```

---

## API 参考

所有 `/api/*` 接口需 `Authorization: Bearer <token>`。

### 鉴权

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/auth/login` | `{password}` → `{token}` |
| GET | `/api/auth/me` | 校验 token |
| POST | `/api/auth/change-password` | 修改密码（旧 token 全部失效） |

### 系统

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/stats` | 系统总览数据 |
| GET | `/api/system/processes` | 进程列表 |

### 路由器

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/router/config` | 读取配置 |
| POST | `/api/router/config` | 保存配置 |
| GET | `/api/router/detect` | 检测接口 |
| POST | `/api/router/apply` | 一键应用 |

### WireGuard

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/wireguard/peers` | 对端列表 |
| POST | `/api/wireguard/peer/add` | 添加对端 |
| POST | `/api/wireguard/peer/remove` | 删除对端 |
| GET | `/api/wireguard/peer/{id}/config` | 获取客户端配置 |

### 防火墙

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/firewall/all` | 所有 nftables 表 |
| GET | `/api/firewall/zones` | 区域配置 |
| POST | `/api/firewall/zones` | 保存区域 |
| POST | `/api/firewall/apply-zones` | 应用区域 |
| POST | `/api/firewall/flush` | 清空表 |

### 包管理

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/packages/router-essentials` | 检查路由必备包 |
| POST | `/api/packages/install-router-essentials` | 安装路由必备包 |
| GET | `/api/packages/vm-essentials` | 检查虚拟机必备包 |
| POST | `/api/packages/install-vm-essentials` | 安装虚拟机必备包 |
| GET | `/api/packages/disk-essentials` | 检查磁盘必备包 |
| POST | `/api/packages/install-disk-essentials` | 安装磁盘必备包 |
| GET | `/api/packages/samba-essentials` | 检查 Samba 必备包 |
| POST | `/api/packages/install-samba-essentials` | 安装 Samba 必备包 |
| GET | `/api/packages/search?q=` | 搜索 |
| GET | `/api/packages/installed` | 已安装列表 |
| POST | `/api/packages/install` | 安装指定包 |
| POST | `/api/packages/remove` | 卸载指定包 |
| POST | `/api/packages/update` | 更新索引 |
| POST | `/api/packages/upgrade` | 升级系统 |
| GET | `/api/packages/task/{id}` | 查询任务进度 |

### 虚拟机

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/vm/status` | KVM 状态 + 设置 |
| POST | `/api/vm/settings` | 保存存储设置 |
| GET | `/api/vm/list` | 列表 |
| GET | `/api/vm/isos` | ISO 镜像库 |
| GET | `/api/vm/browse-qcow2` | 浏览 QCOW2 文件 |
| GET | `/api/vm/detail/{name}` | 详情 |
| POST | `/api/vm/create` | 创建 |
| POST | `/api/vm/action` | 启动 / 关机 / 重启等 |
| POST | `/api/vm/delete` | 删除 |
| POST | `/api/vm/update-resources` | 修改 vCPU / 内存 |
| POST | `/api/vm/update-vnc` | 修改 VNC |
| POST | `/api/vm/attach-disk` | 添加磁盘 |
| POST | `/api/vm/attach-iso` | 挂载 ISO |
| POST | `/api/vm/detach` | 移除设备 |
| POST | `/api/vm/vnc/firewall` | 放行 VNC 端口 |

### 磁盘

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/disk/list` | 块设备列表 |
| POST | `/api/disk/mount` | 挂载 |
| POST | `/api/disk/umount` | 卸载 |
| POST | `/api/disk/format` | 格式化 |

### Samba

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/samba/status` | 服务状态 + 共享列表 |
| POST | `/api/samba/install` | 安装 Samba |
| POST | `/api/samba/restart` | 重启服务 |
| GET | `/api/samba/guest-policy` | 读取 Guest 策略 |
| POST | `/api/samba/guest-policy` | 设置 Guest 策略 |
| GET | `/api/samba/system-users` | 系统用户 / 组列表 |
| GET | `/api/samba/users` | Samba 用户列表 |
| POST | `/api/samba/users/add` | 添加 Samba 用户 |
| POST | `/api/samba/users/passwd` | 修改密码 |
| POST | `/api/samba/users/toggle` | 启用 / 禁用 |
| POST | `/api/samba/users/remove` | 删除用户 |
| POST | `/api/samba/share/add` | 添加 / 更新共享 |
| POST | `/api/samba/share/remove` | 删除共享 |

### 其他

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/tools/ping` | Ping |
| POST | `/api/tools/dns` | DNS 查询 |
| GET | `/api/network/routes` | 路由表 |
| GET | `/api/network/neighbors` | 邻居表 |
| WS | `/ws/traffic?token=` | 实时流量推送 |

---

## 配置文件位置

| 文件 | 说明 |
|---|---|
| `/etc/netrouter/password.json` | 密码哈希（PBKDF2-SHA256，200000 次迭代） |
| `/etc/netrouter/secret.key` | JWT 签名密钥 |
| `/etc/netrouter/token_version` | Token 版本号（改密后递增） |
| `/etc/netrouter/router.yaml` | 路由器配置 |
| `/etc/netrouter/firewall.json` | 防火墙配置 |
| `/etc/netrouter/wg_peers.json` | WireGuard 对端列表 |
| `/etc/netrouter/vm.json` | 虚拟机全局设置 |
| `/etc/netrouter/audit.log` | 审计日志 |

### 系统配置文件

| 文件 | 说明 |
|---|---|
| `/etc/netplan/99-netrouter.yaml` | 网卡 / 桥接配置 |
| `/etc/hostapd/hostapd.conf` | WiFi AP 配置 |
| `/etc/dnsmasq.d/netrouter.conf` | DHCP / DNS 配置 |
| `/etc/nftables.conf` | 防火墙规则 |
| `/etc/wireguard/wg0.conf` | WireGuard 配置 |
| `/etc/fstab` | 磁盘自动挂载（NetRouter 管理块） |
| `/etc/samba/smb.conf` | Samba 配置（NetRouter 管理块） |

### 备份文件

| 文件 | 说明 |
|---|---|
| `/etc/fstab.netrouter.bak` | fstab 首次修改前的备份 |
| `/etc/samba/smb.conf.netrouter.bak` | smb.conf 首次修改前的备份 |

---

## 安全设计

| 类别 | 措施 |
|---|---|
| **鉴权** | JWT（HS256）+ token 版本号，改密后所有会话立即失效 |
| **密码存储** | PBKDF2-HMAC-SHA256，200000 次迭代，随机 16 字节 salt |
| **登录限速** | 5 次 / 分钟 / IP |
| **输入校验** | 所有字段严格正则（接口名 / IP / 端口 / 用户 / 路径 / 包名等） |
| **命令执行** | 一律使用 `subprocess.run(list)`，不用 shell |
| **原子写** | `os.replace`，防配置截断 |
| **审计** | 所有敏感操作写入 `/etc/netrouter/audit.log` |
| **防火墙强制** | 区域模型不可关闭，默认 DROP |
| **系统盘保护** | 磁盘管理中禁止格式化 / 挂载系统盘 |
| **fstab 校验** | 写前 `findmnt --verify`，失败拒绝并回滚 |
| **smb.conf 校验** | 写前 `testparm -s`，失败拒绝 |
| **WireGuard 私钥** | 前端展示脱敏（`***`） |
| **隐藏文档** | 关闭 `/docs` `/openapi.json` `/redoc` |

---

## 故障排查

### 服务无法启动

```bash
# 检查端口占用
sudo ss -tlnp | grep 8080

# 检查 Python 依赖
python3 -c "import fastapi, uvicorn, yaml, psutil"

# 手动运行看错误
sudo python3 /opt/netrouter/route.py
```

### 无法登录

```bash
# 重置密码
sudo rm /etc/netrouter/password.json
sudo python3 route.py
# 启动时输出新密码
```

或指定密码：

```bash
sudo rm /etc/netrouter/password.json
sudo NETROUTER_PASSWORD='NewPass123' python3 route.py
```

### 一键应用报错

查看页面右侧的**步骤列表**，红叉的步骤就是失败点。常见：

| 错误 | 原因 |
|---|---|
| `Netplan 语法错误` | 接口名 / IP 格式不对 |
| `hostapd 启动失败` | WiFi 网卡不支持 AP 模式 / 驱动问题 |
| `dnsmasq 启动失败` | 53 端口被占用（systemd-resolved） |
| `nftables 加载失败` | 规则语法错误 / 内核模块缺失 |

### Samba 访问报"没有权限访问"

```bash
# 1) 检查 Samba 用户
sudo pdbedit -L

# 2) 若 user 不在，添加
sudo smbpasswd -a user

# 3) 检查 Guest 策略
sudo testparm -s | grep "map to guest"

# 4) 检查共享配置
sudo testparm -s | awk '/\[public\]/,/^\[/' | head -20

# 5) Windows 端清凭据（在 Windows CMD）
net use * /delete /y
cmdkey /delete:192.168.0.***

# 6) 用明确用户名连接
net use \\192.168.0.***\home /user:192.168.0.***\user *
```

### 虚拟机创建失败

```bash
# 检查 KVM
ls -la /dev/kvm
kvm-ok

# 检查 libvirtd
sudo systemctl status libvirtd

# 检查存储目录
ls -ld /var/lib/libvirt/images
df -h /var/lib/libvirt/images
```

### 磁盘格式化失败

```bash
# 检查工具是否安装
which mkfs.ext4 mkfs.vfat mkfs.exfat mkfs.ntfs mkfs.xfs

# 未装的话去「包管理 → 磁盘管理必备」一键安装

# 检查设备是否被挂载
findmnt /dev/sdb1
```

### 忘记密码 / 想重置

```bash
sudo rm /etc/netrouter/password.json /etc/netrouter/token_version
sudo python3 route.py
```

---

## 常见问题

### Q: 修改了路由配置后失联怎么办？

- **等 30 秒**：netplan 应用后可能需要重新获取 IP
- **物理接触**：将显示器 / 键盘接到服务器上
- **恢复网络**：删除 `/etc/netplan/99-netrouter.yaml`，执行 `sudo netplan apply`
- **SSH 应急**：路由器会自动放行 22/tcp；若 SSH 也断了，用物理终端

### Q: Windows 网络邻居看不到共享？

```cmd
:: 1) 启动服务
net start ComputerBrowser

:: 2) 或者直接用 IP 访问
\\192.168.0.***\public

:: 3) 或映射网络驱动器
net use Z: \\192.168.0.***\public /user:192.168.0.***\user *
```

### Q: 修改 fstab 后无法开机？

- 若能进 GRUB：按 `e` 编辑启动参数，在内核行末尾加 `single` 或 `init=/bin/bash`，进单用户模式删除 NetRouter 管理块
- 若不能：用 U 盘启动 → 挂载根分区 → 编辑 `/etc/fstab`
- 恢复备份：`cp /etc/fstab.netrouter.bak /etc/fstab`

### Q: 单个服务启动失败会影响其他服务吗？

不会。每个步骤独立执行，失败只影响当前步骤。已成功的步骤仍然生效。

### Q: VNC 端口外网访问不了？

- 虚拟机创建时**不会自动放行 VNC 端口**到 WAN
- 需要手动：虚拟机详情 → 「放行 wan → VNC」
- 或到「防火墙 → 端口开放 / 关闭」手动加规则

### Q: 如何更新 NetRouter？

```bash
# 停止服务
sudo systemctl stop netrouter

# 备份配置
sudo tar czf netrouter-backup-$(date +%Y%m%d).tar.gz /etc/netrouter

# 替换 route.py
sudo cp route.py.new /opt/netrouter/route.py

# 启动
sudo systemctl start netrouter
```

### Q: 如何修改监听端口？

```bash
sudo NETROUTER_PORT=9090 python3 route.py
```

或在 systemd unit 里加：

```ini
Environment=NETROUTER_PORT=9090
```

---

## 卸载

```bash
# 1. 停止服务
sudo systemctl stop netrouter
sudo systemctl disable netrouter
sudo rm /etc/systemd/system/netrouter.service
sudo systemctl daemon-reload

# 2. 删除 NetRouter 配置
sudo rm -rf /etc/netrouter

# 3. 恢复系统配置（可选，谨慎）
sudo rm /etc/netplan/99-netrouter.yaml
sudo rm /etc/hostapd/hostapd.conf
sudo rm /etc/dnsmasq.d/netrouter.conf
sudo rm /etc/nftables.conf
sudo rm /etc/systemd/system/set-regdomain.service
sudo rm /etc/systemd/system/netrouter-pppoe.service
sudo rm /etc/sysctl.d/99-netrouter.conf

# 4. 清理 fstab 和 smb.conf（保留原有系统条目）
#    用编辑器打开 /etc/fstab，删除 NetRouter 管理块
#    用编辑器打开 /etc/samba/smb.conf，删除 NetRouter 管理块

# 5. 恢复网络
sudo netplan apply

# 6. 删除程序
sudo rm -rf /opt/netrouter
```

---

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request。

## 免责声明

本软件涉及网络、防火墙、磁盘等底层操作，使用不当可能导致**网络中断 / 数据丢失**。请务必：

- 在**测试环境**先行验证
- **备份**重要配置和数据
- 生产环境使用前**充分评估**

代码全部由DeepSeek V4 AI独立完成，作者不对使用本软件造成的任何损失负责。
