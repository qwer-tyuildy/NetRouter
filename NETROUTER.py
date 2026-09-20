#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetRouter — 基于 Ubuntu 的一体化路由器软件（安全加固版）
============================================================
· 概览      — 实时流量 / 系统监控 / 进程 / 测速 / 网络诊断工具
· 路由器    — WAN/LAN/WiFi/WireGuard（客户端/服务器）一键配置
· 防火墙    — 区域设置 / 区域转发 / 端口转发 / 端口开放关闭（强制启用）
· 包管理    — apt-get install / update / upgrade / remove, apt-cache search
· 虚拟机    — QEMU/KVM + libvirt 一键环境，虚拟机管理与 VNC
· 磁盘管理  — 块设备挂载 / 格式化 / fstab 自动挂载
· 文件共享  — Samba SMB / CIFS 共享管理
依赖：pip install fastapi uvicorn pyyaml psutil
运行：sudo python3 route.py
"""
import os, re, sys, json, time, hmac, socket, base64, hashlib, secrets
import asyncio, platform, subprocess, tempfile, shutil, threading
import ipaddress, logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from datetime import timedelta
try:
    import yaml
    import psutil
    import uvicorn
    from fastapi import (
        FastAPI, HTTPException, Depends, WebSocket,
        WebSocketDisconnect, Query, Request
    )
    from fastapi.responses import (
        HTMLResponse, JSONResponse, Response, StreamingResponse
    )
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from starlette.types import ASGIApp, Scope, Receive, Send
except ImportError as e:
    print(f"[NetRouter] 缺少依赖: {e.name}")
    print("请先执行: pip install fastapi uvicorn pyyaml psutil")
    sys.exit(1)

# ============================================================
# 日志
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("netrouter")

# ============================================================
# 全局配置
# ============================================================
CONF_DIR = Path(os.environ.get("NETROUTER_DIR", "/etc/netrouter"))
CONF_DIR.mkdir(parents=True, exist_ok=True)
try:
    os.chmod(CONF_DIR, 0o700)
except OSError:
    pass

PW_FILE = CONF_DIR / "password.json"
SECRET_FILE = CONF_DIR / "secret.key"
TOKEN_VERSION_FILE = CONF_DIR / "token_version"
ROUTER_CONF = CONF_DIR / "router.yaml"
FIREWALL_CONF = CONF_DIR / "firewall.json"
WG_PEERS_FILE = CONF_DIR / "wg_peers.json"
VM_CONF = CONF_DIR / "vm.json"
AUDIT_LOG = CONF_DIR / "audit.log"

TOKEN_TTL = 86400 * 7
NETPLAN_FILE = Path("/etc/netplan/99-netrouter.yaml")
DNSMASQ_FILE = Path("/etc/dnsmasq.d/netrouter.conf")
HOSTAPD_CONF = Path("/etc/hostapd/hostapd.conf")
WG_DIR = Path("/etc/wireguard")
NFT_ROUTER_TABLE = "router"
PORT = int(os.environ.get("NETROUTER_PORT", "8080"))
HOST = os.environ.get("NETROUTER_HOST", "0.0.0.0")

_cfg_lock = threading.RLock()
_secret_lock = threading.Lock()
_vm_lock = threading.RLock()

# ============================================================
# 路由功能必备软件包
# ============================================================
ROUTER_ESSENTIAL_PKGS = [
    "hostapd", "dnsmasq", "nftables", "wireguard-tools",
    "bridge-utils", "iw", "rfkill",
]
ROUTER_PPPOE_PKGS = ["ppp", "pppoe"]
ROUTER_ALL_PKGS = ROUTER_ESSENTIAL_PKGS + ROUTER_PPPOE_PKGS
ROUTER_PKG_DESC = {
    "hostapd":         "WiFi AP 热点服务",
    "dnsmasq":         "DHCP / DNS 服务",
    "nftables":        "防火墙（NAT / 转发）",
    "wireguard-tools": "WireGuard VPN 工具",
    "bridge-utils":    "网桥管理",
    "iw":              "无线网卡配置",
    "rfkill":          "无线开关控制",
    "ppp":             "PPPoE 拨号支持",
    "pppoe":           "PPPoE 客户端",
}

# ============================================================
# 虚拟机必备软件包
# ============================================================
VM_PKGS = [
    "qemu-system-x86", "qemu-utils",
    "libvirt-daemon-system", "libvirt-clients", "libvirt-daemon",
    "virtinst", "bridge-utils", "ovmf", "cpu-checker",
]
VM_PKG_DESC = {
    "qemu-system-x86":       "QEMU x86 系统模拟器（KVM 加速）",
    "qemu-utils":            "QEMU 磁盘镜像工具（qemu-img）",
    "libvirt-daemon-system": "libvirt 守护进程与系统集成",
    "libvirt-clients":       "virsh / virt-install 等客户端",
    "libvirt-daemon":        "libvirt 核心守护进程",
    "virtinst":              "virt-install 虚拟机安装工具",
    "bridge-utils":          "网桥管理工具（brctl）",
    "ovmf":                  "UEFI 固件（支持 UEFI 启动）",
    "cpu-checker":           "KVM 支持检测（kvm-ok）",
}
VM_DEFAULT_STORAGE = "/var/lib/libvirt/images"
VM_DEFAULT_ISO_DIRS = [
    "/var/lib/libvirt/images", "/var/lib/libvirt/boot",
    "/iso", "/srv/iso",
]
VM_QCOSCAN_DIRS = [
    "/var/lib/libvirt/images", "/vm", "/mnt", "/media",
    "/srv", "/opt", "/data", "/home", "/root", "/tmp",
]
VNC_PORT_MIN = 5901
VNC_PORT_MAX = 5999
DEFAULT_VM_CFG = {
    "storage_dir": VM_DEFAULT_STORAGE,
    "iso_dirs": list(VM_DEFAULT_ISO_DIRS),
}

# ============================================================
# 磁盘管理必备软件包
# ============================================================
DISK_PKGS = [
    "util-linux", "dosfstools", "exfatprogs", "ntfs-3g",
    "xfsprogs", "btrfs-progs", "f2fs-tools", "e2fsprogs",
]
DISK_PKG_DESC = {
    "util-linux":   "lsblk / findmnt / blkid（块设备探测）",
    "dosfstools":   "FAT32 / VFAT 格式化与检查",
    "exfatprogs":   "exFAT 格式化与检查",
    "ntfs-3g":      "NTFS 读写支持与 mkfs.ntfs",
    "xfsprogs":     "XFS 格式化与检查",
    "btrfs-progs":  "Btrfs 格式化与检查",
    "f2fs-tools":   "F2FS 格式化与检查",
    "e2fsprogs":    "ext2/3/4 格式化与检查",
}

# ============================================================
# 文件共享必备软件包
# ============================================================
SAMBA_PKGS = ["samba", "samba-common-bin", "smbclient"]
SAMBA_PKG_DESC = {
    "samba":            "SMB / CIFS 服务端与客户端",
    "samba-common-bin": "smbpasswd / smbd / nmbd 等工具",
    "smbclient":        "SMB 客户端测试工具",
}

# ============================================================
# 防火墙默认配置
# ============================================================
DEFAULT_FIREWALL_CFG = {
    "enabled": True,
    "zones": [], "forwardings": [],
    "port_forwards": [], "input_rules": [],
}
FW_ACTIONS = ("ACCEPT", "REJECT", "DROP")

# ============================================================
# 输入校验正则
# ============================================================
_RE_IFNAME     = re.compile(r"^[A-Za-z0-9_.@-]{1,32}$")
_RE_ZONE_NAME  = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_RE_PORT       = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")
_RE_IPV4       = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_RE_IPV6       = re.compile(r"^[0-9a-fA-F:]+$")
_RE_CIDR       = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
_RE_NETMASK    = re.compile(r"^(3[0-2]|[12]?\d)$")
_RE_LEASE      = re.compile(r"^\d{1,6}[smhd]?$")
_RE_WG_ADDR    = re.compile(r"^[0-9a-fA-F:.]+/\d{1,3}$")
_RE_WG_PORT    = re.compile(r"^\d{1,5}$")
_RE_WG_KEY     = re.compile(r"^[A-Za-z0-9+/=]{40,64}$")
_RE_WG_ENDP    = re.compile(r"^[A-Za-z0-9._:\-\[\]]{1,255}$")
_RE_WG_AIPS    = re.compile(r"^[0-9a-fA-F:.,/\s]{1,512}$")
_RE_WG_IF      = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_RE_SSID       = re.compile(r"^[^\n\r]{1,32}$")
_RE_WPA_PSK    = re.compile(r"^[^\n\r]{8,63}$")
_RE_COUNTRY    = re.compile(r"^[A-Za-z]{2}$")
_RE_PPP_USER   = re.compile(r"^[A-Za-z0-9_@.\-]{1,64}$")
_RE_PPP_PWD    = re.compile(r"^[^\s\"'\\\n\r]{1,128}$")
_RE_CHANNEL    = re.compile(r"^\d{1,3}$")
_RE_HOSTNAME   = re.compile(r"^[a-zA-Z0-9._-]{1,253}$")
_RE_PKG_NAME   = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9+._:-]{0,199}$")
_RE_VM_NAME    = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")
_RE_VM_OSVAR   = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")
_RE_VM_VNCPWD  = re.compile(r"^[A-Za-z0-9_.\-]{4,8}$")
_RE_DEV_PATH   = re.compile(r"^/dev/[A-Za-z0-9/._-]{1,128}$")
_RE_FS_TYPE    = re.compile(r"^(ext4|xfs|btrfs|vfat|exfat|ntfs|f2fs)$")
_RE_LABEL      = re.compile(r"^[A-Za-z0-9_\-.]{1,16}$")
_RE_SHARE_NAME = re.compile(r"^[A-Za-z0-9_\-.]{1,32}$")
_RE_LINUX_GROUP = re.compile(r"^[a-z_][a-z0-9_\-]{0,31}$")

# ============================================================
# 审计日志
# ============================================================
def audit(action: str, detail: str = ""):
    try:
        line = (f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
                f"[{action}] {detail}\n")
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(line)
        try:
            os.chmod(AUDIT_LOG, 0o600)
        except OSError:
            pass
    except OSError:
        pass

# ============================================================
# 基础工具
# ============================================================
def read_file(path, default=None):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read().strip()
    except (OSError, IOError):
        return default

def read_int(path, default=0):
    v = read_file(path)
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

def run_cmd(cmd, timeout=8, check=False, input_data=None):
    try:
        p = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=True, text=True, timeout=timeout,
            input=input_data,
        )
        return p.returncode == 0, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return False, "", "超时"
    except FileNotFoundError:
        return False, "", f"未找到: {cmd[0] if isinstance(cmd, list) else cmd}"
    except OSError as e:
        return False, "", str(e)

def human_seconds(sec):
    try:
        return str(timedelta(seconds=int(sec)))
    except Exception:
        return "?"

def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def _valid_ip(s: str) -> bool:
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, s)
            return True
        except OSError:
            pass
    return False

def _atomic_write(path: Path, data: str, mode: int = 0o600):
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    try:
        tmp.write_text(data, encoding="utf-8")
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise

# ============================================================
# 鉴权
# ============================================================
def _load_secret() -> bytes:
    with _secret_lock:
        if SECRET_FILE.exists():
            try:
                b = SECRET_FILE.read_bytes()
                if len(b) >= 32:
                    return b
            except OSError:
                pass
        s = secrets.token_bytes(32)
        tmp = SECRET_FILE.with_name(SECRET_FILE.name + f".tmp.{os.getpid()}")
        try:
            tmp.write_bytes(s)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, SECRET_FILE)
        except OSError:
            pass
        return s

SECRET = _load_secret()

def _pbkdf2(pwd: str, salt: bytes, iters: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, iters)

def hash_password(pwd: str) -> dict:
    salt = secrets.token_bytes(16)
    iters = 200_000
    return {
        "salt": base64.b64encode(salt).decode(),
        "hash": base64.b64encode(_pbkdf2(pwd, salt, iters)).decode(),
        "iterations": iters,
    }

def verify_password(pwd: str, rec: dict) -> bool:
    try:
        salt = base64.b64decode(rec["salt"])
        expected = base64.b64decode(rec["hash"])
        got = _pbkdf2(pwd, salt, rec["iterations"])
    except Exception:
        return False
    return hmac.compare_digest(got, expected)

def init_default_password() -> Optional[str]:
    if PW_FILE.exists():
        return None
    pwd = os.environ.get("NETROUTER_PASSWORD") or secrets.token_urlsafe(12)
    _atomic_write(PW_FILE, json.dumps(hash_password(pwd)), 0o600)
    return pwd

def load_password_record() -> Optional[dict]:
    if not PW_FILE.exists():
        return None
    try:
        return json.loads(PW_FILE.read_text())
    except Exception:
        return None

def _token_version() -> int:
    try:
        return int(read_file(TOKEN_VERSION_FILE, "1") or "1")
    except (TypeError, ValueError):
        return 1

def _bump_token_version():
    _atomic_write(TOKEN_VERSION_FILE, str(_token_version() + 1), 0o600)

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def create_token(sub: str = "admin") -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": sub, "iat": now, "exp": now + TOKEN_TTL,
               "ver": _token_version()}
    h = _b64e(json.dumps(header, separators=(",", ":")).encode())
    p = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64e(sig)}"

def decode_token(token: str) -> Optional[dict]:
    if not token or token.count(".") != 2:
        return None
    h, p, s = token.split(".")
    expected = hmac.new(SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64d(s), expected):
        return None
    try:
        payload = json.loads(_b64d(p))
    except Exception:
        return None
    if payload.get("exp", 0) < time.time():
        return None
    if payload.get("ver") != _token_version():
        return None
    return payload

# ============================================================
# 系统信息采集
# ============================================================
_prev_cpu = {"total": 0, "idle": 0}
_cpu_lock = threading.Lock()

def get_cpu_usage():
    line = (read_file("/proc/stat", "") or "").splitlines()
    if not line:
        return 0.0
    parts = line[0].split()
    values = [int(x) for x in parts[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    total = sum(values)
    with _cpu_lock:
        global _prev_cpu
        if _prev_cpu["total"] == 0:
            time.sleep(0.1)
            line = (read_file("/proc/stat", "") or "").splitlines()
            parts = line[0].split()
            values = [int(x) for x in parts[1:]]
            idle = values[3] + (values[4] if len(values) > 4 else 0)
            total = sum(values)
        dt = total - _prev_cpu["total"]
        di = idle - _prev_cpu["idle"]
        _prev_cpu = {"total": total, "idle": idle}
    if dt <= 0:
        return 0.0
    return max(0.0, min(100.0, (dt - di) / dt * 100.0))

def get_memory():
    info = {}
    for line in (read_file("/proc/meminfo", "") or "").splitlines():
        parts = line.split(":")
        if len(parts) == 2:
            key = parts[0].strip()
            val = parts[1].strip().split()[0]
            try:
                info[key] = int(val) * 1024
            except ValueError:
                pass
    total = info.get("MemTotal", 0)
    free = info.get("MemFree", 0)
    buffers = info.get("Buffers", 0)
    cached = info.get("Cached", 0) + info.get("SReclaimable", 0)
    available = info.get("MemAvailable", free + buffers + cached)
    used = total - available if total else 0
    mem = {
        "total": total, "used": used, "free": free,
        "buffers": buffers, "cached": cached, "available": available,
        "percent": (used / total * 100) if total else 0.0,
    }
    st = info.get("SwapTotal", 0)
    sf = info.get("SwapFree", 0)
    swap = {
        "total": st, "used": st - sf, "free": sf,
        "percent": ((st - sf) / st * 100) if st else 0.0,
    }
    return mem, swap

def get_disks():
    disks = []
    seen = set()
    for line in (read_file("/proc/mounts", "") or "").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, mount, fstype = parts[0], parts[1], parts[2]
        if not dev.startswith("/dev/"):
            continue
        if fstype in ("proc", "sysfs", "tmpfs", "devtmpfs", "cgroup", "cgroup2"):
            continue
        if dev in seen:
            continue
        seen.add(dev)
        try:
            st = os.statvfs(mount)
            total = st.f_blocks * st.f_frsize
            free = st.f_bavail * st.f_frsize
            used = total - free
            disks.append({
                "device": dev, "mount": mount, "fstype": fstype,
                "total": total, "used": used, "free": free,
                "percent": (used / total * 100) if total else 0.0,
            })
        except OSError:
            continue
    return disks

def get_system_info():
    info = {}
    info["hostname"] = socket.gethostname()
    info["kernel"] = read_file("/proc/sys/kernel/osrelease", "unknown")
    distro = "unknown"
    if os.path.exists("/etc/os-release"):
        for line in (read_file("/etc/os-release", "") or "").splitlines():
            if line.startswith("PRETTY_NAME="):
                distro = line.split("=", 1)[1].strip('"')
                break
    info["distro"] = distro
    ok, out, _ = run_cmd(["uname", "-m"])
    info["arch"] = out.strip() if ok else "unknown"
    uptime = read_file("/proc/uptime", "0 0").split()[0]
    info["uptime_sec"] = float(uptime)
    info["uptime"] = human_seconds(float(uptime))
    try:
        boot_time = time.time() - float(uptime)
        info["boot_time"] = time.strftime("%Y-%m-%d %H:%M:%S",
                                          time.localtime(boot_time))
    except Exception:
        info["boot_time"] = "?"
    cpu_model = "unknown"
    cpuinfo = read_file("/proc/cpuinfo", "") or ""
    m = re.search(r"^(?:model name|Model|Hardware)\s*:\s*(.+)$", cpuinfo, re.M)
    if m:
        cpu_model = m.group(1).strip()
    info["cpu_model"] = cpu_model
    info["cpu_cores"] = os.cpu_count() or 1
    load = (read_file("/proc/loadavg", "") or "").split()
    if len(load) >= 3:
        info["load"] = [float(load[0]), float(load[1]), float(load[2])]
    else:
        info["load"] = [0.0, 0.0, 0.0]
    return info

def _read_sensors():
    out = []
    thermal = Path("/sys/class/thermal")
    if thermal.exists():
        for zone in sorted(thermal.glob("thermal_zone*")):
            try:
                t = int((zone / "temp").read_text().strip()) / 1000.0
                name = (zone / "type").read_text().strip()
                if -50 < t < 200:
                    out.append({"name": name, "temp": round(t, 1)})
            except OSError:
                continue
    hwmon = Path("/sys/class/hwmon")
    if hwmon.exists():
        for chip in sorted(hwmon.glob("hwmon*")):
            try:
                chip_name = (chip / "name").read_text().strip()
            except OSError:
                continue
            for tfile in sorted(chip.glob("temp*_input")):
                try:
                    t = int(tfile.read_text().strip()) / 1000.0
                    label_file = tfile.parent / (tfile.stem + "_label")
                    label = (label_file.read_text().strip()
                             if label_file.exists() else tfile.stem)
                    if -50 < t < 200:
                        out.append({"name": f"{chip_name}/{label}",
                                    "temp": round(t, 1)})
                except OSError:
                    continue
    return out

def process_list(limit: int = 20, sort: str = "cpu") -> list:
    procs = []
    for p in psutil.process_iter([
        "pid", "name", "username", "cpu_percent",
        "memory_percent", "memory_info", "status", "cmdline",
    ]):
        try:
            i = p.info
            procs.append({
                "pid": i["pid"],
                "name": i["name"] or "",
                "user": i["username"] or "",
                "cpu": round(i["cpu_percent"] or 0.0, 1),
                "mem": round(i["memory_percent"] or 0.0, 1),
                "rss": i["memory_info"].rss if i["memory_info"] else 0,
                "status": i["status"] or "",
                "cmdline": " ".join(i["cmdline"] or [])[:140],
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    key = "cpu" if sort == "cpu" else "mem"
    procs.sort(key=lambda x: x[key], reverse=True)
    return procs[:min(limit, 200)]

# ============================================================
# 网络接口 / WiFi / WireGuard / DHCP
# ============================================================
def list_net_interfaces():
    out = []
    net_dir = "/sys/class/net"
    if not os.path.isdir(net_dir):
        return out
    for name in sorted(os.listdir(net_dir)):
        if name == "lo":
            continue
        out.append(name)
    return out

def get_interface_info(name):
    base = f"/sys/class/net/{name}"
    if not os.path.isdir(base):
        return None
    info = {"name": name}
    info["mac"] = read_file(f"{base}/address", "?")
    info["operstate"] = read_file(f"{base}/operstate", "?")
    info["carrier"] = read_int(f"{base}/carrier", 0) == 1
    info["wireless"] = (os.path.isdir(f"{base}/wireless")
                        or os.path.isdir(f"{base}/phy80211"))
    info["mtu"] = read_int(f"{base}/mtu", 0)
    speed = read_file(f"{base}/speed", "")
    try:
        info["speed_mbps"] = int(speed)
    except (ValueError, TypeError):
        info["speed_mbps"] = None
    info["rx_bytes"] = read_int(f"{base}/statistics/rx_bytes", 0)
    info["tx_bytes"] = read_int(f"{base}/statistics/tx_bytes", 0)
    info["rx_packets"] = read_int(f"{base}/statistics/rx_packets", 0)
    info["tx_packets"] = read_int(f"{base}/statistics/tx_packets", 0)
    info["rx_errors"] = read_int(f"{base}/statistics/rx_errors", 0)
    info["tx_errors"] = read_int(f"{base}/statistics/tx_errors", 0)
    addrs = []
    ok, out, _ = run_cmd(["ip", "-j", "addr", "show", "dev", name], timeout=3)
    if ok and out:
        try:
            for itf in json.loads(out):
                for a in itf.get("addr_info", []):
                    addrs.append({
                        "family": a.get("family"),
                        "address": a.get("local"),
                        "prefixlen": a.get("prefixlen"),
                    })
        except json.JSONDecodeError:
            pass
    info["addresses"] = addrs
    info["master"] = None
    master_link = f"{base}/master"
    if os.path.islink(master_link):
        try:
            info["master"] = os.path.basename(os.readlink(master_link))
        except OSError:
            pass
    return info

def get_bridge_info():
    bridges = {}
    net_dir = "/sys/class/net"
    if not os.path.isdir(net_dir):
        return bridges
    for name in os.listdir(net_dir):
        brif = f"{net_dir}/{name}/brif"
        if os.path.isdir(brif):
            try:
                bridges[name] = sorted(os.listdir(brif))
            except OSError:
                bridges[name] = []
    return bridges

def get_wireguard():
    ok, out, _ = run_cmd(["wg", "show", "all", "dump"], timeout=3)
    if not ok or not out:
        return []
    interfaces = {}
    for line in out.strip().splitlines():
        parts = line.split("\t")
        if len(parts) == 5:
            iface = parts[0]
            interfaces[iface] = {
                "name": iface, "public_key": parts[2],
                "listen_port": parts[3], "peers": [],
            }
        elif len(parts) >= 8:
            iface = parts[0]
            if iface not in interfaces:
                continue
            try:
                handshake = int(parts[5])
            except ValueError:
                handshake = 0
            now = int(time.time())
            hs_ago = ("从未" if handshake == 0
                      else f"{human_seconds(now - handshake)}前")
            interfaces[iface]["peers"].append({
                "public_key": parts[1],
                "endpoint": parts[3] or "(无)",
                "allowed_ips": parts[4].replace(",", ", "),
                "latest_handshake": handshake,
                "handshake_ago": hs_ago,
                "rx_bytes": int(parts[6]) if parts[6].isdigit() else 0,
                "tx_bytes": int(parts[7]) if parts[7].isdigit() else 0,
            })
    return list(interfaces.values())

def _detect_wifi_iface():
    for n in list_net_interfaces():
        if (os.path.isdir(f"/sys/class/net/{n}/wireless")
                or os.path.isdir(f"/sys/class/net/{n}/phy80211")):
            return n
    return None

def get_wifi_ap_info(iface=None):
    if not iface:
        iface = _detect_wifi_iface()
    if not iface:
        return None
    ok, out, _ = run_cmd(["iw", "dev", iface, "info"], timeout=3)
    if not ok or not out:
        return None
    info = {"iface": iface}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("ssid "):
            info["ssid"] = line.split(None, 1)[1]
        elif line.startswith("type "):
            info["type"] = line.split(None, 1)[1]
        elif line.startswith("channel "):
            m = re.match(r"channel (\d+) \((\d+) MHz\), width: (\d+) MHz", line)
            if m:
                info["channel"] = int(m.group(1))
                info["freq_mhz"] = int(m.group(2))
                info["width_mhz"] = int(m.group(3))
        elif line.startswith("txpower "):
            info["txpower"] = line.split(None, 1)[1]
    return info

def get_wifi_ap_clients(iface=None):
    clients = []
    if (os.path.exists("/usr/sbin/hostapd_cli")
            or os.path.exists("/usr/bin/hostapd_cli")):
        ok, out, _ = run_cmd(["hostapd_cli", "all_sta"], timeout=3)
        if ok and out:
            cur = None
            for line in out.splitlines():
                if re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", line.strip()):
                    if cur:
                        clients.append(cur)
                    cur = {"mac": line.strip()}
                elif cur and "=" in line:
                    k, v = line.split("=", 1)
                    cur[k.strip()] = v.strip()
            if cur:
                clients.append(cur)
    if clients:
        return clients
    if not iface:
        iface = _detect_wifi_iface()
    if not iface:
        return clients
    ok, out, _ = run_cmd(["iw", "dev", iface, "station", "dump"], timeout=3)
    if not ok or not out:
        return clients
    cur = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Station "):
            if cur:
                clients.append(cur)
            cur = {"mac": line.split()[1]}
        elif cur and ":" in line:
            k, v = line.split(":", 1)
            cur[k.strip()] = v.strip()
    if cur:
        clients.append(cur)
    return clients

def get_dhcp_leases():
    paths = [
        "/var/lib/misc/dnsmasq.leases",
        "/var/lib/dnsmasq/dnsmasq.leases",
        "/tmp/dnsmasq.leases",
    ]
    leases = []
    for p in paths:
        if os.path.isfile(p):
            for line in (read_file(p, "") or "").splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    ts, mac, ip, host, cid = parts[:5]
                    try:
                        expire = int(ts)
                        now = int(time.time())
                        left = max(0, expire - now)
                        if left > 86400 * 30:
                            left = 0
                    except ValueError:
                        left = 0
                    leases.append({
                        "mac": mac, "ip": ip,
                        "hostname": host if host != "*" else "",
                        "client_id": cid if cid != "*" else "",
                        "left": human_seconds(left) if left else "—",
                    })
            break
    return leases

# ============================================================
# 路由器配置
# ============================================================
DEFAULT_ROUTER_CFG = {
    "wan_if": "", "wan_mode": "dhcp",
    "wan_ip": "", "wan_gateway": "",
    "wan_dns": "8.8.8.8, 8.8.4.4",
    "wan_pppoe_user": "", "wan_pppoe_pass": "", "wan_pppoe_iface": "ppp0",
    "lan_ifs": "", "br_name": "br-lan",
    "lan_ip": "192.168.10.1", "lan_netmask": "24",
    "lan_dhcp_enabled": True,
    "dhcp_start": "192.168.10.100", "dhcp_end": "192.168.10.200",
    "dhcp_lease": "12h", "dns_servers": "8.8.8.8 8.8.4.4",
    "wifi_ssid": "UbuntuAP", "wifi_passphrase": "ChangeMe12345",
    "wifi_country": "CN", "wifi_band": "5", "wifi_channel": "149",
    "wifi_channel_width": "80", "wifi_pmf": "1",
    "wg_enabled": False, "wg_mode": "client",
    "wg_interface": "wg0", "wg_keepalive": "25",
    "wg_address": "10.0.0.2/32", "wg_endpoint": "",
    "wg_allowed_ips": "192.168.0.0/24, 10.0.0.0/24",
    "wg_server_pubkey": "", "wg_private_key": "",
    "wg_preshared_key": "", "wg_server_address": "10.0.0.1/24",
    "wg_server_port": "51820", "wg_server_endpoint": "",
    "wg_server_private_key": "", "wg_client_dns": "8.8.8.8",
    "wg_client_allowed_ips": "0.0.0.0/0, ::/0",
    "applied": False, "applied_at": "",
}

def load_router_cfg() -> dict:
    with _cfg_lock:
        if ROUTER_CONF.exists():
            try:
                data = json.loads(ROUTER_CONF.read_text())
                merged = dict(DEFAULT_ROUTER_CFG)
                merged.update(data)
                return merged
            except Exception:
                pass
        return dict(DEFAULT_ROUTER_CFG)

def save_router_cfg(cfg: dict):
    with _cfg_lock:
        data = dict(DEFAULT_ROUTER_CFG)
        data.update(cfg or {})
        _atomic_write(ROUTER_CONF,
                      json.dumps(data, indent=2, ensure_ascii=False),
                      0o600)

def detect_router_interfaces() -> dict:
    ifaces = []
    bridges = get_bridge_info()
    bridged = set()
    for members in bridges.values():
        bridged.update(members)
    for name in list_net_interfaces():
        if name.startswith(("docker", "veth", "virbr", "tun", "tap",
                            "wg", "ppp", "br-")):
            continue
        base = f"/sys/class/net/{name}"
        is_wifi = (os.path.isdir(f"{base}/wireless")
                   or os.path.isdir(f"{base}/phy80211"))
        state = read_file(f"{base}/operstate", "?")
        carrier = read_int(f"{base}/carrier", 0) == 1
        ifaces.append({
            "name": name, "wireless": is_wifi,
            "state": state, "carrier": carrier,
            "bridged": name in bridged,
            "mac": read_file(f"{base}/address", ""),
        })
    return {"interfaces": ifaces, "bridges": list(bridges.keys())}

def _find_wifi_in_lan(cfg: dict) -> Optional[str]:
    lan_ifs = [x.strip() for x in (cfg.get("lan_ifs") or "")
               .replace(",", " ").split() if x.strip()]
    for name in lan_ifs:
        base = f"/sys/class/net/{name}"
        if (os.path.isdir(f"{base}/wireless")
                or os.path.isdir(f"{base}/phy80211")):
            return name
    return None

def _apt_install(packages: List[str]) -> dict:
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    for p in packages:
        if not _RE_PKG_NAME.match(p):
            return {"ok": False, "message": f"非法包名: {p}"}
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    subprocess.run(["apt", "update", "-qq"], env=env,
                   capture_output=True, timeout=300)
    p = subprocess.run(
        ["apt", "install", "-y", "-qq"] + packages,
        env=env, capture_output=True, text=True, timeout=900,
    )
    return {"ok": p.returncode == 0,
            "message": (p.stdout + p.stderr)[-2000:] or "安装完成"}

def validate_router_cfg(cfg: dict) -> List[str]:
    errors: List[str] = []
    wan_if = (cfg.get("wan_if") or "").strip()
    if not wan_if:
        errors.append("未选择 WAN 接口")
    elif not _RE_IFNAME.match(wan_if):
        errors.append(f"WAN 接口名非法: {wan_if}")
    wan_mode = cfg.get("wan_mode", "dhcp")
    if wan_mode not in ("dhcp", "static", "pppoe"):
        errors.append(f"WAN 模式非法: {wan_mode}")
    if wan_mode == "static":
        if not _RE_CIDR.match((cfg.get("wan_ip") or "").strip()):
            errors.append("WAN 静态 IP 格式非法（需 CIDR）")
        if not _valid_ip((cfg.get("wan_gateway") or "").strip()):
            errors.append("WAN 网关格式非法")
        for d in (cfg.get("wan_dns") or "").replace(",", " ").split():
            if d and not _valid_ip(d):
                errors.append(f"WAN DNS 非法: {d}")
    elif wan_mode == "pppoe":
        if not _RE_PPP_USER.match((cfg.get("wan_pppoe_user") or "").strip()):
            errors.append("PPPoE 用户名非法")
        if not _RE_PPP_PWD.match(cfg.get("wan_pppoe_pass") or ""):
            errors.append("PPPoE 密码非法（禁空白/引号）")
        iface = (cfg.get("wan_pppoe_iface") or "ppp0").strip()
        if not _RE_IFNAME.match(iface):
            errors.append("PPPoE 接口名非法")
    br = (cfg.get("br_name") or "br-lan").strip()
    if not _RE_IFNAME.match(br):
        errors.append(f"桥接名称非法: {br}")
    lan_ifs = (cfg.get("lan_ifs") or "").replace(",", " ").split()
    if not lan_ifs:
        errors.append("未选择 LAN 接口")
    for i in lan_ifs:
        if not _RE_IFNAME.match(i):
            errors.append(f"LAN 接口名非法: {i}")
    if wan_if and wan_if in lan_ifs:
        errors.append("WAN 接口不能同时作为 LAN")
    if not _RE_IPV4.match((cfg.get("lan_ip") or "").strip()):
        errors.append("LAN IP 格式非法")
    if not _RE_NETMASK.match((cfg.get("lan_netmask") or "").strip()):
        errors.append("LAN 掩码非法（0-32）")
    if cfg.get("lan_dhcp_enabled", True):
        if not _RE_IPV4.match((cfg.get("dhcp_start") or "").strip()):
            errors.append("DHCP 起始地址非法")
        if not _RE_IPV4.match((cfg.get("dhcp_end") or "").strip()):
            errors.append("DHCP 结束地址非法")
        if not _RE_LEASE.match((cfg.get("dhcp_lease") or "").strip()):
            errors.append("DHCP 租期非法（如 12h/1d）")
    for d in (cfg.get("dns_servers") or "").replace(",", " ").split():
        if d and not _valid_ip(d):
            errors.append(f"DHCP DNS 非法: {d}")
    if not _RE_SSID.match(cfg.get("wifi_ssid") or ""):
        errors.append("WiFi SSID 非法（1-32 字符，禁换行）")
    if not _RE_WPA_PSK.match(cfg.get("wifi_passphrase") or ""):
        errors.append("WiFi 密码非法（8-63 字符，禁换行）")
    if not _RE_COUNTRY.match(cfg.get("wifi_country") or ""):
        errors.append("WiFi 国家代码非法（2 字母）")
    if not _RE_CHANNEL.match(str(cfg.get("wifi_channel") or "")):
        errors.append("WiFi 信道非法")
    if str(cfg.get("wifi_band") or "") not in ("2.4", "5"):
        errors.append("WiFi 频段非法")
    if str(cfg.get("wifi_channel_width") or "") not in ("20", "40", "80"):
        errors.append("WiFi 带宽非法")
    if cfg.get("wg_enabled"):
        iface = (cfg.get("wg_interface") or "wg0").strip()
        if not _RE_WG_IF.match(iface) or ".." in iface or "/" in iface:
            errors.append(f"WireGuard 接口名非法: {iface}")
        mode = cfg.get("wg_mode", "client")
        if mode == "server":
            if not _RE_WG_ADDR.match((cfg.get("wg_server_address") or "").strip()):
                errors.append("WG 服务器地址非法（需 CIDR）")
            if not _RE_WG_PORT.match((cfg.get("wg_server_port") or "").strip()):
                errors.append("WG 服务器端口非法")
            else:
                try:
                    p = int(cfg["wg_server_port"])
                    if not (0 < p < 65536):
                        errors.append("WG 服务器端口越界")
                except (TypeError, ValueError):
                    errors.append("WG 服务器端口非法")
            ep = (cfg.get("wg_server_endpoint") or "").strip()
            if ep and not _RE_WG_ENDP.match(ep):
                errors.append("WG 对外 Endpoint 非法")
            if cfg.get("wg_client_dns"):
                for d in str(cfg["wg_client_dns"]).replace(",", " ").split():
                    if d and not _valid_ip(d):
                        errors.append(f"WG 客户端 DNS 非法: {d}")
            if cfg.get("wg_client_allowed_ips"):
                if not _RE_WG_AIPS.match(str(cfg["wg_client_allowed_ips"])):
                    errors.append("WG 客户端 AllowedIPs 非法")
        else:
            if not _RE_WG_ADDR.match((cfg.get("wg_address") or "").strip()):
                errors.append("WG 本机地址非法（需 CIDR）")
            ep = (cfg.get("wg_endpoint") or "").strip()
            if not _RE_WG_ENDP.match(ep):
                errors.append("WG Endpoint 非法")
            pk = (cfg.get("wg_server_pubkey") or "").strip()
            if not _RE_WG_KEY.match(pk):
                errors.append("WG 服务器公钥非法")
            if cfg.get("wg_allowed_ips") and \
                    not _RE_WG_AIPS.match(str(cfg["wg_allowed_ips"])):
                errors.append("WG AllowedIPs 非法")
    return errors

# === END OF PART 1 ===
# ============================================================
# 路由器文件生成器
# ============================================================
def _write_netplan_router(cfg: dict) -> str:
    wan = cfg["wan_if"]
    wan_mode = cfg.get("wan_mode", "dhcp")
    lan_ifs_str = cfg.get("lan_ifs", "") or ""
    lan_list = [x.strip() for x in lan_ifs_str.replace(",", " ").split()
                if x.strip() and x.strip() != wan]
    br = cfg["br_name"]
    lines = [
        "# NetRouter — 由路由器配置向导自动生成",
        "network:", "  version: 2", "  renderer: networkd",
        "", "  ethernets:", f"    {wan}:",
    ]
    if wan_mode == "dhcp":
        lines.append("      dhcp4: true")
    elif wan_mode == "static":
        lines.append("      dhcp4: false")
        if cfg.get("wan_ip"):
            lines.append("      addresses:")
            lines.append(f"        - {cfg['wan_ip']}")
        if cfg.get("wan_gateway"):
            lines.append("      routes:")
            lines.append("        - to: default")
            lines.append(f"          via: {cfg['wan_gateway']}")
        dns_list = [d.strip() for d in
                    (cfg.get("wan_dns") or "").replace(",", " ").split()
                    if d.strip()]
        if dns_list:
            lines.append("      nameservers:")
            lines.append("        addresses:")
            for d in dns_list:
                lines.append(f"          - {d}")
    else:
        lines.append("      dhcp4: false")
    lines.append("      optional: true")
    lines.append("")
    for iface in lan_list:
        lines += [f"    {iface}:", "      dhcp4: false",
                  "      optional: true", ""]
    lines += ["  bridges:", f"    {br}:"]
    if lan_list:
        lines.append("      interfaces:")
        for iface in lan_list:
            lines.append(f"        - {iface}")
    lines += [
        "      addresses:",
        f"        - {cfg['lan_ip']}/{cfg['lan_netmask']}",
        "      dhcp4: false",
        "      parameters:",
        "        stp: false",
        "        forward-delay: 0",
    ]
    return "\n".join(lines) + "\n"

def _write_hostapd(cfg: dict, wifi_if: str, br_name: str) -> str:
    band = str(cfg.get("wifi_band", "5"))
    ch = int(cfg.get("wifi_channel", "149"))
    cw = str(cfg.get("wifi_channel_width", "80"))
    if band == "5":
        hw_mode = "a"
        if cw == "80" and ch in (36, 40, 44, 48):
            seg0 = 42
        elif cw == "80" and ch in (149, 153, 157, 161):
            seg0 = 155
        else:
            seg0 = 0
    else:
        hw_mode = "g"
        seg0 = 0
    lines = [
        f"interface={wifi_if}", "driver=nl80211",
        f"bridge={br_name}",
        "ctrl_interface=/var/run/hostapd",
        "ctrl_interface_group=0", "",
        f"ssid={cfg['wifi_ssid']}",
        f"country_code={cfg['wifi_country']}",
        "ieee80211d=1", "",
        f"hw_mode={hw_mode}", f"channel={ch}",
    ]
    if band == "5" and cw == "80" and seg0:
        lines += ["vht_oper_chwidth=1",
                  f"vht_oper_centr_freq_seg0_idx={seg0}"]
    lines += [
        "", "ieee80211n=1",
        "ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40][LDPC][TX-STBC][RX-STBC1]",
    ]
    if band == "5":
        lines += [
            "ieee80211ac=1",
            "vht_capab=[SHORT-GI-80][LDPC][TX-STBC][RX-STBC1][SU-BEAMFORMER]"
            "[SU-BEAMFORMEE][MAX-A-MPDU-LEN-EXP7]",
        ]
    lines += [
        "", "wmm_enabled=1", "uapsd_advertisement_enabled=1",
        "", "wpa=2",
        f"wpa_passphrase={cfg['wifi_passphrase']}",
        "wpa_key_mgmt=WPA-PSK", "wpa_pairwise=CCMP", "rsn_pairwise=CCMP",
        "", f"ieee80211w={cfg.get('wifi_pmf', '1')}",
        "", "auth_algs=1", "ignore_broadcast_ssid=0",
    ]
    return "\n".join(lines) + "\n"

def _write_dnsmasq(cfg: dict) -> str:
    lines = [
        "# Managed by NetRouter",
        f"interface={cfg['br_name']}",
        "bind-interfaces",
    ]
    if cfg.get("lan_dhcp_enabled", True):
        lines.append(
            f"dhcp-range={cfg['dhcp_start']},{cfg['dhcp_end']},"
            f"{cfg['dhcp_lease']}"
        )
        lines.append(f"dhcp-option=3,{cfg['lan_ip']}")
        dns = [x.strip() for x in (cfg.get("dns_servers") or "")
               .replace(",", " ").split() if x.strip()]
        for s in dns:
            if _valid_ip(s):
                lines.append(f"dhcp-option=6,{s}")
    else:
        lines.append("# DHCP disabled by user")
    return "\n".join(lines) + "\n"

def _write_pppoe(cfg: dict) -> dict:
    iface = cfg.get("wan_if", "")
    user = cfg.get("wan_pppoe_user", "")
    pwd = cfg.get("wan_pppoe_pass", "")
    if not iface or not user or not pwd:
        return {"ok": False, "message": "缺少 WAN 接口或 PPPoE 用户名/密码"}
    if (not _RE_IFNAME.match(iface) or not _RE_PPP_USER.match(user)
            or not _RE_PPP_PWD.match(pwd)):
        return {"ok": False, "message": "PPPoE 参数格式非法"}
    try:
        peers_dir = Path("/etc/ppp/peers")
        peers_dir.mkdir(parents=True, exist_ok=True)
        peers_file = peers_dir / "netrouter-wan"
        _atomic_write(peers_file,
            "# NetRouter PPPoE — 自动生成\n"
            "plugin rp-pppoe.so\n"
            f"nic-{iface}\n"
            f'name "{user}"\n'
            "usepeerdns\npersist\nnoauth\ndefaultroute\nnoipdefault\n"
            "hide-password\nmtu 1492\nmru 1492\n"
            "lcp-echo-interval 10\nlcp-echo-failure 3\n",
            0o600)
        for name in ("chap-secrets", "pap-secrets"):
            f = Path("/etc/ppp") / name
            existing = f.read_text() if f.exists() else ""
            if "netrouter-pppoe" not in existing:
                with open(f, "a") as fp:
                    fp.write(f"\n# netrouter-pppoe\n"
                             f'"{user}" * "{pwd}" *\n')
                try:
                    os.chmod(f, 0o600)
                except OSError:
                    pass
        svc = Path("/etc/systemd/system/netrouter-pppoe.service")
        _atomic_write(svc,
            "[Unit]\n"
            "Description=NetRouter PPPoE\n"
            "After=systemd-networkd.service\n"
            "Wants=network-pre.target\n"
            "Before=nftables.service dnsmasq.service\n\n"
            "[Service]\nType=simple\n"
            "ExecStart=/usr/sbin/pppd call netrouter-wan nodetach\n"
            "Restart=on-failure\nRestartSec=5\n\n"
            "[Install]\nWantedBy=multi-user.target\n",
            0o644)
        return {"ok": True, "message": "PPPoE 配置已写入"}
    except OSError as e:
        return {"ok": False, "message": str(e)}

# ============================================================
# WireGuard
# ============================================================
def _gen_wg_keypair():
    ok, priv, _ = run_cmd(["wg", "genkey"])
    if not ok or not priv.strip():
        return None, None
    priv = priv.strip()
    p = subprocess.run(["wg", "pubkey"], input=priv,
                       capture_output=True, text=True)
    pub = p.stdout.strip() if p.returncode == 0 else ""
    return priv, pub

def _gen_wg_psk() -> str:
    ok, out, _ = run_cmd(["wg", "genpsk"])
    return out.strip() if ok else ""

def _pubkey_from_priv(priv: str) -> str:
    if not priv:
        return ""
    p = subprocess.run(["wg", "pubkey"], input=priv,
                       capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else ""

def _next_client_ip(cfg: dict, peers: list) -> str:
    try:
        net = ipaddress.ip_network(
            cfg.get("wg_server_address") or "10.0.0.1/24", strict=False)
    except Exception:
        return "10.0.0.2/32"
    if net.num_addresses > 1024:
        return "10.0.0.2/32"
    used = set()
    for p in peers:
        try:
            used.add(str(ipaddress.ip_address(p["address"].split("/")[0])))
        except Exception:
            pass
    try:
        used.add(str(ipaddress.ip_address(
            (cfg.get("wg_server_address") or "10.0.0.1/24").split("/")[0])))
    except Exception:
        pass
    for h in net.hosts():
        if str(h) not in used:
            return f"{h}/32"
    return "10.0.0.2/32"

def load_wg_peers() -> list:
    if WG_PEERS_FILE.exists():
        try:
            return json.loads(WG_PEERS_FILE.read_text()).get("peers", [])
        except Exception:
            pass
    return []

def save_wg_peers(peers: list):
    _atomic_write(WG_PEERS_FILE,
                  json.dumps({"peers": peers},
                             indent=2, ensure_ascii=False),
                  0o600)

def _write_wireguard_client(cfg: dict) -> str:
    priv = cfg.get("wg_private_key") or ""
    if not priv:
        priv, _ = _gen_wg_keypair()
        priv = priv or ""
        cfg["wg_private_key"] = priv
    lines = [
        "[Interface]",
        f"Address = {cfg['wg_address']}",
        f"PrivateKey = {priv}",
        "", "[Peer]",
        f"PublicKey = {cfg['wg_server_pubkey']}",
        f"Endpoint = {cfg['wg_endpoint']}",
        f"AllowedIPs = {cfg['wg_allowed_ips']}",
    ]
    if cfg.get("wg_preshared_key"):
        lines.append(f"PresharedKey = {cfg['wg_preshared_key']}")
    lines.append(f"PersistentKeepalive = {cfg.get('wg_keepalive', '25')}")
    return "\n".join(lines) + "\n"

def _write_wireguard_server(cfg: dict, peers: list) -> str:
    priv = cfg.get("wg_server_private_key") or ""
    if not priv:
        priv, _ = _gen_wg_keypair()
        cfg["wg_server_private_key"] = priv or ""
    lines = [
        "[Interface]",
        f"Address = {cfg.get('wg_server_address') or '10.0.0.1/24'}",
        f"ListenPort = {cfg.get('wg_server_port') or '51820'}",
        f"PrivateKey = {priv}",
        "SaveConfig = false", "",
    ]
    for p in peers:
        if not _RE_WG_KEY.match(p.get("public_key", "")):
            continue
        lines.append(f"# name: {p.get('name', 'peer')}")
        lines.append(f"PublicKey = {p['public_key']}")
        if p.get("preshared_key") and _RE_WG_KEY.match(p["preshared_key"]):
            lines.append(f"PresharedKey = {p['preshared_key']}")
        ips = p.get("allowed_ips") or p.get("address") or ""
        if _RE_WG_AIPS.match(ips):
            lines.append(f"AllowedIPs = {ips}")
        else:
            continue
        lines.append("")
    return "\n".join(lines)

def _peer_client_config(cfg: dict, peer: dict) -> str:
    server_pub = _pubkey_from_priv(cfg.get("wg_server_private_key") or "")
    endpoint = (cfg.get("wg_server_endpoint") or "").strip()
    if endpoint and ":" not in endpoint:
        endpoint = f"{endpoint}:{cfg.get('wg_server_port') or '51820'}"
    lines = [
        "[Interface]",
        f"PrivateKey = {peer['private_key']}",
        f"Address = {peer['address']}",
    ]
    dns = (cfg.get("wg_client_dns") or "").strip()
    if dns:
        lines.append(f"DNS = {dns}")
    lines += ["", "[Peer]", f"PublicKey = {server_pub}"]
    if peer.get("preshared_key"):
        lines.append(f"PresharedKey = {peer['preshared_key']}")
    if endpoint:
        lines.append(f"Endpoint = {endpoint}")
    lines.append(
        f"AllowedIPs = {cfg.get('wg_client_allowed_ips') or '0.0.0.0/0, ::/0'}")
    lines.append(f"PersistentKeepalive = {cfg.get('wg_keepalive') or '25'}")
    return "\n".join(lines) + "\n"

# ============================================================
# 防火墙配置
# ============================================================
def load_firewall_cfg() -> dict:
    with _cfg_lock:
        if FIREWALL_CONF.exists():
            try:
                data = json.loads(FIREWALL_CONF.read_text())
                merged = dict(DEFAULT_FIREWALL_CFG)
                merged.update(data)
                merged["enabled"] = True
                return merged
            except Exception:
                pass
        return dict(DEFAULT_FIREWALL_CFG)

def save_firewall_cfg(cfg: dict):
    with _cfg_lock:
        data = dict(DEFAULT_FIREWALL_CFG)
        data.update(cfg or {})
        data["enabled"] = True
        _atomic_write(FIREWALL_CONF,
                      json.dumps(data, indent=2, ensure_ascii=False),
                      0o600)

def _sanitize_action(v, default="ACCEPT"):
    v = str(v or default).upper()
    return v if v in FW_ACTIONS else default

def _sanitize_fw_cfg(cfg: dict) -> dict:
    cfg = cfg or {}
    zones = []
    seen_names = set()
    for z in (cfg.get("zones") or []):
        if not isinstance(z, dict):
            continue
        name = str(z.get("name") or "").strip()
        if not _RE_ZONE_NAME.match(name) or name in seen_names:
            continue
        seen_names.add(name)
        ifs, seen_ifs = [], set()
        for i in (z.get("interfaces") or []):
            i = str(i).strip()
            if _RE_IFNAME.match(i) and i not in seen_ifs:
                seen_ifs.add(i)
                ifs.append(i)
        zones.append({
            "name": name, "interfaces": ifs,
            "input":   _sanitize_action(z.get("input")),
            "output":  _sanitize_action(z.get("output")),
            "forward": _sanitize_action(z.get("forward")),
            "masq":    bool(z.get("masq")),
            "mtu_fix": bool(z.get("mtu_fix")),
        })
    zone_names = {z["name"] for z in zones}
    forwardings, seen_fwd = [], set()
    for f in (cfg.get("forwardings") or []):
        if not isinstance(f, dict):
            continue
        src = str(f.get("src") or "").strip()
        dest = str(f.get("dest") or "").strip()
        if src not in zone_names or dest not in zone_names or src == dest:
            continue
        if (src, dest) in seen_fwd:
            continue
        seen_fwd.add((src, dest))
        forwardings.append({
            "src": src, "dest": dest,
            "enabled": bool(f.get("enabled", True)),
        })
    port_forwards = []
    for p in (cfg.get("port_forwards") or []):
        if not isinstance(p, dict):
            continue
        src_zone = str(p.get("src_zone") or "").strip()
        if src_zone not in zone_names:
            continue
        dest_ip = str(p.get("dest_ip") or "").strip()
        if not _valid_ip(dest_ip):
            continue
        try:
            src_port = int(p.get("src_port") or 0)
            dest_port = int(p.get("dest_port") or src_port)
        except (TypeError, ValueError):
            continue
        if not (0 < src_port < 65536) or not (0 < dest_port < 65536):
            continue
        proto = str(p.get("proto") or "tcp").lower()
        if proto not in ("tcp", "udp", "tcp+udp"):
            proto = "tcp"
        pf = {
            "name": str(p.get("name") or "").strip()[:64] or "rule",
            "proto": proto, "src_zone": src_zone,
            "src_port": src_port, "dest_ip": dest_ip,
            "dest_port": dest_port,
            "enabled": bool(p.get("enabled", True)),
        }
        src_ip = str(p.get("src_ip") or "").strip()
        if src_ip and _valid_ip(src_ip):
            pf["src_ip"] = src_ip
        port_forwards.append(pf)
    input_rules = []
    for r in (cfg.get("input_rules") or []):
        if not isinstance(r, dict):
            continue
        zone = str(r.get("zone") or "").strip()
        if zone not in zone_names:
            continue
        m = _RE_PORT.match(str(r.get("port") or "").strip())
        if not m:
            continue
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (0 < lo < 65536) or not (0 < hi < 65536) or lo > hi:
            continue
        proto = str(r.get("proto") or "tcp").lower()
        if proto not in ("tcp", "udp", "tcp+udp"):
            proto = "tcp"
        rule = {
            "name": str(r.get("name") or "").strip()[:64] or "rule",
            "zone": zone, "proto": proto,
            "port": (f"{lo}-{hi}" if hi != lo else str(lo)),
            "action": _sanitize_action(r.get("action")),
            "enabled": bool(r.get("enabled", True)),
        }
        sip = str(r.get("src_ip") or "").strip()
        if sip:
            if _valid_ip(sip):
                rule["src_ip"] = sip
            else:
                continue
        input_rules.append(rule)
    return {
        "enabled": True, "zones": zones,
        "forwardings": forwardings,
        "port_forwards": port_forwards,
        "input_rules": input_rules,
    }

def _nft_quote(v: str) -> str:
    return '"' + v.replace('\\', '\\\\').replace('"', '\\"') + '"'

def _build_default_zones_from_router(cfg: dict) -> dict:
    br = cfg.get("br_name") or "br-lan"
    wan_mode = cfg.get("wan_mode", "dhcp")
    wan_ifs: List[str] = []
    if wan_mode == "pppoe":
        wan_ifs.append(cfg.get("wan_pppoe_iface") or "ppp0")
    elif cfg.get("wan_if"):
        wan_ifs.append(cfg["wan_if"])
    if (cfg.get("wg_enabled") and cfg.get("wg_interface")
            and cfg.get("wg_mode") != "server"):
        wan_ifs.append(cfg["wg_interface"])
    lan_ifaces: List[str] = []
    if br:
        lan_ifaces.append(br)
    if (cfg.get("wg_enabled") and cfg.get("wg_mode") == "server"
            and cfg.get("wg_interface")):
        lan_ifaces.append(cfg["wg_interface"])
    zones = []
    if lan_ifaces:
        zones.append({
            "name": "lan", "interfaces": lan_ifaces,
            "input": "ACCEPT", "output": "ACCEPT",
            "forward": "ACCEPT", "masq": False, "mtu_fix": False,
        })
    if wan_ifs:
        zones.append({
            "name": "wan", "interfaces": wan_ifs,
            "input": "REJECT", "output": "ACCEPT",
            "forward": "REJECT", "masq": True, "mtu_fix": True,
        })
    forwardings = []
    if lan_ifaces and wan_ifs:
        forwardings.append({"src": "lan", "dest": "wan", "enabled": True})
    return {"zones": zones, "forwardings": forwardings}

def _write_nftables(cfg: dict) -> str:
    fw = _sanitize_fw_cfg(load_firewall_cfg())
    zones = [z for z in fw["zones"] if z["interfaces"]]
    zones_active = bool(zones)
    znames = {z["name"] for z in zones}
    br = cfg.get("br_name") or "br-lan"
    wan_mode = cfg.get("wan_mode", "dhcp")
    wan_ifs = []
    if wan_mode == "pppoe":
        wan_ifs.append(cfg.get("wan_pppoe_iface") or "ppp0")
    elif cfg.get("wan_if"):
        wan_ifs.append(cfg["wan_if"])
    if (cfg.get("wg_enabled") and cfg.get("wg_interface")
            and cfg.get("wg_mode") != "server"):
        wan_ifs.append(cfg["wg_interface"])
    wan_ifs = [i for i in wan_ifs if _RE_IFNAME.match(i)]
    if not _RE_IFNAME.match(br):
        br = "br-lan"
    L = [
        "#!/usr/sbin/nft -f",
        "# NetRouter 统一规则集",
        "#   基础层：来自「路由器」配置（NAT / 转发）",
        "#   增强层：来自「防火墙 → 区域设置」",
        "#   区域防火墙强制启用，不可关闭。",
        "#   由 route.py 自动生成，请勿手工修改。",
        "flush ruleset", "", "table inet router {",
    ]
    if zones_active:
        for z in zones:
            elems = ", ".join(_nft_quote(i) for i in z["interfaces"])
            L += [
                f"    set z_{z['name']} {{",
                "        type ifname",
                f"        elements = {{ {elems} }}",
                "    }",
            ]
        L.append("")
    L += [
        "    chain prerouting {",
        "        type nat hook prerouting priority dstnat; policy accept;",
    ]
    if zones_active:
        for p in fw.get("port_forwards", []):
            if not p.get("enabled", True) or p["src_zone"] not in znames:
                continue
            proto = p["proto"]
            protos = ["tcp"] if proto == "tcp" \
                else (["udp"] if proto == "udp" else ["tcp", "udp"])
            dest_ip = p["dest_ip"]
            for pr in protos:
                rule = [f'iifname @z_{p["src_zone"]}', pr]
                if p.get("src_ip"):
                    s = p["src_ip"]
                    rule.append(f'ip6 saddr {s}' if ":" in s
                                else f'ip saddr {s}')
                rule.append(f'dport {p["src_port"]}')
                if ":" in dest_ip:
                    rule.append(f'dnat ip6 to [{dest_ip}]:{p["dest_port"]}')
                else:
                    rule.append(f'dnat ip to {dest_ip}:{p["dest_port"]}')
                L.append("        " + " ".join(rule))
    L += ["    }", ""]
    L += [
        "    chain postrouting {",
        "        type nat hook postrouting priority srcnat; policy accept;",
    ]
    for oif in wan_ifs:
        L.append(f'        oifname "{oif}" masquerade')
    if zones_active:
        for z in zones:
            if z.get("masq"):
                L.append(f"        oifname @z_{z['name']} masquerade")
    L += ["    }", ""]
    L += [
        "    chain forward {",
        "        type filter hook forward priority filter;",
    ]
    if zones_active:
        L.append("        policy drop;")
        L.append("        ct state established,related accept")
        L.append("        ct status dnat accept")
        for oif in wan_ifs:
            L.append(f'        iifname "{br}" oifname "{oif}" accept')
        for f in fw.get("forwardings", []):
            if not f.get("enabled", True):
                continue
            if f["src"] not in znames or f["dest"] not in znames:
                continue
            L.append(
                f"        iifname @z_{f['src']} oifname @z_{f['dest']} accept"
            )
    else:
        L.append("        policy accept;")
        for oif in wan_ifs:
            L.append(f'        iifname "{br}" oifname "{oif}" accept')
            L.append(f'        iifname "{oif}" oifname "{br}" '
                     "ct state established,related accept")
    L += ["    }", ""]
    L += [
        "    chain input {",
        "        type filter hook input priority filter;",
    ]
    if zones_active:
        L.append("        policy drop;")
        L.append("        iif lo accept")
        L.append("        ct state established,related accept")
        L.append("        udp dport { 67, 68 } accept")
        L.append("        icmp type echo-request accept")
        L.append("        icmpv6 type { echo-request, nd-neighbor-solicit,"
                 " nd-neighbor-advert, nd-router-solicit, nd-router-advert }"
                 " accept")
        for r in fw.get("input_rules", []):
            if not r.get("enabled", True):
                continue
            if r["zone"] not in znames:
                continue
            proto = r["proto"]
            protos = ["tcp"] if proto == "tcp" \
                else (["udp"] if proto == "udp" else ["tcp", "udp"])
            for p in protos:
                parts = [f'iifname @z_{r["zone"]}']
                if r.get("src_ip"):
                    s = r["src_ip"]
                    parts.append(f'ip6 saddr {s}' if ":" in s
                                 else f'ip saddr {s}')
                parts.append(p)
                parts.append(f'dport {r["port"]}')
                parts.append(r["action"].lower())
                L.append("        " + " ".join(parts))
        for z in zones:
            if z["input"] == "ACCEPT":
                L.append(f"        iifname @z_{z['name']} accept")
    else:
        L.append("        policy accept;")
    L += ["    }", ""]
    L += [
        "    chain output {",
        "        type filter hook output priority filter; policy accept;",
        "    }",
    ]
    L.append("}")
    return "\n".join(L) + "\n"

def apply_router_config(cfg: dict, install: bool = False,
                        apply_network: bool = True) -> dict:
    if not is_root():
        return {"ok": False, "message": "需要 root 权限（请以 sudo 运行）",
                "steps": []}
    errors = validate_router_cfg(cfg)
    if errors:
        return {"ok": False,
                "message": "配置校验失败: " + "; ".join(errors),
                "steps": [{"name": "校验配置", "ok": False,
                           "message": "; ".join(errors)}]}
    steps = []
    wan_mode = cfg.get("wan_mode", "dhcp")
    if install:
        pkgs = list(ROUTER_ESSENTIAL_PKGS)
        if wan_mode == "pppoe":
            pkgs += ROUTER_PPPOE_PKGS
        r = _apt_install(pkgs)
        steps.append({"name": "安装软件包", **r})
        if not r["ok"]:
            return {"ok": False, "message": "依赖安装失败", "steps": steps}
    else:
        steps.append({"name": "安装软件包", "ok": True,
                      "message": "已跳过（请在包管理→路由功能必备中安装）"})
    run_cmd("modprobe nf_conntrack 2>/dev/null", check=False)
    run_cmd("modprobe nf_nat 2>/dev/null", check=False)
    run_cmd("modprobe nf_nat_ipv4 2>/dev/null", check=False)
    run_cmd("modprobe pppoe 2>/dev/null", check=False)
    country = cfg.get("wifi_country", "CN")
    if _RE_COUNTRY.match(country):
        run_cmd(["iw", "reg", "set", country], timeout=5)
    unit = """[Unit]
Description=Set WiFi regulatory domain
Before=hostapd.service
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/iw reg set {country}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
""".format(country=country)
    try:
        _atomic_write(Path("/etc/systemd/system/set-regdomain.service"),
                      unit, 0o644)
        steps.append({"name": "生成监管域单元", "ok": True, "message": "已写入"})
    except OSError as e:
        steps.append({"name": "生成监管域单元", "ok": False,
                      "message": str(e)})
    try:
        NETPLAN_FILE.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(NETPLAN_FILE, _write_netplan_router(cfg), 0o600)
        steps.append({"name": "写入 Netplan", "ok": True,
                      "message": str(NETPLAN_FILE)})
    except OSError as e:
        return {"ok": False, "message": f"写入 Netplan 失败: {e}",
                "steps": steps}
    ok, out, err = run_cmd(["netplan", "generate"], timeout=15)
    if not ok:
        steps.append({"name": "校验 Netplan", "ok": False,
                      "message": err or out})
        return {"ok": False, "message": "Netplan 语法错误", "steps": steps}
    steps.append({"name": "校验 Netplan", "ok": True, "message": "语法通过"})
    if apply_network:
        ok, out, err = run_cmd(["netplan", "apply"], timeout=30)
        steps.append({"name": "应用 Netplan", "ok": ok,
                      "message": err or out or "已应用"})
    time.sleep(1)
    wifi_iface = _find_wifi_in_lan(cfg)
    if wifi_iface:
        try:
            HOSTAPD_CONF.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(HOSTAPD_CONF,
                          _write_hostapd(cfg, wifi_iface, cfg["br_name"]),
                          0o600)
            default_file = Path("/etc/default/hostapd")
            if default_file.exists():
                txt = default_file.read_text()
                if "DAEMON_CONF=" in txt:
                    txt = re.sub(r'^DAEMON_CONF=.*$',
                                 f'DAEMON_CONF="{HOSTAPD_CONF}"',
                                 txt, flags=re.M)
                else:
                    txt += f'\nDAEMON_CONF="{HOSTAPD_CONF}"\n'
                _atomic_write(default_file, txt, 0o644)
            else:
                _atomic_write(default_file,
                              f'DAEMON_CONF="{HOSTAPD_CONF}"\n', 0o644)
            override_dir = Path("/etc/systemd/system/hostapd.service.d")
            override_dir.mkdir(parents=True, exist_ok=True)
            _atomic_write(override_dir / "override.conf",
                "[Unit]\nAfter=\nAfter=network.target set-regdomain.service\n"
                "Before=systemd-networkd.service\n", 0o644)
            steps.append({"name": "写入 hostapd", "ok": True,
                          "message": f"{HOSTAPD_CONF} · AP={wifi_iface}"})
        except OSError as e:
            steps.append({"name": "写入 hostapd", "ok": False,
                          "message": str(e)})
    else:
        steps.append({"name": "写入 hostapd", "ok": True,
                      "message": "跳过（LAN 中未包含无线接口）"})
    try:
        DNSMASQ_FILE.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(DNSMASQ_FILE, _write_dnsmasq(cfg), 0o644)
        dhcp_status = "启用" if cfg.get("lan_dhcp_enabled", True) else "禁用"
        steps.append({"name": "写入 dnsmasq", "ok": True,
                      "message": f"{DNSMASQ_FILE} · DHCP={dhcp_status}"})
    except OSError as e:
        steps.append({"name": "写入 dnsmasq", "ok": False, "message": str(e)})
    try:
        _atomic_write(Path("/etc/sysctl.d/99-netrouter.conf"),
                      "net.ipv4.ip_forward=1\n", 0o644)
        run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        steps.append({"name": "启用 IP 转发", "ok": True, "message": "已启用"})
    except Exception as e:
        steps.append({"name": "启用 IP 转发", "ok": False, "message": str(e)})
    if cfg.get("wg_enabled"):
        try:
            WG_DIR.mkdir(parents=True, exist_ok=True)
            os.chmod(WG_DIR, 0o700)
            wg_if = cfg.get("wg_interface") or "wg0"
            if not _RE_WG_IF.match(wg_if) or ".." in wg_if or "/" in wg_if:
                raise ValueError(f"wg_interface 非法: {wg_if}")
            wg_file = WG_DIR / f"{wg_if}.conf"
            if cfg.get("wg_mode") == "server":
                peers = load_wg_peers()
                content = _write_wireguard_server(cfg, peers)
                _atomic_write(wg_file, content, 0o600)
                save_router_cfg(cfg)
            else:
                content = _write_wireguard_client(cfg)
                _atomic_write(wg_file, content, 0o600)
                save_router_cfg(cfg)
            steps.append({"name": "写入 WireGuard", "ok": True,
                          "message": f"{wg_file} · 模式={cfg.get('wg_mode')}"})
        except (OSError, ValueError) as e:
            steps.append({"name": "写入 WireGuard", "ok": False,
                          "message": str(e)})
    else:
        steps.append({"name": "写入 WireGuard", "ok": True,
                      "message": "跳过（未启用）"})
    if wan_mode == "pppoe":
        r = _write_pppoe(cfg)
        steps.append({"name": "写入 PPPoE", **r})
    try:
        fw = load_firewall_cfg()
        base = _build_default_zones_from_router(cfg)
        if not fw.get("zones"):
            fw["enabled"] = True
            fw["zones"] = base["zones"]
            fw["forwardings"] = base["forwardings"]
            fw.setdefault("port_forwards", [])
            fw.setdefault("input_rules", [])
            save_firewall_cfg(fw)
            steps.append({"name": "初始化防火墙区域", "ok": True,
                          "message": "已创建默认 lan / wan 区域"})
        else:
            changed = []
            for bz in base["zones"]:
                for z in fw["zones"]:
                    if z["name"] == bz["name"]:
                        if z.get("interfaces") != bz["interfaces"]:
                            z["interfaces"] = bz["interfaces"]
                            changed.append(f"{z['name']} 接口")
                        break
            has_l2w = any(f.get("src") == "lan" and f.get("dest") == "wan"
                          for f in fw.get("forwardings", []))
            if not has_l2w and base["forwardings"]:
                fw.setdefault("forwardings", []).append(base["forwardings"][0])
                changed.append("lan→wan 转发")
            fw["enabled"] = True
            save_firewall_cfg(fw)
            steps.append({"name": "同步防火墙区域", "ok": True,
                          "message": ("更新: " + ", ".join(changed))
                          if changed else "无需变更"})
    except Exception as e:
        steps.append({"name": "初始化防火墙区域", "ok": False,
                      "message": str(e)})
    try:
        fw = load_firewall_cfg()
        has_wan = any(z.get("name") == "wan" for z in fw.get("zones", []))
        if has_wan:
            has_ssh = any(
                r.get("zone") == "wan"
                and str(r.get("port")) == "22"
                and r.get("action") == "ACCEPT"
                and r.get("enabled", True)
                and r.get("proto") in ("tcp", "tcp+udp")
                for r in fw.get("input_rules", [])
            )
            if not has_ssh:
                fw.setdefault("input_rules", []).insert(0, {
                    "name": "allow-ssh",
                    "zone": "wan", "proto": "tcp", "port": "22",
                    "action": "ACCEPT", "enabled": True,
                })
                save_firewall_cfg(fw)
                steps.append({"name": "默认放行 SSH", "ok": True,
                              "message": "wan TCP 22 ACCEPT"})
            else:
                steps.append({"name": "默认放行 SSH", "ok": True,
                              "message": "已存在，跳过"})
        else:
            steps.append({"name": "默认放行 SSH", "ok": True,
                          "message": "无 wan 区域，跳过"})
    except Exception as e:
        steps.append({"name": "默认放行 SSH", "ok": False, "message": str(e)})
    try:
        fw = load_firewall_cfg()
        has_wan = any(z.get("name") == "wan" for z in fw.get("zones", []))
        if has_wan:
            mgmt_port = str(PORT)
            has_mgmt = any(
                r.get("zone") == "wan"
                and str(r.get("port")) == mgmt_port
                and r.get("action") == "ACCEPT"
                and r.get("enabled", True)
                and r.get("proto") in ("tcp", "tcp+udp")
                for r in fw.get("input_rules", [])
            )
            if not has_mgmt:
                rules = fw.setdefault("input_rules", [])
                insert_at = 0
                for i, r in enumerate(rules):
                    if r.get("name") == "allow-ssh":
                        insert_at = i + 1
                        break
                rules.insert(insert_at, {
                    "name": "allow-mgmt",
                    "zone": "wan", "proto": "tcp", "port": mgmt_port,
                    "action": "ACCEPT", "enabled": True,
                })
                save_firewall_cfg(fw)
                steps.append({"name": "默认放行管理端口", "ok": True,
                              "message": f"wan TCP {mgmt_port} ACCEPT"})
            else:
                steps.append({"name": "默认放行管理端口", "ok": True,
                              "message": "已存在，跳过"})
        else:
            steps.append({"name": "默认放行管理端口", "ok": True,
                          "message": "无 wan 区域，跳过"})
    except Exception as e:
        steps.append({"name": "默认放行管理端口", "ok": False,
                      "message": str(e)})
    if cfg.get("wg_enabled") and cfg.get("wg_mode") == "server":
        try:
            fw = load_firewall_cfg()
            port = str(cfg.get("wg_server_port") or "51820")
            exists = any(
                r.get("zone") == "wan"
                and str(r.get("port")) == port
                and r.get("proto") == "udp"
                and r.get("action") == "ACCEPT"
                for r in fw.get("input_rules", [])
            )
            if not exists:
                fw.setdefault("input_rules", []).append({
                    "name": "wireguard",
                    "zone": "wan", "proto": "udp", "port": port,
                    "action": "ACCEPT", "enabled": True,
                })
                save_firewall_cfg(fw)
                steps.append({"name": "放行 WireGuard 端口", "ok": True,
                              "message": f"wan UDP {port} ACCEPT"})
            else:
                steps.append({"name": "放行 WireGuard 端口", "ok": True,
                              "message": "已存在，跳过"})
        except Exception as e:
            steps.append({"name": "放行 WireGuard 端口", "ok": False,
                          "message": str(e)})
    try:
        _atomic_write(Path("/etc/nftables.conf"),
                      _write_nftables(cfg), 0o600)
        ok, out, err = run_cmd(["nft", "-f", "/etc/nftables.conf"], timeout=15)
        steps.append({"name": "应用 nftables", "ok": ok,
                      "message": err or "已加载"})
    except OSError as e:
        steps.append({"name": "应用 nftables", "ok": False,
                      "message": str(e)})
    services = ["set-regdomain", "systemd-networkd", "nftables"]
    if wifi_iface:
        services.append("hostapd")
    if wan_mode == "pppoe":
        services.append("netrouter-pppoe")
    services.append("dnsmasq")
    if cfg.get("wg_enabled"):
        services.append(f"wg-quick@{cfg['wg_interface']}")
    for svc in services:
        run_cmd(["systemctl", "unmask", svc])
        run_cmd(["systemctl", "enable", svc])
    restart_order = ["set-regdomain", "systemd-networkd"]
    if wifi_iface:
        restart_order.append("hostapd")
    if wan_mode == "pppoe":
        restart_order.append("netrouter-pppoe")
    restart_order += ["nftables", "dnsmasq"]
    if cfg.get("wg_enabled"):
        restart_order.append(f"wg-quick@{cfg['wg_interface']}")
    for svc in restart_order:
        run_cmd(["systemctl", "restart", svc], timeout=20)
        time.sleep(0.4)
    steps.append({"name": "启动服务", "ok": True, "message": "已按顺序启用"})
    cfg["applied"] = True
    cfg["applied_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    save_router_cfg(cfg)
    audit("apply", f"WAN={cfg.get('wan_if')} mode={cfg.get('wan_mode')}")
    return {
        "ok": True, "message": "路由器配置已应用",
        "steps": steps,
        "config": {k: v for k, v in cfg.items()
                   if "private_key" not in k},
    }

# ============================================================
# nftables 管理
# ============================================================
def nft_run(args: list, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["nft"] + args, capture_output=True,
                          text=True, check=check)

def _expr_to_string(expr: list) -> str:
    parts = []
    for e in expr:
        if "match" in e:
            m = e["match"]
            left = m.get("left", {})
            key = (left.get("payload", {}).get("field", "")
                   or left.get("meta", {}).get("key", "")
                   or left.get("cmp", {}).get("field", ""))
            right = m.get("right", "")
            if isinstance(right, dict) and "set" in right:
                right = "{" + ",".join(str(x) for x in right["set"]) + "}"
            elif isinstance(right, dict):
                right = right.get("prefix", {}).get("addr", str(right))
            parts.append(f"{key} {m.get('op', '')} {right}")
        elif "counter" in e:
            parts.append("counter")
        elif "nat" in e:
            n = e["nat"]
            parts.append("nat " + n.get("type", "") + " "
                         + str(n.get("addr", "")) + ":" + str(n.get("port", "")))
        elif "redir" in e:
            parts.append("redirect")
        elif "mangle" in e:
            parts.append("mangle")
        for kw in ("accept", "drop", "reject", "masquerade", "return"):
            if kw in e:
                parts.append(kw)
        if "jump" in e:
            parts.append("jump " + str(e["jump"].get("target", "")))
        if "goto" in e:
            parts.append("goto " + str(e["goto"].get("target", "")))
        if "log" in e:
            parts.append("log")
    return " ".join(parts) or "(empty)"

def firewall_dump_all() -> dict:
    p = nft_run(["-j", "list", "ruleset"], check=False)
    if p.returncode != 0:
        return {"tables": [], "error": p.stderr}
    try:
        data = json.loads(p.stdout or "{}")
    except json.JSONDecodeError:
        return {"tables": [], "error": "解析失败"}
    tables: dict = {}
    for item in data.get("nftables", []):
        if "table" in item:
            t = item["table"]
            key = f"{t['family']} {t['name']}"
            tables[key] = {
                "family": t["family"], "name": t["name"],
                "chains": [], "sets": [], "counters": [],
                "managed": False,
                "router": (t["name"] == NFT_ROUTER_TABLE
                           and t["family"] == "inet"),
            }
        elif "chain" in item:
            c = item["chain"]
            key = f"{c['family']} {c['table']}"
            if key in tables:
                tables[key]["chains"].append({
                    "name": c["name"], "type": c.get("type"),
                    "hook": c.get("hook"), "prio": c.get("prio"),
                    "policy": c.get("policy"), "rules": [],
                })
        elif "rule" in item:
            r = item["rule"]
            key = f"{r['family']} {r['table']}"
            if key in tables:
                for chain in tables[key]["chains"]:
                    if chain["name"] == r["chain"]:
                        chain["rules"].append({
                            "handle": r["handle"],
                            "expr": _expr_to_string(r.get("expr", [])),
                        })
                        break
        elif "set" in item:
            s = item["set"]
            key = f"{s['family']} {s['table']}"
            if key in tables:
                tables[key]["sets"].append({
                    "name": s["name"], "type": s.get("type", ""),
                    "count": len(s.get("elem", [])),
                })
    return {"tables": list(tables.values())}

SYSTEM_TABLES = {
    ("ip", "filter"), ("ip", "nat"), ("ip", "mangle"), ("ip", "raw"),
    ("ip6", "filter"), ("ip6", "nat"), ("ip6", "mangle"), ("ip6", "raw"),
    ("inet", "firewalld"), ("inet", "filter"),
}

def firewall_flush_table(family: str, name: str) -> dict:
    if family not in ("ip", "ip6", "inet", "arp", "bridge", "netdev"):
        return {"ok": False, "message": "不支持的 family"}
    if (family, name) in SYSTEM_TABLES:
        return {"ok": False, "message": "禁止清空系统关键表"}
    if name == NFT_ROUTER_TABLE and family == "inet":
        return {"ok": False, "message": "禁止清空路由器主表"}
    if not re.match(r"^[A-Za-z0-9_.\-]{1,64}$", name or ""):
        return {"ok": False, "message": "非法表名"}
    p = nft_run(["flush", "table", family, name], check=False)
    return {"ok": p.returncode == 0,
            "message": p.stderr.strip() or "已清空"}

# ============================================================
# 网络诊断
# ============================================================
def route_list() -> list:
    out = []
    for fam, flag in (("ipv4", "-4"), ("ipv6", "-6")):
        ok, so, _ = run_cmd(["ip", flag, "-j", "route", "show"], timeout=3)
        if ok:
            try:
                for item in json.loads(so or "[]"):
                    item["family"] = fam
                    out.append(item)
            except json.JSONDecodeError:
                continue
    return out

def neighbor_list() -> list:
    out = []
    for fam, flag in (("ipv4", "-4"), ("ipv6", "-6")):
        ok, so, _ = run_cmd(["ip", flag, "-j", "neigh", "show"], timeout=3)
        if ok:
            try:
                for item in json.loads(so or "[]"):
                    item["family"] = fam
                    out.append(item)
            except json.JSONDecodeError:
                continue
    return out

def tools_ping(host: str, count: int = 4) -> dict:
    if not _RE_HOSTNAME.match(host):
        return {"ok": False, "output": "非法主机名"}
    count = min(max(int(count), 1), 10)
    ok, out, err = run_cmd(
        ["ping", "-c", str(count), "-W", "1",
         "-w", str(count * 2 + 2), host],
        timeout=count * 3 + 5,
    )
    return {"ok": ok, "output": out + err}

def tools_dns(name: str, server: str = "") -> dict:
    if not _RE_HOSTNAME.match(name):
        return {"ok": False, "output": "非法域名"}
    cmd = ["dig", "+short", name]
    if server:
        if not _valid_ip(server):
            return {"ok": False, "output": "非法 DNS 服务器"}
        cmd.insert(1, "@" + server)
    ok, out, err = run_cmd(cmd, timeout=5)
    if ok and out.strip():
        return {"ok": True, "output": out.strip()}
    ok2, out2, err2 = run_cmd(["getent", "hosts", name], timeout=5)
    return {"ok": ok2, "output": out2.strip() or err2.strip() or "未找到"}

# ============================================================
# 包管理
# ============================================================
_pkg_tasks: Dict[str, dict] = {}
_pkg_tasks_lock = threading.Lock()

def check_packages_status(packages: List[str],
                          desc_map: Optional[dict] = None) -> List[dict]:
    desc_map = desc_map if desc_map is not None else ROUTER_PKG_DESC
    results = []
    for pkg in packages:
        ok, out, _ = run_cmd(
            ["dpkg-query", "-W", "-f=${Status}", pkg], timeout=5)
        installed = ok and "install ok installed" in out
        results.append({
            "name": pkg, "installed": installed,
            "desc": desc_map.get(pkg, ""),
        })
    return results

def pkg_validate_name(name: str) -> bool:
    return bool(_RE_PKG_NAME.match(name or ""))

def pkg_validate_list(names: List[str]) -> Optional[str]:
    if not names:
        return "包列表为空"
    if len(names) > 50:
        return "单次操作最多 50 个包"
    for n in names:
        if not pkg_validate_name(n):
            return f"非法包名: {n}"
    return None

def pkg_search(query: str, limit: int = 60) -> list:
    if not query or len(query) < 2:
        return []
    if not re.match(r"^[a-zA-Z0-9+._:-]{2,100}$", query):
        return []
    ok, out, _ = run_cmd(["apt-cache", "search", "--names-only", query],
                         timeout=15)
    if not ok or not out.strip():
        ok, out, _ = run_cmd(["apt-cache", "search", query], timeout=15)
    results = []
    if not ok:
        return results
    for line in out.splitlines():
        if " - " in line:
            name, desc = line.split(" - ", 1)
            results.append({"name": name.strip(), "desc": desc.strip()})
            if len(results) >= limit:
                break
    return results

def pkg_list_installed(limit: int = 2000) -> list:
    ok, out, _ = run_cmd(
        ["dpkg-query", "-W",
         "-f=${Package}\t${Version}\t${binary:Summary}\n"],
        timeout=15,
    )
    if not ok:
        return []
    results = []
    for line in out.splitlines():
        parts = line.split("\t", 2)
        if len(parts) < 2:
            continue
        name = parts[0].strip()
        version = parts[1].strip()
        summary = parts[2].strip() if len(parts) > 2 else ""
        results.append({"name": name, "version": version, "summary": summary})
    results.sort(key=lambda x: x["name"])
    return results[:limit]

def pkg_run_task(cmd: list, label: str) -> str:
    task_id = secrets.token_urlsafe(12)
    with _pkg_tasks_lock:
        _pkg_tasks[task_id] = {
            "id": task_id, "label": label,
            "command": " ".join(cmd),
            "status": "running", "output": "",
            "ok": None, "returncode": None,
            "started_at": time.time(), "finished_at": None,
        }

    def worker():
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive",
                   LANG="C.UTF-8", LC_ALL="C.UTF-8")
        rc = -1
        try:
            proc = subprocess.Popen(
                cmd, env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            if proc.stdout is not None:
                for line in iter(proc.stdout.readline, ""):
                    with _pkg_tasks_lock:
                        t = _pkg_tasks.get(task_id)
                        if not t:
                            break
                        t["output"] += line
                        if len(t["output"]) > 200_000:
                            t["output"] = ("[...truncated...]\n"
                                           + t["output"][-150_000:])
            try:
                proc.wait(timeout=1800)
            except subprocess.TimeoutExpired:
                proc.kill()
                with _pkg_tasks_lock:
                    if task_id in _pkg_tasks:
                        _pkg_tasks[task_id]["output"] += "\n[TIMEOUT]\n"
            rc = proc.returncode if proc.returncode is not None else -1
        except Exception as e:
            with _pkg_tasks_lock:
                if task_id in _pkg_tasks:
                    _pkg_tasks[task_id]["output"] += f"\n[ERROR] {e}\n"
            rc = -1
        with _pkg_tasks_lock:
            if task_id in _pkg_tasks:
                _pkg_tasks[task_id]["status"] = "done"
                _pkg_tasks[task_id]["ok"] = (rc == 0)
                _pkg_tasks[task_id]["returncode"] = rc
                _pkg_tasks[task_id]["finished_at"] = time.time()

    threading.Thread(target=worker, daemon=True).start()
    return task_id

def pkg_task_get(task_id: str) -> Optional[dict]:
    with _pkg_tasks_lock:
        t = _pkg_tasks.get(task_id)
        return dict(t) if t else None

def pkg_tasks_cleanup():
    now = time.time()
    with _pkg_tasks_lock:
        to_del = [
            k for k, v in _pkg_tasks.items()
            if v["finished_at"] and now - v["finished_at"] > 3600
        ]
        for k in to_del:
            del _pkg_tasks[k]

def _pkg_cleanup_daemon():
    while True:
        time.sleep(300)
        try:
            pkg_tasks_cleanup()
        except Exception:
            pass

threading.Thread(target=_pkg_cleanup_daemon, daemon=True).start()

# ============================================================
# 虚拟机 (QEMU/KVM + libvirt)
# ============================================================
def load_vm_cfg() -> dict:
    with _cfg_lock:
        if VM_CONF.exists():
            try:
                data = json.loads(VM_CONF.read_text())
                merged = dict(DEFAULT_VM_CFG)
                merged.update(data)
                return merged
            except Exception:
                pass
        return dict(DEFAULT_VM_CFG)

def save_vm_cfg(cfg: dict) -> dict:
    with _cfg_lock:
        data = dict(DEFAULT_VM_CFG)
        data.update(cfg or {})
        sd = str(data.get("storage_dir") or "").strip()
        if (not sd or not sd.startswith("/") or ".." in sd
                or len(sd) > 256):
            sd = VM_DEFAULT_STORAGE
        data["storage_dir"] = sd.rstrip("/") or "/"
        dirs = []
        for d in (data.get("iso_dirs") or VM_DEFAULT_ISO_DIRS):
            d = str(d).strip()
            if d.startswith("/") and ".." not in d and len(d) < 256:
                dirs.append(d.rstrip("/") or "/")
        data["iso_dirs"] = dirs or list(VM_DEFAULT_ISO_DIRS)
        _atomic_write(VM_CONF,
                      json.dumps(data, indent=2, ensure_ascii=False),
                      0o600)
        return data

def _vm_storage_dir() -> Path:
    return Path(load_vm_cfg().get("storage_dir") or VM_DEFAULT_STORAGE)

def _vm_dir(name: str) -> Path:
    return _vm_storage_dir() / name

def _vm_disk_path(name: str) -> Path:
    return _vm_dir(name) / f"{name}.qcow2"

def _virsh(args: list, timeout: int = 10):
    return run_cmd(["virsh", "-c", "qemu:///system"] + args, timeout=timeout)

def _ensure_libvirtd():
    try:
        ok, out, _ = run_cmd(["systemctl", "is-active", "libvirtd"], timeout=3)
        if not ok or out.strip() != "active":
            run_cmd(["systemctl", "start", "libvirtd"], timeout=20)
        run_cmd(["systemctl", "enable", "libvirtd"], timeout=10)
    except Exception:
        pass

def vm_kvm_available() -> dict:
    info = {"available": False, "reason": "", "libvirtd": "unknown",
            "virsh": shutil.which("virsh") or "",
            "virt_install": shutil.which("virt-install") or ""}
    if os.path.exists("/dev/kvm"):
        info["available"] = True
    else:
        info["reason"] = "未检测到 /dev/kvm（CPU 虚拟化未启用或缺少模块）"
    ok, out, _ = run_cmd(["systemctl", "is-active", "libvirtd"], timeout=3)
    info["libvirtd"] = out.strip() if ok else "inactive"
    return info

def vm_list_isos() -> list:
    cfg = load_vm_cfg()
    dirs = cfg.get("iso_dirs") or VM_DEFAULT_ISO_DIRS
    out, seen = [], set()
    for d in dirs:
        if not os.path.isdir(d):
            continue
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        for f in names:
            if not f.lower().endswith(".iso"):
                continue
            fp = os.path.join(d, f)
            try:
                rp = os.path.realpath(fp)
            except OSError:
                continue
            if rp in seen:
                continue
            seen.add(rp)
            try:
                st = os.stat(fp)
                out.append({"path": fp, "name": f, "size": st.st_size})
            except OSError:
                continue
    return out

def vm_browse_qcow2(extra_dir: str = "") -> list:
    roots = []
    if extra_dir:
        try:
            if (extra_dir.startswith("/") and ".." not in extra_dir
                    and os.path.isdir(extra_dir)):
                roots.append(extra_dir)
        except Exception:
            pass
    try:
        sd = str(_vm_storage_dir())
        if sd not in roots and os.path.isdir(sd):
            roots.append(sd)
    except Exception:
        pass
    for d in VM_QCOSCAN_DIRS:
        if d not in roots and os.path.isdir(d):
            roots.append(d)
    out, seen = [], set()
    for root in roots:
        try:
            for dirpath, dirnames, filenames in os.walk(
                    root, followlinks=False):
                depth = dirpath.count(os.sep) - root.count(os.sep)
                if depth >= 4:
                    dirnames[:] = []
                    continue
                dirnames[:] = [
                    d for d in dirnames
                    if not d.startswith(".")
                    and d not in ("proc", "sys", "dev", "run", "snap",
                                  "boot", "lost+found")
                ]
                for f in filenames:
                    if f.startswith("."):
                        continue
                    if not f.lower().endswith((".qcow2", ".qcow")):
                        continue
                    fp = os.path.join(dirpath, f)
                    try:
                        rp = os.path.realpath(fp)
                    except OSError:
                        continue
                    if rp in seen:
                        continue
                    seen.add(rp)
                    try:
                        st = os.stat(fp)
                    except OSError:
                        continue
                    out.append({
                        "path": fp, "name": f,
                        "size": st.st_size, "mtime": st.st_mtime,
                    })
                    if len(out) >= 500:
                        return out
        except OSError:
            continue
    out.sort(key=lambda x: x["mtime"], reverse=True)
    return out

def _vm_used_vnc_ports() -> set:
    used = set()
    for vm in vm_list():
        p = vm.get("vnc_port")
        if p:
            try:
                used.add(int(p))
            except (TypeError, ValueError):
                pass
    return used

def _alloc_vnc_port() -> Optional[int]:
    used = _vm_used_vnc_ports()
    for p in range(VNC_PORT_MIN, VNC_PORT_MAX + 1):
        if p not in used:
            return p
    return None

def vm_info(name: str) -> Optional[dict]:
    if not _RE_VM_NAME.match(name or ""):
        return None
    ok, dom_out, _ = _virsh(["dominfo", name], timeout=5)
    if not ok:
        return None
    info = {
        "name": name, "state": "unknown", "running": False,
        "vcpu": 0, "memory_mb": 0, "max_memory_mb": 0,
        "autostart": False, "vnc_port": None, "vnc_listen": "",
        "vnc_password": False, "uuid": "", "os_type": "",
        "disks": [], "interfaces": [], "storage_dir": "",
    }
    for line in dom_out.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        if k == "State":
            info["state"] = v
        elif k == "CPU(s)":
            try:
                info["vcpu"] = int(v)
            except ValueError:
                pass
        elif k == "Max memory":
            m = re.match(r"(\d+)", v)
            if m:
                info["max_memory_mb"] = int(m.group(1)) // 1024
        elif k == "Used memory":
            m = re.match(r"(\d+)", v)
            if m:
                info["memory_mb"] = int(m.group(1)) // 1024
        elif k == "Autostart":
            info["autostart"] = (v == "enable")
        elif k == "UUID":
            info["uuid"] = v
    ok, did_out, _ = _virsh(["domid", name], timeout=5)
    info["running"] = bool(ok and did_out.strip() not in ("", "-"))
    if not info["running"]:
        info["memory_mb"] = 0
    ok, xml_out, _ = _virsh(["dumpxml", name], timeout=5)
    if ok and xml_out:
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_out)
            for g in root.iter("graphics"):
                if g.get("type") == "vnc":
                    try:
                        p = int(g.get("port", "-1"))
                        info["vnc_port"] = p if p > 0 else None
                    except ValueError:
                        info["vnc_port"] = None
                    info["vnc_listen"] = g.get("listen", "") or ""
                    info["vnc_password"] = bool(g.get("passwd"))
            for d in root.iter("disk"):
                dev = d.get("device", "")
                if dev not in ("disk", "cdrom"):
                    continue
                src = d.find("source")
                tgt = d.find("target")
                path = ""
                if src is not None:
                    path = src.get("file") or src.get("dev") or ""
                target = tgt.get("dev", "") if tgt is not None else ""
                info["disks"].append({
                    "device": dev, "path": path, "target": target,
                })
            for i in root.iter("interface"):
                iface = {"type": i.get("type", ""), "source": "", "mac": ""}
                s = i.find("source")
                if s is not None:
                    iface["source"] = (s.get("bridge")
                                       or s.get("network") or "")
                mac = i.find("mac")
                if mac is not None:
                    iface["mac"] = mac.get("address", "")
                info["interfaces"].append(iface)
            os_el = root.find("os")
            if os_el is not None:
                t = os_el.find("type")
                if t is not None:
                    info["os_type"] = (t.text or "")
        except Exception:
            pass
    for d in info.get("disks", []):
        if d.get("device") == "disk" and d.get("path"):
            try:
                info["storage_dir"] = str(Path(d["path"]).parent)
            except Exception:
                pass
            break
    return info

def vm_list() -> list:
    ok, out, _ = _virsh(["list", "--all", "--name"], timeout=5)
    if not ok:
        return []
    names = [n.strip() for n in out.splitlines() if n.strip()]
    return [v for v in (vm_info(n) for n in names) if v]

def _vm_open_vnc_in_firewall(vm_name: str, port: int, enable: bool) -> dict:
    try:
        rule_name = (f"vnc-{vm_name}")[:64]
        fw = load_firewall_cfg()
        rules = fw.setdefault("input_rules", [])
        rules[:] = [r for r in rules if r.get("name") != rule_name]
        if enable:
            rules.append({
                "name": rule_name,
                "zone": "wan", "proto": "tcp", "port": str(port),
                "action": "ACCEPT", "enabled": True,
            })
        save_firewall_cfg(fw)
        content = _write_nftables(load_router_cfg())
        _atomic_write(Path("/etc/nftables.conf"), content, 0o600)
        ok, out, err = run_cmd(["nft", "-f", "/etc/nftables.conf"], timeout=15)
        if not ok:
            return {"ok": False,
                    "message": (err or out or "应用 nftables 失败").strip()}
        return {"ok": True,
                "message": ("已放行 VNC 端口" if enable
                            else "已撤销 VNC 放行规则")}
    except Exception as e:
        return {"ok": False, "message": f"更新防火墙失败: {e}"}

def _vm_rollback_disk(disk_mode: str, disk_path: Path,
                      rollback_src: Optional[Path], vm_dir: Path):
    try:
        if disk_mode == "import" and rollback_src is not None:
            if disk_path.exists():
                shutil.move(str(disk_path), str(rollback_src))
        elif disk_mode == "new":
            if disk_path.exists():
                disk_path.unlink()
    except (OSError, shutil.Error):
        pass
    try:
        vm_dir.rmdir()
    except OSError:
        pass

def vm_create(payload: dict) -> dict:
    if not is_root():
        return {"ok": False, "message": "需要 root 权限（请以 sudo 启动 NetRouter）"}
    if not shutil.which("virt-install"):
        return {"ok": False,
                "message": "未安装 virt-install，请先在「包管理」中安装"}
    name = (payload.get("name") or "").strip()
    if not _RE_VM_NAME.match(name):
        return {"ok": False,
                "message": "名称非法（字母/数字开头，1-64 位）"}
    if vm_info(name) is not None:
        return {"ok": False, "message": f"虚拟机 {name} 已存在"}
    try:
        vcpu = int(payload.get("vcpu", 2))
        memory = int(payload.get("memory", 2048))
    except (TypeError, ValueError):
        return {"ok": False, "message": "CPU / 内存参数非法"}
    if not (1 <= vcpu <= 64):
        return {"ok": False, "message": "vCPU 数量需在 1-64 之间"}
    if not (128 <= memory <= 262144):
        return {"ok": False, "message": "内存需在 128-262144 MB 之间"}
    bridge = (payload.get("bridge") or "br-lan").strip()
    if not _RE_IFNAME.match(bridge):
        return {"ok": False, "message": "网桥名称非法"}
    if not os.path.isdir(f"/sys/class/net/{bridge}"):
        return {"ok": False,
                "message": f"网桥 {bridge} 不存在（请先在「路由器」页创建）"}
    iso = (payload.get("iso") or "").strip()
    iso_real = ""
    if iso:
        if not iso.lower().endswith(".iso"):
            return {"ok": False, "message": "仅支持 .iso 镜像文件"}
        try:
            iso_real = os.path.realpath(iso)
        except OSError:
            return {"ok": False, "message": "无法解析 ISO 路径"}
        if not os.path.isfile(iso_real):
            return {"ok": False, "message": f"ISO 文件不存在: {iso}"}
        cfg_vm = load_vm_cfg()
        allowed_dirs = cfg_vm.get("iso_dirs") or VM_DEFAULT_ISO_DIRS
        if not any(iso_real.startswith(d.rstrip("/") + "/")
                   for d in allowed_dirs):
            return {"ok": False,
                    "message": "ISO 必须位于 " + " / ".join(allowed_dirs)}
    disk_mode = (payload.get("disk_mode") or "new").strip().lower()
    if disk_mode not in ("new", "import", "none"):
        return {"ok": False, "message": "磁盘模式非法"}
    vnc_port = payload.get("vnc_port")
    if vnc_port in (None, "", 0, "0"):
        vnc_port = _alloc_vnc_port()
        if vnc_port is None:
            return {"ok": False, "message": "无可用 VNC 端口"}
    else:
        try:
            vnc_port = int(vnc_port)
        except (TypeError, ValueError):
            return {"ok": False, "message": "VNC 端口非法"}
        if not (VNC_PORT_MIN <= vnc_port <= VNC_PORT_MAX):
            return {"ok": False,
                    "message": f"VNC 端口需在 {VNC_PORT_MIN}-{VNC_PORT_MAX}"}
        if vnc_port in _vm_used_vnc_ports():
            return {"ok": False, "message": f"VNC 端口 {vnc_port} 已被占用"}
    vnc_pass = (payload.get("vnc_password") or "").strip()
    if vnc_pass and not _RE_VM_VNCPWD.match(vnc_pass):
        return {"ok": False, "message": "VNC 密码需 4-8 位"}
    os_variant = (payload.get("os_variant") or "").strip()
    if os_variant and not _RE_VM_OSVAR.match(os_variant):
        return {"ok": False, "message": "OS 类型标识非法"}
    base_dir = _vm_storage_dir()
    vm_dir = _vm_dir(name)
    disk_path = _vm_disk_path(name)
    try:
        base_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(base_dir, 0o755)
        vm_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(vm_dir, 0o755)
    except OSError as e:
        return {"ok": False, "message": f"创建虚拟机目录失败: {e}"}
    disk_arg_str: Optional[str] = None
    rollback_src: Optional[Path] = None
    if disk_mode == "new":
        if disk_path.exists():
            return {"ok": False, "message": f"磁盘已存在: {disk_path}"}
        try:
            disk_size = int(payload.get("disk_size", 20))
        except (TypeError, ValueError):
            return {"ok": False, "message": "磁盘容量非法"}
        if not (1 <= disk_size <= 4096):
            return {"ok": False, "message": "磁盘容量需在 1-4096 GB"}
        # 预先创建 qcow2 磁盘，避免 virt-install 的 path=+size= 参数冲突
        ok_q, out_q, err_q = run_cmd(
            ["qemu-img", "create", "-f", "qcow2",
             str(disk_path), f"{disk_size}G"], timeout=120)
        if not ok_q:
            try:
                if disk_path.exists():
                    disk_path.unlink()
            except OSError:
                pass
            return {"ok": False,
                    "message": f"创建磁盘失败: {(err_q or out_q).strip()}"}
        try:
            os.chmod(disk_path, 0o644)
        except OSError:
            pass
        disk_arg_str = f"path={disk_path},format=qcow2,bus=virtio"
    elif disk_mode == "import":
        src = (payload.get("import_path") or "").strip()
        if not src:
            return {"ok": False, "message": "请提供要导入的 QCOW2 文件路径"}
        if not src.startswith("/"):
            return {"ok": False, "message": "导入路径必须为绝对路径"}
        try:
            src_path = Path(src).resolve()
        except OSError:
            return {"ok": False, "message": "无法解析导入路径"}
        if not src_path.is_file():
            return {"ok": False, "message": f"文件不存在: {src}"}
        if src_path.suffix.lower() not in (".qcow2", ".qcow"):
            return {"ok": False, "message": "仅支持 .qcow2 / .qcow 磁盘文件"}
        ok, out, err = run_cmd(
            ["qemu-img", "info", "--output=json", str(src_path)],
            timeout=15)
        if not ok:
            return {"ok": False,
                    "message": f"无效的磁盘文件: {(err or out)[:200]}"}
        try:
            meta = json.loads(out)
            fmt = (meta.get("format") or "").lower()
            if fmt not in ("qcow2", "qcow"):
                return {"ok": False,
                        "message": f"磁盘格式需为 qcow2/qcow，检测到 {fmt}"}
        except json.JSONDecodeError:
            pass
        same = False
        try:
            same = disk_path.exists() and src_path.samefile(disk_path)
        except OSError:
            same = False
        if not same:
            try:
                if disk_path.exists():
                    disk_path.unlink()
                shutil.move(str(src_path), str(disk_path))
                rollback_src = src_path
                os.chmod(disk_path, 0o644)
            except (OSError, shutil.Error) as e:
                return {"ok": False, "message": f"移动磁盘文件失败: {e}"}
        disk_arg_str = f"path={disk_path},format=qcow2,bus=virtio"
    _ensure_libvirtd()
    graphics = f"vnc,port={vnc_port},listen=0.0.0.0"
    if vnc_pass:
        graphics += f",password={vnc_pass}"
    args = [
        "virt-install",
        "--connect", "qemu:///system",
        "--name", name,
        "--memory", str(memory),
        "--vcpus", str(vcpu),
        "--cpu", "host-passthrough",
        "--network", f"bridge={bridge},model=virtio",
        "--graphics", graphics,
        "--video", "qxl",
        "--os-variant", os_variant or "generic",
        "--noautoconsole",
        "--wait", "0",
    ]
    if disk_arg_str:
        args += ["--disk", disk_arg_str]
    if iso_real:
        args += ["--cdrom", iso_real]
    elif disk_mode == "import":
        args += ["--import"]
    else:
        args += ["--boot", "hd,menu=on"]
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        _vm_rollback_disk(disk_mode, disk_path, rollback_src, vm_dir)
        return {"ok": False, "message": "virt-install 执行超时"}
    except OSError as e:
        _vm_rollback_disk(disk_mode, disk_path, rollback_src, vm_dir)
        return {"ok": False, "message": str(e)}
    if p.returncode != 0:
        _vm_rollback_disk(disk_mode, disk_path, rollback_src, vm_dir)
        msg = (p.stderr or p.stdout or "").strip()[-1500:]
        return {"ok": False, "message": f"创建失败: {msg}"}
    audit("vm-create",
          f"name={name} vcpu={vcpu} mem={memory} disk_mode={disk_mode} "
          f"vnc={vnc_port} iso={iso_real or '-'}")
    return {
        "ok": True,
        "message": (f"虚拟机 {name} 已创建（VNC 端口 {vnc_port}，"
                    f"磁盘目录 {vm_dir}）"),
        "vm": vm_info(name),
        "vnc_port": vnc_port,
        "storage_dir": str(vm_dir),
        "note": "VNC 端口未自动放行，可在详情中手动开放",
    }

def vm_action(name: str, action: str) -> dict:
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    if not _RE_VM_NAME.match(name or ""):
        return {"ok": False, "message": "虚拟机名称非法"}
    if not shutil.which("virsh"):
        return {"ok": False, "message": "未安装 virsh"}
    cmd_map = {
        "start":         ["start"],
        "shutdown":      ["shutdown"],
        "destroy":       ["destroy"],
        "reboot":        ["reboot"],
        "reset":         ["reset"],
        "suspend":       ["suspend"],
        "resume":        ["resume"],
        "autostart-on":  ["autostart"],
        "autostart-off": ["autostart", "--disable"],
    }
    if action not in cmd_map:
        return {"ok": False, "message": "不支持的操作"}
    _ensure_libvirtd()
    ok, out, err = _virsh(cmd_map[action] + [name], timeout=30)
    if not ok:
        return {"ok": False, "message": (err or out or "操作失败").strip()}
    audit("vm-action", f"name={name} action={action}")
    return {"ok": True, "message": (out or "完成").strip(),
            "vm": vm_info(name)}

def vm_delete(name: str, remove_disks: bool = False) -> dict:
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    if not _RE_VM_NAME.match(name or ""):
        return {"ok": False, "message": "虚拟机名称非法"}
    info = vm_info(name)
    if not info:
        return {"ok": False, "message": "虚拟机不存在"}
    if info.get("running"):
        return {"ok": False, "message": "请先关闭虚拟机后再删除"}
    ok, out, err = _virsh(["undefine", name, "--nvram"], timeout=30)
    if not ok:
        ok, out, err = _virsh(["undefine", name], timeout=30)
    if not ok:
        return {"ok": False, "message": (err or out or "删除失败").strip()}
    removed = []
    if remove_disks:
        try:
            base = _vm_storage_dir().resolve()
        except OSError:
            base = _vm_storage_dir()
        for d in info.get("disks", []):
            if d.get("device") != "disk":
                continue
            p = d.get("path") or ""
            if not p:
                continue
            pp = Path(p)
            try:
                pp_resolved = pp.resolve()
            except OSError:
                continue
            try:
                pp_resolved.relative_to(base)
            except ValueError:
                continue
            try:
                pp.unlink()
                removed.append(str(pp))
                try:
                    pp.parent.rmdir()
                except OSError:
                    pass
            except OSError:
                pass
    vnc_port = info.get("vnc_port")
    if vnc_port:
        try:
            _vm_open_vnc_in_firewall(name, vnc_port, False)
        except Exception:
            pass
    audit("vm-delete", f"name={name} remove_disks={remove_disks}")
    return {"ok": True, "message": "已删除虚拟机",
            "removed_disks": removed}

# === END OF PART 2 ===
# ============================================================
# 虚拟机编辑 / 磁盘 / ISO
# ============================================================
def _vm_edit_xml(name: str, edit_func) -> Tuple[bool, str]:
    ok, xml_str, err = _virsh(["dumpxml", name], timeout=5)
    if not ok:
        return False, err or "读取 XML 失败"
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_str)
    except Exception as e:
        return False, f"XML 解析失败: {e}"
    try:
        edit_func(root)
    except Exception as e:
        return False, f"XML 修改失败: {e}"
    new_xml = ET.tostring(root, encoding="unicode")
    tmp = Path("/tmp") / f"netrouter-vm-{name}-{os.getpid()}.xml"
    try:
        tmp.write_text(new_xml, encoding="utf-8")
    except OSError as e:
        return False, f"临时文件写入失败: {e}"
    try:
        ok2, out2, err2 = _virsh(["define", str(tmp)], timeout=10)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    if not ok2:
        return False, (err2 or out2 or "define 失败").strip()
    return True, new_xml

def vm_update_resources(name: str, vcpu: Optional[int] = None,
                        memory_mb: Optional[int] = None) -> dict:
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    if not _RE_VM_NAME.match(name or ""):
        return {"ok": False, "message": "虚拟机名称非法"}
    info = vm_info(name)
    if not info:
        return {"ok": False, "message": "虚拟机不存在"}
    running = bool(info.get("running"))
    changes = []
    if vcpu is not None:
        try:
            vcpu = int(vcpu)
        except (TypeError, ValueError):
            return {"ok": False, "message": "vCPU 非法"}
        if not (1 <= vcpu <= 64):
            return {"ok": False, "message": "vCPU 范围 1-64"}
        ok, out, err = _virsh(
            ["setvcpus", name, str(vcpu), "--config", "--maximum"], timeout=10)
        if not ok:
            return {"ok": False,
                    "message": f"设置 vCPU 最大值失败: {(err or out).strip()}"}
        args = ["setvcpus", name, str(vcpu), "--config"]
        if running:
            args.append("--live")
        ok, out, err = _virsh(args, timeout=10)
        if not ok:
            return {"ok": False,
                    "message": f"设置 vCPU 失败: {(err or out).strip()}"}
        changes.append(f"vCPU={vcpu}")
    if memory_mb is not None:
        try:
            memory_mb = int(memory_mb)
        except (TypeError, ValueError):
            return {"ok": False, "message": "内存非法"}
        if not (128 <= memory_mb <= 262144):
            return {"ok": False, "message": "内存范围 128-262144 MB"}
        mem_kb = memory_mb * 1024
        ok, out, err = _virsh(
            ["setmaxmem", name, str(mem_kb), "--config"], timeout=10)
        if not ok:
            return {"ok": False,
                    "message": f"设置最大内存失败: {(err or out).strip()}"}
        args = ["setmem", name, str(mem_kb), "--config"]
        if running:
            args.append("--live")
        ok, out, err = _virsh(args, timeout=10)
        if not ok:
            return {"ok": False,
                    "message": f"设置内存失败: {(err or out).strip()}"}
        changes.append(f"内存={memory_mb}MB")
    if not changes:
        return {"ok": False, "message": "无修改"}
    audit("vm-update-resources", f"name={name} {','.join(changes)}")
    return {"ok": True,
            "message": "已更新：" + ", ".join(changes),
            "vm": vm_info(name)}

def vm_update_vnc(name: str, port=None, listen=None, password=None) -> dict:
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    if not _RE_VM_NAME.match(name or ""):
        return {"ok": False, "message": "虚拟机名称非法"}
    info = vm_info(name)
    if not info:
        return {"ok": False, "message": "虚拟机不存在"}
    new_port = None
    port_specified = port is not None
    if port_specified:
        s = str(port).strip()
        if s in ("", "0", "auto"):
            new_port = None
        else:
            try:
                new_port = int(s)
            except (TypeError, ValueError):
                return {"ok": False, "message": "VNC 端口非法"}
            if not (VNC_PORT_MIN <= new_port <= VNC_PORT_MAX):
                return {"ok": False,
                        "message": f"VNC 端口需在 {VNC_PORT_MIN}-{VNC_PORT_MAX}"}
            if (new_port != info.get("vnc_port")
                    and new_port in _vm_used_vnc_ports()):
                return {"ok": False,
                        "message": f"端口 {new_port} 已被占用"}
    new_listen = None
    listen_specified = listen is not None
    if listen_specified:
        s = str(listen).strip()
        if not s:
            new_listen = ""
        else:
            if not _valid_ip(s) and s not in ("0.0.0.0", "::"):
                return {"ok": False, "message": "VNC 监听地址非法"}
            new_listen = s
    new_pass = None
    pwd_specified = password is not None
    if pwd_specified:
        s = str(password).strip()
        if not s:
            new_pass = ""
        else:
            if not _RE_VM_VNCPWD.match(s):
                return {"ok": False, "message": "VNC 密码需 4-8 位"}
            new_pass = s
    if not (port_specified or listen_specified or pwd_specified):
        return {"ok": False, "message": "无修改"}
    state = {"done": False}
    def edit(root):
        for g in root.iter("graphics"):
            if g.get("type") != "vnc":
                continue
            if port_specified:
                if new_port is None:
                    g.set("port", "-1")
                    g.set("autoport", "yes")
                else:
                    g.set("port", str(new_port))
                    if "autoport" in g.attrib:
                        del g.attrib["autoport"]
            if listen_specified:
                if new_listen:
                    g.set("listen", new_listen)
                else:
                    g.attrib.pop("listen", None)
            if pwd_specified:
                if new_pass:
                    g.set("passwd", new_pass)
                else:
                    g.attrib.pop("passwd", None)
            state["done"] = True
            break
    ok, msg = _vm_edit_xml(name, edit)
    if not ok:
        return {"ok": False, "message": msg}
    if not state["done"]:
        return {"ok": False, "message": "XML 中未找到 VNC 图形设备"}
    audit("vm-update-vnc",
          f"name={name} port={new_port} listen={new_listen} "
          f"pwd={'set' if new_pass else 'none'}")
    return {"ok": True,
            "message": "VNC 配置已更新（重启虚拟机后生效）",
            "vm": vm_info(name)}

def vm_attach_disk(name: str, size_gb: int, bus: str = "virtio") -> dict:
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    if not _RE_VM_NAME.match(name or ""):
        return {"ok": False, "message": "虚拟机名称非法"}
    info = vm_info(name)
    if not info:
        return {"ok": False, "message": "虚拟机不存在"}
    try:
        size_gb = int(size_gb)
    except (TypeError, ValueError):
        return {"ok": False, "message": "磁盘容量非法"}
    if not (1 <= size_gb <= 4096):
        return {"ok": False, "message": "磁盘容量需在 1-4096 GB"}
    if bus not in ("virtio", "scsi", "sata", "ide"):
        bus = "virtio"
    used = {d.get("target") for d in info.get("disks", []) if d.get("target")}
    prefix = {"virtio": "vd", "scsi": "sd", "sata": "sd", "ide": "hd"}[bus]
    target = None
    for letter in "bcdefghijklmnopqrstu":
        t = f"{prefix}{letter}"
        if t not in used:
            target = t
            break
    if not target:
        return {"ok": False, "message": "无可用磁盘槽位"}
    vm_dir = _vm_dir(name)
    try:
        vm_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(vm_dir, 0o755)
    except OSError as e:
        return {"ok": False, "message": f"目录创建失败: {e}"}
    disk_file = vm_dir / f"{name}-{target}.qcow2"
    if disk_file.exists():
        return {"ok": False, "message": f"磁盘文件已存在: {disk_file}"}
    ok, out, err = run_cmd(
        ["qemu-img", "create", "-f", "qcow2",
         str(disk_file), f"{size_gb}G"], timeout=60)
    if not ok:
        return {"ok": False,
                "message": f"创建磁盘失败: {(err or out).strip()}"}
    try:
        os.chmod(disk_file, 0o644)
    except OSError:
        pass
    ok, out, err = _virsh([
        "attach-disk", name, str(disk_file), target,
        "--persistent", "--subdriver", "qcow2", "--targetbus", bus,
    ], timeout=15)
    if not ok:
        try:
            disk_file.unlink()
        except OSError:
            pass
        return {"ok": False, "message": f"挂载失败: {(err or out).strip()}"}
    audit("vm-attach-disk",
          f"name={name} target={target} size={size_gb}G bus={bus}")
    return {"ok": True,
            "message": f"已添加磁盘 {target}（{size_gb} GB）",
            "target": target, "path": str(disk_file),
            "vm": vm_info(name)}

def vm_attach_iso(name: str, iso_path: str) -> dict:
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    if not _RE_VM_NAME.match(name or ""):
        return {"ok": False, "message": "虚拟机名称非法"}
    info = vm_info(name)
    if not info:
        return {"ok": False, "message": "虚拟机不存在"}
    if not iso_path:
        return {"ok": False, "message": "请提供 ISO 路径"}
    try:
        iso_real = os.path.realpath(iso_path)
    except OSError:
        return {"ok": False, "message": "路径解析失败"}
    if not iso_real.lower().endswith(".iso"):
        return {"ok": False, "message": "仅支持 .iso 文件"}
    if not os.path.isfile(iso_real):
        return {"ok": False, "message": f"文件不存在: {iso_real}"}
    cfg_vm = load_vm_cfg()
    allowed = cfg_vm.get("iso_dirs") or VM_DEFAULT_ISO_DIRS
    if not any(iso_real.startswith(d.rstrip("/") + "/") for d in allowed):
        return {"ok": False, "message": "ISO 必须位于 " + " / ".join(allowed)}
    used_cdrom = set()
    for d in info.get("disks", []):
        if d.get("device") == "cdrom" and d.get("target"):
            used_cdrom.add(d["target"])
    target = None
    for t in ("sda", "sdb", "sdc", "sdd", "hdc"):
        if t not in used_cdrom:
            target = t
            break
    if not target:
        return {"ok": False, "message": "无可用 CD-ROM 槽位"}
    ok, out, err = _virsh([
        "attach-disk", name, iso_real, target,
        "--type", "cdrom", "--mode", "readonly", "--persistent",
    ], timeout=15)
    if not ok:
        return {"ok": False, "message": f"挂载失败: {(err or out).strip()}"}
    audit("vm-attach-iso", f"name={name} iso={iso_real} target={target}")
    return {"ok": True,
            "message": f"已挂载 ISO 到 {target}",
            "target": target, "path": iso_real,
            "vm": vm_info(name)}

def vm_detach(name: str, target: str) -> dict:
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    if not _RE_VM_NAME.match(name or ""):
        return {"ok": False, "message": "虚拟机名称非法"}
    if not re.match(r"^[a-zA-Z]{1,4}\d{0,3}$", target or ""):
        return {"ok": False, "message": "目标设备名非法"}
    info = vm_info(name)
    if not info:
        return {"ok": False, "message": "虚拟机不存在"}
    disk = None
    for d in info.get("disks", []):
        if d.get("target") == target:
            disk = d
            break
    if not disk:
        return {"ok": False, "message": f"未找到目标设备 {target}"}
    running = bool(info.get("running"))
    if disk.get("device") == "cdrom":
        ok, out, err = _virsh(
            ["change-media", name, target, "--eject", "--config"],
            timeout=15)
        if not ok:
            ok, out, err = _virsh(
                ["detach-disk", name, target, "--persistent"], timeout=15)
        if not ok:
            return {"ok": False, "message": f"卸载失败: {(err or out).strip()}"}
        audit("vm-detach-iso", f"name={name} target={target}")
        return {"ok": True, "message": f"已卸载 {target}",
                "vm": vm_info(name)}
    args = ["detach-disk", name, target, "--persistent"]
    if running:
        args.append("--live")
    ok, out, err = _virsh(args, timeout=15)
    if not ok:
        return {"ok": False, "message": f"卸载失败: {(err or out).strip()}"}
    disk_path = disk.get("path") or ""
    file_removed = None
    try:
        base = _vm_storage_dir().resolve()
        pp = Path(disk_path).resolve()
        pp.relative_to(base)
        try:
            if pp.parent == _vm_dir(name).resolve():
                if pp.exists():
                    pp.unlink()
                    file_removed = str(pp)
        except OSError:
            pass
    except (ValueError, OSError):
        pass
    audit("vm-detach-disk",
          f"name={name} target={target} file={'deleted' if file_removed else 'kept'}")
    return {"ok": True,
            "message": f"已移除磁盘 {target}"
                       + ("（磁盘文件已删除）" if file_removed else ""),
            "removed_file": file_removed,
            "vm": vm_info(name)}

# ============================================================
# 磁盘管理
# ============================================================
FSTAB_FILE = Path("/etc/fstab")
FSTAB_BACKUP = Path("/etc/fstab.netrouter.bak")
FSTAB_MARKER_BEGIN = "# >>> NetRouter Managed Mounts BEGIN (do not edit)"
FSTAB_MARKER_END = "# <<< NetRouter Managed Mounts END"
_MOUNT_BASES = ("/mnt", "/media")
_MKFS_CMDS = {
    "ext4":  ["mkfs.ext4", "-F"],
    "xfs":   ["mkfs.xfs", "-f"],
    "btrfs": ["mkfs.btrfs", "-f"],
    "vfat":  ["mkfs.vfat", "-I"],
    "exfat": ["mkfs.exfat"],
    "ntfs":  ["mkfs.ntfs", "-F", "-Q"],
    "f2fs":  ["mkfs.f2fs", "-f"],
}

def _system_disks():
    sys_disks = set()
    ok, out, _ = run_cmd(["lsblk", "-J", "-o", "NAME,MOUNTPOINT,TYPE"],
                         timeout=8)
    if ok and out:
        try:
            data = json.loads(out)
            def is_sys_mp(mp):
                if not mp:
                    return False
                return (mp == "/" or mp.startswith("/boot")
                        or mp in ("/usr", "/var"))
            def walk(node, top):
                if is_sys_mp(node.get("mountpoint") or ""):
                    sys_disks.add(top)
                for c in node.get("children", []) or []:
                    walk(c, top)
            for d in data.get("blockdevices", []):
                if d.get("type") == "disk":
                    walk(d, d.get("name", ""))
            if sys_disks:
                return sys_disks
        except (json.JSONDecodeError, TypeError):
            pass
    for line in (read_file("/proc/mounts", "") or "").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        dev, mp = parts[0], parts[1]
        if not dev.startswith("/dev/"):
            continue
        if mp == "/" or mp.startswith("/boot"):
            base = os.path.basename(dev)
            m = re.match(r"^(.*?)(?:p?\d+)$", base)
            sys_disks.add(m.group(1) if m else base)
    return sys_disks

def _device_is_system(device_path):
    if not device_path:
        return True
    try:
        name = os.path.basename(device_path.rstrip("/"))
    except Exception:
        return True
    sys_disks = _system_disks()
    if name in sys_disks:
        return True
    ok, out, _ = run_cmd(["lsblk", "-n", "-o", "PKNAME", device_path],
                         timeout=5)
    if ok:
        for line in out.splitlines():
            p = line.strip()
            if p and p in sys_disks:
                return True
    return False

def _device_uuid(device):
    ok, out, _ = run_cmd(["blkid", "-s", "UUID", "-o", "value", device],
                         timeout=5)
    return out.strip() if ok else ""

def _device_fstype(device):
    ok, out, _ = run_cmd(["blkid", "-s", "TYPE", "-o", "value", device],
                         timeout=5)
    return out.strip() if ok else ""

def _read_fstab():
    try:
        return FSTAB_FILE.read_text(encoding="utf-8")
    except OSError:
        return ""

def _parse_fstab_line(s):
    parts = s.split()
    if len(parts) < 4:
        return None
    return {
        "spec": parts[0], "mountpoint": parts[1],
        "fstype": parts[2], "options": parts[3],
        "dump": parts[4] if len(parts) > 4 else "0",
        "passno": parts[5] if len(parts) > 5 else "0",
    }

def _load_fstab_all():
    entries = {}
    for line in _read_fstab().splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        e = _parse_fstab_line(s)
        if e:
            entries[e["spec"]] = e
    return entries

def _load_fstab_managed():
    entries = {}
    in_block = False
    for line in _read_fstab().splitlines():
        s = line.strip()
        if s == FSTAB_MARKER_BEGIN:
            in_block = True
            continue
        if s == FSTAB_MARKER_END:
            in_block = False
            continue
        if not in_block or not s or s.startswith("#"):
            continue
        e = _parse_fstab_line(s)
        if e:
            entries[e["spec"]] = e
    return entries

def _strip_managed_block(content):
    out = []
    in_block = False
    for line in content.splitlines():
        s = line.strip()
        if s == FSTAB_MARKER_BEGIN:
            in_block = True
            continue
        if s == FSTAB_MARKER_END:
            in_block = False
            continue
        if in_block:
            continue
        out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return ("\n".join(out) + "\n") if out else ""

def _serialize_fstab_managed(entries):
    if not entries:
        return ""
    lines = [FSTAB_MARKER_BEGIN]
    for e in entries:
        lines.append(
            f"{e['spec']}  {e['mountpoint']}  {e['fstype']}  "
            f"{e['options']}  {e.get('dump', '0')}  {e.get('passno', '2')}"
        )
    lines.append(FSTAB_MARKER_END)
    return "\n".join(lines) + "\n"

def _verify_fstab(content):
    if not content.strip():
        return True, ""
    tmp = Path(f"/tmp/netrouter-fstab-verify-{os.getpid()}")
    try:
        tmp.write_text(content, encoding="utf-8")
        try:
            os.chmod(tmp, 0o644)
        except OSError:
            pass
    except OSError as e:
        return False, str(e)
    try:
        ok, out, err = run_cmd(
            ["findmnt", "--verify", "--tab-file", str(tmp)], timeout=15)
        if ok:
            return True, ""
        msg = (err or out or "").strip()
        low = msg.lower()
        if ("unknown option" in low or "unrecognized option" in low
                or "invalid option" in low):
            ok2, out2, err2 = run_cmd(
                ["mount", "-a", "--fake", "-T", str(tmp)], timeout=15)
            if ok2:
                return True, ""
            return False, (err2 or out2 or "fstab 校验失败").strip()
        return False, msg or "fstab 校验失败"
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass

def _write_fstab_safely(new_content):
    ok, err = _verify_fstab(new_content)
    if not ok:
        return {"ok": False,
                "message": f"fstab 校验失败（已阻止写入，防止开机异常）: {err}"}
    try:
        if FSTAB_FILE.exists() and not FSTAB_BACKUP.exists():
            shutil.copy2(str(FSTAB_FILE), str(FSTAB_BACKUP))
    except OSError:
        pass
    try:
        _atomic_write(FSTAB_FILE, new_content, 0o644)
    except OSError as e:
        return {"ok": False, "message": f"写入 fstab 失败: {e}"}
    return {"ok": True, "message": "fstab 已更新"}

def _validate_mount_point(mp):
    if not mp:
        return "挂载点为空"
    if not mp.startswith("/"):
        return "挂载点必须为绝对路径"
    if ".." in mp:
        return "挂载点不能包含 .."
    if len(mp) > 200:
        return "挂载点过长"
    if not re.match(r"^/[A-Za-z0-9._\-/]+$", mp):
        return "挂载点含非法字符"
    if not any(mp == b or mp.startswith(b + "/") for b in _MOUNT_BASES):
        return f"挂载点必须在 {' 或 '.join(_MOUNT_BASES)} 下"
    return None

def list_block_devices():
    ok, out, _ = run_cmd(
        ["lsblk", "-J", "-b", "-o",
         "NAME,PATH,TYPE,SIZE,FSTYPE,LABEL,UUID,MOUNTPOINT,RO,RM,MODEL"],
        timeout=10)
    if not ok or not out:
        return {"devices": [], "system_disks": [],
                "error": "lsblk 执行失败，请确认已安装 util-linux"}
    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        return {"devices": [], "system_disks": [],
                "error": f"lsblk JSON 解析失败: {e}"}
    sys_disks = _system_disks()
    fstab_all = _load_fstab_all()
    fstab_managed = _load_fstab_managed()
    def _bool(v):
        return str(v or "0").lower() in ("1", "true", "yes")
    def entry(node, is_sys_parent):
        name = node.get("name") or ""
        is_sys = is_sys_parent or (name in sys_disks)
        uuid = node.get("uuid") or ""
        label = node.get("label") or ""
        path = node.get("path") or f"/dev/{name}"
        specs = []
        if uuid:
            specs.append(f"UUID={uuid}")
        if label:
            specs.append(f"LABEL={label}")
        specs.append(path)
        in_fstab = any(s in fstab_all for s in specs)
        in_managed = any(s in fstab_managed for s in specs)
        e = {
            "name": name, "path": path,
            "type": node.get("type") or "",
            "size": int(node.get("size") or 0),
            "fstype": node.get("fstype") or "",
            "label": label, "uuid": uuid,
            "mountpoint": node.get("mountpoint") or "",
            "ro": _bool(node.get("ro")),
            "rm": _bool(node.get("rm")),
            "model": (node.get("model") or "").strip(),
            "is_system": is_sys,
            "in_fstab": in_fstab,
            "in_managed": in_managed,
            "children": [],
        }
        for c in node.get("children", []) or []:
            e["children"].append(entry(c, is_sys))
        return e
    devices = [entry(d, False) for d in data.get("blockdevices", [])]
    return {"devices": devices, "system_disks": sorted(sys_disks)}

def disk_mount(device, mountpoint, fstype="", options="",
               auto=False, passno=2):
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    if not _RE_DEV_PATH.match(device or ""):
        return {"ok": False, "message": "设备路径非法"}
    if not os.path.exists(device):
        return {"ok": False, "message": f"设备不存在: {device}"}
    if _device_is_system(device):
        return {"ok": False, "message": "系统盘设备禁止操作"}
    err = _validate_mount_point(mountpoint)
    if err:
        return {"ok": False, "message": err}
    if fstype and not _RE_FS_TYPE.match(fstype):
        return {"ok": False, "message": f"不支持的文件系统: {fstype}"}
    try:
        Path(mountpoint).mkdir(parents=True, exist_ok=True)
        os.chmod(mountpoint, 0o755)
    except OSError as e:
        return {"ok": False, "message": f"创建挂载点失败: {e}"}
    ok, out, _ = run_cmd(["findmnt", "-n", "-S", device], timeout=5)
    if ok and out.strip():
        # findmnt -n -S 输出：TARGET(挂载点) SOURCE FSTYPE OPTIONS
        current = out.strip().split("\n")[0].split()[0]
        if current == mountpoint:
            return {"ok": False, "message": f"已在 {mountpoint} 挂载"}
        return {"ok": False, "message": f"设备已挂载到 {current}，请先卸载"}
    cmd = ["mount"]
    if fstype:
        cmd += ["-t", fstype]
    if options:
        cmd += ["-o", options]
    cmd += [device, mountpoint]
    ok, out, err2 = run_cmd(cmd, timeout=30)
    if not ok:
        try:
            os.rmdir(mountpoint)
        except OSError:
            pass
        return {"ok": False,
                "message": f"挂载失败: {(err2 or out).strip()[-500:]}"}
    if not auto:
        audit("disk-mount", f"{device} -> {mountpoint} (temp)")
        return {"ok": True, "message": "已挂载（临时，重启后失效）"}
    uuid = _device_uuid(device)
    spec = f"UUID={uuid}" if uuid else device
    if not fstype:
        fstype = _device_fstype(device) or "auto"
    opts = options or "defaults"
    if "nofail" not in opts.split(","):
        opts = opts + ",nofail"
    entries = _load_fstab_managed()
    entries[spec] = {
        "spec": spec, "mountpoint": mountpoint,
        "fstype": fstype, "options": opts,
        "dump": "0", "passno": str(passno),
    }
    content = _strip_managed_block(_read_fstab())
    block = _serialize_fstab_managed(list(entries.values()))
    new_content = content.rstrip() + ("\n\n" if content.strip() else "") + block
    r = _write_fstab_safely(new_content)
    if not r["ok"]:
        try:
            run_cmd(["umount", mountpoint], timeout=15)
        except Exception:
            pass
        return {"ok": False, "message": r["message"] + "（已回滚挂载）"}
    audit("disk-auto-mount", f"{device} -> {mountpoint} spec={spec}")
    return {"ok": True, "message": f"已挂载并写入 fstab（{spec}）"}

def disk_umount(device_or_mp, remove_fstab=True):
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    target = (device_or_mp or "").strip()
    if not target:
        return {"ok": False, "message": "参数为空"}
    if target.startswith("/dev/"):
        if not _RE_DEV_PATH.match(target):
            return {"ok": False, "message": "设备路径非法"}
        device = target
        ok, out, _ = run_cmd(["findmnt", "-n", "-S", device], timeout=5)
        if not ok or not out.strip():
            return {"ok": False, "message": "设备未挂载"}
        # findmnt -n -S 输出：TARGET SOURCE FSTYPE OPTIONS，TARGET 在首列
        mp = out.strip().split("\n")[0].split()[0]
    else:
        err = _validate_mount_point(target)
        if err:
            return {"ok": False, "message": err}
        mp = target
    ok, out, err2 = run_cmd(["umount", mp], timeout=30)
    if not ok:
        return {"ok": False,
                "message": f"卸载失败: {(err2 or out).strip()[-500:]}"}
    if remove_fstab:
        entries = _load_fstab_managed()
        if entries:
            new_entries = {}
            removed = []
            for spec, e in entries.items():
                if e["mountpoint"] == mp:
                    removed.append(spec)
                    continue
                new_entries[spec] = e
            if removed:
                content = _strip_managed_block(_read_fstab())
                block = _serialize_fstab_managed(list(new_entries.values()))
                new_content = (
                    content.rstrip() + ("\n\n" if content.strip() else "")
                    + block
                ) if block else content
                r = _write_fstab_safely(new_content)
                if not r["ok"]:
                    audit("disk-umount", f"{mp} (fstab 更新失败)")
                    return {"ok": True,
                            "message": f"已卸载，但 fstab 更新失败: {r['message']}"}
    audit("disk-umount", f"{mp}")
    return {"ok": True, "message": f"已卸载 {mp}"}

def disk_format(device, fstype, label=""):
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    if not _RE_DEV_PATH.match(device or ""):
        return {"ok": False, "message": "设备路径非法"}
    if not os.path.exists(device):
        return {"ok": False, "message": f"设备不存在: {device}"}
    if _device_is_system(device):
        return {"ok": False, "message": "系统盘设备禁止格式化"}
    if fstype not in _MKFS_CMDS:
        return {"ok": False, "message": f"不支持的文件系统: {fstype}"}
    if label and not _RE_LABEL.match(label):
        return {"ok": False, "message": "标签非法（1-16 位字母数字 _ - .）"}
    ok, out, _ = run_cmd(["findmnt", "-n", "-S", device], timeout=5)
    if ok and out.strip():
        return {"ok": False, "message": "设备已挂载，请先卸载"}
    tool = _MKFS_CMDS[fstype][0]
    if not shutil.which(tool):
        return {"ok": False,
                "message": f"缺少工具 {tool}，请安装对应软件包"}
    cmd = list(_MKFS_CMDS[fstype])
    if label:
        if fstype in ("ext4", "xfs", "btrfs", "f2fs", "ntfs"):
            cmd += ["-L", label]
        elif fstype in ("vfat", "exfat"):
            cmd += ["-n", label[:11]]
    cmd.append(device)
    ok, out, err = run_cmd(cmd, timeout=600)
    if not ok:
        msg = (err or out or "").strip()[-800:]
        return {"ok": False, "message": f"格式化失败: {msg}"}
    audit("disk-format", f"{device} fstype={fstype} label={label}")
    return {"ok": True, "message": f"已格式化为 {fstype}"}

# ============================================================
# 文件共享 Samba
# ============================================================
SAMBA_CONF = Path("/etc/samba/smb.conf")
SAMBA_BACKUP = Path("/etc/samba/smb.conf.netrouter.bak")
SAMBA_MARKER_BEGIN = "# >>> NetRouter Shares BEGIN (do not edit)"
SAMBA_MARKER_END = "# <<< NetRouter Shares END"

def _read_samba_conf():
    try:
        return SAMBA_CONF.read_text(encoding="utf-8")
    except OSError:
        return ""

def _load_samba_shares():
    shares = []
    in_block = False
    cur = None
    for line in _read_samba_conf().splitlines():
        s = line.strip()
        if s == SAMBA_MARKER_BEGIN:
            in_block = True
            continue
        if s == SAMBA_MARKER_END:
            in_block = False
            if cur:
                shares.append(cur)
                cur = None
            continue
        if not in_block:
            continue
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        m = re.match(r"^\[([^\]]+)\]$", s)
        if m:
            if cur:
                shares.append(cur)
            cur = {"name": m.group(1), "params": {}}
            continue
        if cur and "=" in s:
            k, v = s.split("=", 1)
            cur["params"][k.strip().lower()] = v.strip()
    return shares

def _strip_samba_block(content):
    out = []
    in_block = False
    for line in content.splitlines():
        s = line.strip()
        if s == SAMBA_MARKER_BEGIN:
            in_block = True
            continue
        if s == SAMBA_MARKER_END:
            in_block = False
            continue
        if in_block:
            continue
        out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return ("\n".join(out) + "\n") if out else ""

def _serialize_samba_shares(shares):
    if not shares:
        return ""
    lines = [SAMBA_MARKER_BEGIN, ""]
    for sh in shares:
        lines.append(f"[{sh['name']}]")
        for k, v in sh["params"].items():
            lines.append(f"   {k} = {v}")
        lines.append("")
    lines.append(SAMBA_MARKER_END)
    return "\n".join(lines) + "\n"

def _verify_samba_conf(content):
    if not content.strip():
        return True, ""
    tmp = Path(f"/tmp/netrouter-smb-verify-{os.getpid()}.conf")
    try:
        tmp.write_text(content, encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
    except OSError as e:
        return False, str(e)
    try:
        ok, out, err = run_cmd(["testparm", "-s", str(tmp)], timeout=15)
        if ok:
            return True, ""
        return False, (err or out or "").strip()[-800:]
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass

def _write_samba_conf_safely(new_content):
    ok, err = _verify_samba_conf(new_content)
    if not ok:
        return {"ok": False, "message": f"smb.conf 校验失败: {err}"}
    try:
        if SAMBA_CONF.exists() and not SAMBA_BACKUP.exists():
            shutil.copy2(str(SAMBA_CONF), str(SAMBA_BACKUP))
    except OSError:
        pass
    try:
        SAMBA_CONF.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(SAMBA_CONF, new_content, 0o644)
    except OSError as e:
        return {"ok": False, "message": f"写入失败: {e}"}
    return {"ok": True, "message": "smb.conf 已更新"}

def samba_status():
    installed = bool(shutil.which("smbd")) and SAMBA_CONF.exists()
    running = False
    if installed:
        ok, out, _ = run_cmd(["systemctl", "is-active", "smbd"], timeout=3)
        running = ok and out.strip() == "active"
    shares = _load_samba_shares() if installed else []
    return {
        "installed": installed, "running": running,
        "conf_path": str(SAMBA_CONF), "shares": shares,
    }

def samba_install():
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    r = _apt_install(list(SAMBA_PKGS))
    if r.get("ok"):
        run_cmd(["systemctl", "enable", "smbd"], timeout=10)
        run_cmd(["systemctl", "start", "smbd"], timeout=15)
        audit("samba-install", "installed")
    return r

def _linux_group_exists(group: str) -> bool:
    if not group:
        return False
    ok, _, _ = run_cmd(["getent", "group", group], timeout=5)
    return ok


def _list_system_users() -> list:
    """列出可用于 Samba 的普通系统用户（UID 1000-59999）。"""
    ok, out, _ = run_cmd(["getent", "passwd"], timeout=10)
    if not ok:
        return []
    users = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        try:
            uid = int(parts[2])
        except ValueError:
            continue
        if not (1000 <= uid < 60000):
            continue
        name = parts[0]
        if name in SAMBA_PROTECTED_USERS:
            continue
        users.append({
            "name": name,
            "uid": uid,
            "home": parts[5],
            "shell": parts[6],
        })
    users.sort(key=lambda x: x["name"])
    return users


def _list_system_groups() -> list:
    """列出普通系统用户组（GID 1000-59999）。"""
    ok, out, _ = run_cmd(["getent", "group"], timeout=10)
    if not ok:
        return []
    groups = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) < 3:
            continue
        try:
            gid = int(parts[2])
        except ValueError:
            continue
        if not (1000 <= gid < 60000):
            continue
        groups.append({
            "name": parts[0],
            "gid": gid,
            "members": parts[3].split(",") if len(parts) > 3 and parts[3] else [],
        })
    groups.sort(key=lambda x: x["name"])
    return groups


def samba_add_share(payload, overwrite=False):
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    name = (payload.get("name") or "").strip()
    if not _RE_SHARE_NAME.match(name):
        return {"ok": False, "message": "共享名非法（1-32 位字母数字 _ - .）"}
    path = (payload.get("path") or "").strip()
    if not path.startswith("/") or ".." in path or len(path) > 255:
        return {"ok": False, "message": "路径非法"}
    try:
        p = Path(path).resolve()
    except OSError:
        return {"ok": False, "message": "路径解析失败"}
    if not p.is_dir():
        return {"ok": False, "message": f"目录不存在: {path}"}
    readonly = bool(payload.get("readonly", False))
    guest = bool(payload.get("guest", False))
    browseable = bool(payload.get("browseable", True))
    comment = (payload.get("comment") or "")[:64]
    valid_users = (payload.get("valid_users") or "").strip()

    # ---- force user / force group（新增）----
    force_user = (payload.get("force_user") or "").strip()
    force_group = (payload.get("force_group") or "").strip()
    if force_user:
        if not _RE_LINUX_USER.match(force_user):
            return {"ok": False, "message": "force user 用户名非法（小写字母或 _ 开头）"}
        if not _linux_user_exists(force_user):
            return {"ok": False,
                    "message": f"force user 系统用户不存在: {force_user}"}
    if force_group:
        if not _RE_LINUX_GROUP.match(force_group):
            return {"ok": False, "message": "force group 组名非法（小写字母或 _ 开头）"}
        if not _linux_group_exists(force_group):
            return {"ok": False,
                    "message": f"force group 系统组不存在: {force_group}"}

    shares = _load_samba_shares()
    existing = next((s for s in shares if s["name"] == name), None)
    if existing and not overwrite:
        return {"ok": False, "message": f"共享名已存在: {name}（可勾选覆盖）"}

    params = {
        "path": str(p),
        "browseable": "yes" if browseable else "no",
        "read only": "yes" if readonly else "no",
        "guest ok": "yes" if guest else "no",
        "create mask": "0664",
        "directory mask": "0775",
    }
    if comment:
        params["comment"] = comment
    if valid_users and not guest:
        params["valid users"] = valid_users
    if force_user:
        params["force user"] = force_user
    if force_group:
        params["force group"] = force_group

    if existing:
        existing["params"] = params
    else:
        shares.append({"name": name, "params": params})

    content = _strip_samba_block(_read_samba_conf())
    block = _serialize_samba_shares(shares)
    new_content = content.rstrip() + ("\n\n" if content.strip() else "") + block
    r = _write_samba_conf_safely(new_content)
    if not r["ok"]:
        return r
    run_cmd(["systemctl", "reload", "smbd"], timeout=15)
    action = "update-share" if existing else "add-share"
    audit(f"samba-{action}",
          f"name={name} path={p} force_user={force_user or '-'} "
          f"force_group={force_group or '-'}")
    return {"ok": True,
            "message": (f"已更新共享 {name}" if existing
                        else f"已添加共享 {name}")}

def samba_remove_share(name):
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    if not _RE_SHARE_NAME.match(name or ""):
        return {"ok": False, "message": "共享名非法"}
    shares = _load_samba_shares()
    new_shares = [s for s in shares if s["name"] != name]
    if len(new_shares) == len(shares):
        return {"ok": False, "message": f"共享不存在: {name}"}
    content = _strip_samba_block(_read_samba_conf())
    block = _serialize_samba_shares(new_shares)
    new_content = (
        content.rstrip() + ("\n\n" if content.strip() else "") + block
    ) if block else content
    r = _write_samba_conf_safely(new_content)
    if not r["ok"]:
        return r
    run_cmd(["systemctl", "reload", "smbd"], timeout=15)
    audit("samba-remove-share", f"name={name}")
    return {"ok": True, "message": f"已删除共享 {name}"}

# ============================================================
# Samba 全局 Guest 策略
# ============================================================
GUEST_POLICY_VALUES = ("Never", "Bad User", "Bad Password", "Bad Uid")

GUEST_POLICY_DESC = {
    "Never":        "认证失败立即拒绝（Windows 会弹窗重输）",
    "Bad User":     "用户名不存在时降级为 Guest",
    "Bad Password": "密码错误时降级为 Guest",
    "Bad Uid":      "UID 无效时降级为 Guest",
}


def _normalize_guest_policy(value: str) -> str:
    """把 'bad user' / 'BadUser' / 'bad_user' 归一化为 'Bad User'。"""
    if not value:
        return "Bad User"
    s = value.strip()
    # 直接匹配已规范的形式
    for v in GUEST_POLICY_VALUES:
        if s.lower() == v.lower():
            return v
    # 兼容无空格/下划线写法
    compact = s.lower().replace(" ", "").replace("_", "")
    lookup = {"never": "Never", "baduser": "Bad User",
              "badpassword": "Bad Password", "baduid": "Bad Uid"}
    return lookup.get(compact, "Bad User")


def samba_get_guest_policy() -> dict:
    """读取当前 [global] 段里的 map to guest 值。"""
    content = _read_samba_conf()
    policy = "Bad User"  # Samba 默认
    in_global = False
    for line in content.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            in_global = (s.lower() == "[global]")
            continue
        if in_global and s.lower().startswith("map to guest"):
            if "=" in s:
                policy = _normalize_guest_policy(s.split("=", 1)[1])
                break
    return {
        "policy": policy,
        "description": GUEST_POLICY_DESC.get(policy, ""),
        "options": [{"value": v, "desc": GUEST_POLICY_DESC[v]}
                    for v in GUEST_POLICY_VALUES],
    }


def samba_set_guest_policy(policy: str) -> dict:
    """修改 [global] 段的 map to guest 参数。"""
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    policy = _normalize_guest_policy(policy)
    if policy not in GUEST_POLICY_VALUES:
        return {"ok": False,
                "message": f"策略非法，可选：{', '.join(GUEST_POLICY_VALUES)}"}

    content = _read_samba_conf()
    if not content:
        return {"ok": False, "message": "无法读取 /etc/samba/smb.conf"}

    lines = content.split("\n")
    new_lines = []
    in_global = False
    replaced = False
    global_seen = False
    global_end_idx = -1  # 记录 [global] 段结束位置

    for idx, line in enumerate(lines):
        s = line.strip()
        # 遇到新的段头
        if s.startswith("[") and s.endswith("]"):
            if in_global and not replaced:
                # 上一个 [global] 段结束但没找到 map to guest
                # 在段头之前插入一行
                new_lines.append(f"\tmap to guest = {policy}")
                replaced = True
            in_global = (s.lower() == "[global]")
            if in_global:
                global_seen = True
            new_lines.append(line)
            continue
        # 在 [global] 段内
        if in_global and s.lower().startswith("map to guest"):
            indent = line[:len(line) - len(line.lstrip())] or "\t"
            new_lines.append(f"{indent}map to guest = {policy}")
            replaced = True
            continue
        new_lines.append(line)

    # [global] 在文件末尾且没有 map to guest
    if global_seen and in_global and not replaced:
        new_lines.append(f"\tmap to guest = {policy}")
        replaced = True

    # 完全没有 [global] 段（极端情况）
    if not global_seen:
        new_lines.insert(0, f"[global]\n\tmap to guest = {policy}")

    new_content = "\n".join(new_lines)
    r = _write_samba_conf_safely(new_content)
    if not r["ok"]:
        return r
    run_cmd(["systemctl", "reload", "smbd"], timeout=15)
    audit("samba-guest-policy", f"policy={policy}")
    return {"ok": True,
            "message": f"已设置 map to guest = {policy}"
                       + ("（Windows 认证失败将重新弹窗）"
                          if policy == "Never" else "")}

# ============================================================
# Samba 账户管理
# ============================================================
_RE_LINUX_USER = re.compile(r"^[a-z_][a-z0-9_\-]{0,31}$")
SAMBA_PROTECTED_USERS = {
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp",
    "mail", "news", "uucp", "proxy", "www-data", "backup", "list",
    "irc", "gnats", "nobody", "systemd-network", "systemd-resolve",
    "systemd-timesync", "messagebus", "syslog", "_apt",
}


def _linux_user_exists(user: str) -> bool:
    ok, _, _ = run_cmd(["getent", "passwd", user], timeout=5)
    return ok


def _samba_user_exists(user: str) -> bool:
    if not shutil.which("pdbedit"):
        return False
    ok, out, _ = run_cmd(["pdbedit", "-L"], timeout=10)
    if not ok:
        return False
    for line in out.splitlines():
        if line.split(":", 1)[0].strip() == user:
            return True
    return False


def _samba_all_users() -> list:
    if not shutil.which("pdbedit"):
        return []
    ok, out, _ = run_cmd(["pdbedit", "-L"], timeout=10)
    if not ok:
        return []
    users = []
    for line in out.splitlines():
        name = line.split(":", 1)[0].strip()
        if name:
            users.append(name)
    return users


def samba_user_info(user: str) -> dict:
    info = {
        "name": user,
        "enabled": True,
        "has_system_account": _linux_user_exists(user),
        "uid": "",
        "fullname": "",
        "last_change": "",
        "in_shares": [],
    }
    if shutil.which("pdbedit"):
        ok, out, _ = run_cmd(["pdbedit", "-Lv", "-u", user], timeout=10)
        if ok and out:
            for line in out.splitlines():
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                k, v = k.strip().lower(), v.strip()
                if k == "unix username":
                    info["uid"] = v
                elif k == "account flags":
                    flags = v.replace("[", "").replace("]", "").strip()
                    info["enabled"] = "D" not in flags
                elif k == "full name":
                    info["fullname"] = v
                elif k in ("password last set", "pwd last set"):
                    info["last_change"] = v
    try:
        shares = _load_samba_shares()
        for sh in shares:
            vu = sh["params"].get("valid users", "")
            if user in vu.split():
                info["in_shares"].append(sh["name"])
    except Exception:
        pass
    return info


def samba_users_list() -> dict:
    if not shutil.which("pdbedit"):
        return {"installed": False, "users": []}
    users = [samba_user_info(n) for n in _samba_all_users()]
    users.sort(key=lambda x: x["name"])
    return {"installed": True, "users": users}


def samba_user_add(payload: dict) -> dict:
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    if not shutil.which("smbpasswd"):
        return {"ok": False, "message": "未安装 Samba（需 samba-common-bin）"}

    name = (payload.get("name") or "").strip()
    if not _RE_LINUX_USER.match(name):
        return {"ok": False,
                "message": "用户名非法（小写字母/数字/下划线/减号，1-32 位，"
                           "字母或 _ 开头）"}
    if name in SAMBA_PROTECTED_USERS:
        return {"ok": False, "message": f"禁止操作系统/保护账户: {name}"}

    password = payload.get("password") or ""
    if not (6 <= len(password) <= 128):
        return {"ok": False, "message": "密码长度需 6-128 位"}
    if "\n" in password or "\r" in password:
        return {"ok": False, "message": "密码不能包含换行"}

    create_sys = bool(payload.get("create_system", True))

    if _samba_user_exists(name):
        return {"ok": False, "message": f"Samba 用户已存在: {name}"}

    # 创建系统账户（无家目录、不可登录）
    if not _linux_user_exists(name):
        if not create_sys:
            return {"ok": False,
                    "message": f"系统用户 {name} 不存在，且未允许自动创建"}
        shell = payload.get("system_shell") or "/usr/sbin/nologin"
        if shell not in ("/usr/sbin/nologin", "/bin/false",
                         "/bin/bash", "/bin/sh"):
            return {"ok": False, "message": "系统 shell 非法"}
        ok2, o2, e2 = run_cmd(
            ["useradd", "-M", "-s", shell, name], timeout=15)
        if not ok2:
            return {"ok": False,
                    "message": f"创建系统用户失败: {(e2 or o2).strip()}"}
        audit("samba-user-sysadd", f"name={name} shell={shell}")

    ok3, o3, e3 = run_cmd(
        ["smbpasswd", "-s", "-a", name],
        timeout=15,
        input_data=f"{password}\n{password}\n",
    )
    if not ok3:
        return {"ok": False,
                "message": f"设置 Samba 密码失败: {(e3 or o3).strip()}"}

    audit("samba-user-add", f"name={name}")
    return {"ok": True, "message": f"已添加 Samba 用户 {name}",
            "user": samba_user_info(name)}


def samba_user_set_password(name: str, password: str) -> dict:
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    if not _RE_LINUX_USER.match(name or ""):
        return {"ok": False, "message": "用户名非法"}
    if name in SAMBA_PROTECTED_USERS:
        return {"ok": False, "message": f"禁止操作保护账户: {name}"}
    if not (6 <= len(password) <= 128):
        return {"ok": False, "message": "密码长度需 6-128 位"}
    if "\n" in password or "\r" in password:
        return {"ok": False, "message": "密码不能包含换行"}
    if not _samba_user_exists(name):
        return {"ok": False, "message": f"Samba 用户不存在: {name}"}

    ok, o, e = run_cmd(
        ["smbpasswd", "-s", name],
        timeout=15,
        input_data=f"{password}\n{password}\n",
    )
    if not ok:
        return {"ok": False,
                "message": f"修改密码失败: {(e or o).strip()}"}
    audit("samba-user-passwd", f"name={name}")
    return {"ok": True, "message": f"已修改 {name} 的 Samba 密码"}


def samba_user_toggle(name: str, enable: bool) -> dict:
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    if not _RE_LINUX_USER.match(name or ""):
        return {"ok": False, "message": "用户名非法"}
    if name in SAMBA_PROTECTED_USERS:
        return {"ok": False, "message": f"禁止操作保护账户: {name}"}
    if not _samba_user_exists(name):
        return {"ok": False, "message": f"Samba 用户不存在: {name}"}

    flag = "--enable" if enable else "--disable"
    ok, o, e = run_cmd(["pdbedit", "-u", name, flag], timeout=15)
    if not ok:
        return {"ok": False,
                "message": f"{'启用' if enable else '禁用'}失败: "
                           f"{(e or o).strip()}"}
    audit("samba-user-toggle", f"name={name} enable={enable}")
    return {"ok": True,
            "message": f"已{'启用' if enable else '禁用'}用户 {name}"}


def samba_user_remove(name: str, remove_system: bool = False) -> dict:
    if not is_root():
        return {"ok": False, "message": "需要 root 权限"}
    if not _RE_LINUX_USER.match(name or ""):
        return {"ok": False, "message": "用户名非法"}
    if name in SAMBA_PROTECTED_USERS:
        return {"ok": False, "message": f"禁止删除保护账户: {name}"}

    # 若被共享引用，拒绝删除
    try:
        shares = _load_samba_shares()
        used_by = []
        for sh in shares:
            vu = sh["params"].get("valid users", "")
            if name in vu.split():
                used_by.append(sh["name"])
        if used_by:
            return {"ok": False,
                    "message": "用户正被以下共享引用，请先移除引用: "
                               + ", ".join(used_by)}
    except Exception:
        pass

    ok, o, e = run_cmd(["pdbedit", "-x", "-u", name], timeout=15)
    if not ok:
        ok2, o2, e2 = run_cmd(["smbpasswd", "-x", name], timeout=15)
        if not ok2:
            return {"ok": False,
                    "message": f"删除 Samba 用户失败: "
                               f"{(e or o or e2 or o2).strip()}"}

    sys_removed = False
    if remove_system and _linux_user_exists(name):
        ok3, _, _ = run_cmd(["userdel", name], timeout=15)
        sys_removed = ok3

    audit("samba-user-remove",
          f"name={name} sys_removed={sys_removed}")
    return {"ok": True,
            "message": f"已删除 Samba 用户 {name}"
                       + ("（及系统账户）" if sys_removed else ""),
            "system_removed": sys_removed}

# ============================================================
# 实时流量采样
# ============================================================
class TrafficSampler:
    def __init__(self):
        self._prev: dict = {}

    def sample(self) -> dict:
        now = time.monotonic()
        net = Path("/sys/class/net")
        result = {}
        if not net.exists():
            return result
        for name in os.listdir(net):
            if name == "lo":
                continue
            try:
                rx = int((net / name / "statistics/rx_bytes").read_text())
                tx = int((net / name / "statistics/tx_bytes").read_text())
            except OSError:
                continue
            prev = self._prev.get(name)
            if prev:
                dt = now - prev[0]
                if dt > 0:
                    result[name] = {
                        "rx": max(0.0, (rx - prev[1]) / dt),
                        "tx": max(0.0, (tx - prev[2]) / dt),
                        "rx_total": rx, "tx_total": tx,
                    }
            self._prev[name] = (now, rx, tx)
        return result

# ============================================================
# 测速常量
# ============================================================
SPEEDTEST_MAX_DOWNLOAD = 1 * 1024 * 1024 * 1024
SPEEDTEST_MAX_UPLOAD = 128 * 1024 * 1024
_SPEED_CHUNK = os.urandom(256 * 1024)

# ============================================================
# 登录失败限速
# ============================================================
_login_fail: Dict[str, list] = {}
_login_fail_lock = threading.Lock()

def _login_rate_limited(ip: str) -> bool:
    now = time.time()
    with _login_fail_lock:
        arr = _login_fail.setdefault(ip, [])
        arr[:] = [t for t in arr if now - t < 60]
        return len(arr) >= 5

def _login_record_fail(ip: str):
    now = time.time()
    with _login_fail_lock:
        _login_fail.setdefault(ip, []).append(now)

def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host or "?"
    return "?"

# ============================================================
# FastAPI 应用
# ============================================================
app = FastAPI(title="NetRouter", version="2.0.0",
              docs_url=None, redoc_url=None, openapi_url=None)
_bearer = HTTPBearer(auto_error=False)

def require_auth(creds: HTTPAuthorizationCredentials = Depends(_bearer)):
    if creds is None or not decode_token(creds.credentials):
        raise HTTPException(status_code=401, detail="未登录或登录已过期")
    return True

PUBLIC_EXACT = {"/", "/favicon.ico", "/api/auth/login"}

class AuthMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path in PUBLIC_EXACT:
            await self.app(scope, receive, send)
            return
        if path.startswith("/api/"):
            headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                       for k, v in (scope.get("headers") or [])}
            hdr = headers.get("authorization", "")
            token = hdr[7:] if hdr.lower().startswith("bearer ") else ""
            if not decode_token(token):
                resp = JSONResponse({"detail": "未登录"}, status_code=401)
                await resp(scope, receive, send)
                return
        await self.app(scope, receive, send)

app.add_middleware(AuthMiddleware)

@app.post("/api/auth/login")
async def api_login(body: dict, request: Request):
    ip = _client_ip(request)
    if _login_rate_limited(ip):
        await asyncio.sleep(0.5)
        raise HTTPException(429, "尝试次数过多，请稍后再试")
    pwd = (body or {}).get("password", "")
    rec = load_password_record()
    if not rec or not verify_password(pwd, rec):
        _login_record_fail(ip)
        await asyncio.sleep(0.3)
        audit("login-fail", f"ip={ip}")
        raise HTTPException(status_code=401, detail="密码错误")
    audit("login-ok", f"ip={ip}")
    return {"token": create_token("admin"), "expires_in": TOKEN_TTL}

@app.get("/api/auth/me")
def api_me(_=Depends(require_auth)):
    return {"user": "admin"}

@app.post("/api/auth/change-password")
def api_change_password(body: dict, _=Depends(require_auth)):
    old_pwd = (body or {}).get("old_password", "")
    new_pwd = (body or {}).get("new_password", "")
    if not old_pwd or not new_pwd:
        raise HTTPException(400, "请填写旧密码和新密码")
    if len(new_pwd) < 6:
        raise HTTPException(400, "新密码至少 6 位")
    rec = load_password_record()
    if not rec:
        raise HTTPException(400, "密码文件不存在")
    if not verify_password(old_pwd, rec):
        raise HTTPException(401, "旧密码错误")
    _atomic_write(PW_FILE, json.dumps(hash_password(new_pwd)), 0o600)
    _bump_token_version()
    audit("change-password", "")
    return {"ok": True, "message": "密码已修改，所有会话已失效"}

@app.get("/api/stats")
def api_stats(_=Depends(require_auth)):
    mem, swap = get_memory()
    ifaces = []
    for name in list_net_interfaces():
        info = get_interface_info(name)
        if info:
            ifaces.append(info)
    return {
        "system": get_system_info(),
        "cpu_percent": get_cpu_usage(),
        "memory": mem, "swap": swap,
        "disks": get_disks(),
        "wireguard": get_wireguard(),
        "wifi_ap": get_wifi_ap_info(),
        "wifi_clients": get_wifi_ap_clients(),
        "dhcp_leases": get_dhcp_leases(),
        "interfaces": ifaces,
        "bridges": get_bridge_info(),
        "sensors": _read_sensors(),
        "timestamp": time.time(),
        "timestamp_str": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

@app.get("/api/system/processes")
def api_processes(sort: str = "cpu", limit: int = 20,
                  _=Depends(require_auth)):
    return process_list(limit=limit, sort=sort)

@app.get("/api/router/config")
def api_router_cfg(_=Depends(require_auth)):
    cfg = load_router_cfg()
    safe = dict(cfg)
    for k in ("wg_private_key", "wan_pppoe_pass", "wg_server_private_key"):
        if safe.get(k):
            safe[k] = "***"
    return {"config": safe, "root": is_root()}

@app.post("/api/router/config")
def api_router_cfg_save(body: dict, _=Depends(require_auth)):
    with _cfg_lock:
        cur = load_router_cfg()
        for k in ("wg_private_key", "wan_pppoe_pass", "wg_server_private_key"):
            if body.get(k) == "***":
                body[k] = cur.get(k, "")
        cur.update(body or {})
        save_router_cfg(cur)
    audit("router-cfg-save", "")
    return {"ok": True}

@app.get("/api/router/detect")
def api_router_detect(_=Depends(require_auth)):
    return detect_router_interfaces()

@app.post("/api/router/apply")
def api_router_apply(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    with _cfg_lock:
        cfg = load_router_cfg()
        incoming = (body or {}).get("config", body or {})
        for k in ("wg_private_key", "wan_pppoe_pass", "wg_server_private_key"):
            if incoming.get(k) == "***":
                incoming[k] = cfg.get(k, "")
        cfg.update(incoming or {})
    install = bool((body or {}).get("install", False))
    apply_net = bool((body or {}).get("apply_network", True))
    return apply_router_config(cfg, install=install, apply_network=apply_net)

def _peer_public_view(p: dict) -> dict:
    return {k: v for k, v in p.items() if k != "private_key"}

@app.get("/api/wireguard/peers")
def api_wg_peers(_=Depends(require_auth)):
    return {"peers": [_peer_public_view(p) for p in load_wg_peers()]}

@app.post("/api/wireguard/peer/add")
def api_wg_peer_add(body: dict, _=Depends(require_auth)):
    with _cfg_lock:
        cfg = load_router_cfg()
        if cfg.get("wg_mode") != "server":
            raise HTTPException(400, "当前非服务器模式")
        peers = load_wg_peers()
        name = ((body or {}).get("name") or "").strip()
        if not name:
            name = f"peer-{len(peers) + 1}"
        if not re.match(r"^[A-Za-z0-9_.-]{1,64}$", name):
            raise HTTPException(400, "名称仅支持字母、数字、_ . -")
        if any(p["name"] == name for p in peers):
            raise HTTPException(400, "名称已存在")
        priv, pub = _gen_wg_keypair()
        if not priv:
            raise HTTPException(500, "生成密钥失败，请确认已安装 wireguard-tools")
        address = ((body or {}).get("address") or "").strip() \
            or _next_client_ip(cfg, peers)
        if not _RE_WG_ADDR.match(address):
            raise HTTPException(400, "地址格式非法（需 CIDR）")
        peer = {
            "id": secrets.token_urlsafe(8),
            "name": name,
            "private_key": priv, "public_key": pub,
            "preshared_key": _gen_wg_psk(),
            "address": address, "allowed_ips": address,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        peers.append(peer)
        save_wg_peers(peers)
    audit("wg-peer-add", f"name={name}")
    return {"ok": True, "peer": _peer_public_view(peer),
            "config": _peer_client_config(cfg, peer)}

@app.post("/api/wireguard/peer/remove")
def api_wg_peer_remove(body: dict, _=Depends(require_auth)):
    pid = (body or {}).get("id", "")
    with _cfg_lock:
        peers = load_wg_peers()
        new = [p for p in peers if p["id"] != pid]
        if len(new) == len(peers):
            raise HTTPException(404, "对端不存在")
        save_wg_peers(new)
    audit("wg-peer-remove", f"id={pid}")
    return {"ok": True}

@app.get("/api/wireguard/peer/{pid}/config")
def api_wg_peer_config(pid: str, _=Depends(require_auth)):
    if not re.match(r"^[A-Za-z0-9_\-]{1,64}$", pid or ""):
        raise HTTPException(400, "非法 ID")
    cfg = load_router_cfg()
    peer = next((p for p in load_wg_peers() if p["id"] == pid), None)
    if not peer:
        raise HTTPException(404, "对端不存在")
    return {"config": _peer_client_config(cfg, peer),
            "name": peer["name"]}

@app.get("/api/firewall/all")
def api_fw_all(_=Depends(require_auth)):
    return firewall_dump_all()

@app.post("/api/firewall/flush")
def api_fw_flush(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限")
    family = (body or {}).get("family", "")
    name = (body or {}).get("name", "")
    if not family or not name:
        raise HTTPException(400, "缺少 family 或 name")
    r = firewall_flush_table(family, name)
    audit("fw-flush", f"{family} {name} -> {r.get('ok')}")
    return r

@app.get("/api/firewall/zones")
def api_fw_zones_get(_=Depends(require_auth)):
    cfg = load_firewall_cfg()
    cfg["enabled"] = True
    return {"config": cfg}

@app.get("/api/firewall/interfaces")
def api_fw_ifaces(_=Depends(require_auth)):
    ifaces = []
    net_dir = "/sys/class/net"
    if os.path.isdir(net_dir):
        for name in sorted(os.listdir(net_dir)):
            if name == "lo":
                continue
            base = f"{net_dir}/{name}"
            ifaces.append({
                "name": name,
                "wireless": (os.path.isdir(f"{base}/wireless")
                             or os.path.isdir(f"{base}/phy80211")),
                "state": read_file(f"{base}/operstate", "?"),
                "carrier": read_int(f"{base}/carrier", 0) == 1,
            })
    return {"interfaces": ifaces}

@app.post("/api/firewall/zones")
def api_fw_zones_save(body: dict, _=Depends(require_auth)):
    cfg = _sanitize_fw_cfg(body or {})
    save_firewall_cfg(cfg)
    audit("fw-zone-save", "")
    return {"ok": True, "config": cfg}

@app.post("/api/firewall/apply-zones")
def api_fw_apply_zones(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    incoming = (body or {}).get("config") or body or {}
    cfg = _sanitize_fw_cfg(incoming)
    save_firewall_cfg(cfg)
    content = _write_nftables(load_router_cfg())
    try:
        _atomic_write(Path("/etc/nftables.conf"), content, 0o600)
    except OSError as e:
        return {"ok": False, "message": f"写入 /etc/nftables.conf 失败: {e}"}
    ok, out, err = run_cmd(["nft", "-f", "/etc/nftables.conf"], timeout=15)
    msg = (err or out or "").strip() or ("已应用" if ok else "应用失败")
    if ok:
        run_cmd(["systemctl", "enable", "nftables"], timeout=10)
    audit("fw-apply", f"ok={ok}")
    return {"ok": ok, "message": msg, "config": cfg}

@app.get("/api/network/routes")
def api_routes(_=Depends(require_auth)):
    return route_list()

@app.get("/api/network/neighbors")
def api_neighbors(_=Depends(require_auth)):
    return neighbor_list()

@app.post("/api/tools/ping")
def api_ping(body: dict, _=Depends(require_auth)):
    host = (body or {}).get("host", "")
    try:
        count = int((body or {}).get("count", 4))
    except (TypeError, ValueError):
        count = 4
    return tools_ping(host, count)

@app.post("/api/tools/dns")
def api_dns(body: dict, _=Depends(require_auth)):
    name = (body or {}).get("name", "")
    server = (body or {}).get("server", "")
    return tools_dns(name, server)

@app.get("/api/packages/router-essentials")
def api_pkg_router_essentials(_=Depends(require_auth)):
    return {"results": check_packages_status(ROUTER_ALL_PKGS)}

@app.post("/api/packages/install-router-essentials")
def api_pkg_install_router_essentials(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    pkgs = (body or {}).get("packages") or list(ROUTER_ALL_PKGS)
    pkgs = [p for p in pkgs if pkg_validate_name(p)]
    if not pkgs:
        raise HTTPException(400, "无有效包名")
    cmd = ["apt-get", "install", "-y"] + pkgs
    task_id = pkg_run_task(cmd, "安装路由功能必备: " + ", ".join(pkgs))
    audit("pkg-install-essentials", ", ".join(pkgs))
    return {"task_id": task_id}

@app.get("/api/packages/search")
def api_pkg_search(q: str = "", _=Depends(require_auth)):
    return {"results": pkg_search(q)}

@app.get("/api/packages/installed")
def api_pkg_installed(_=Depends(require_auth)):
    return {"results": pkg_list_installed()}

@app.post("/api/packages/install")
def api_pkg_install(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    pkgs = (body or {}).get("packages") or []
    if not isinstance(pkgs, list):
        raise HTTPException(400, "packages 必须是数组")
    err = pkg_validate_list(pkgs)
    if err:
        raise HTTPException(400, err)
    cmd = ["apt-get", "install", "-y"] + pkgs
    task_id = pkg_run_task(cmd, "安装: " + ", ".join(pkgs))
    audit("pkg-install", ", ".join(pkgs))
    return {"task_id": task_id}

@app.post("/api/packages/remove")
def api_pkg_remove(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    pkgs = (body or {}).get("packages") or []
    if not isinstance(pkgs, list):
        raise HTTPException(400, "packages 必须是数组")
    err = pkg_validate_list(pkgs)
    if err:
        raise HTTPException(400, err)
    cmd = ["apt-get", "remove", "-y"] + pkgs
    task_id = pkg_run_task(cmd, "卸载: " + ", ".join(pkgs))
    audit("pkg-remove", ", ".join(pkgs))
    return {"task_id": task_id}

@app.post("/api/packages/update")
def api_pkg_update(_=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    task_id = pkg_run_task(["apt-get", "update"], "更新软件包索引")
    audit("pkg-update", "")
    return {"task_id": task_id}

@app.post("/api/packages/upgrade")
def api_pkg_upgrade(_=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    task_id = pkg_run_task(["apt-get", "upgrade", "-y"], "升级系统软件包")
    audit("pkg-upgrade", "")
    return {"task_id": task_id}

@app.get("/api/packages/task/{task_id}")
def api_pkg_task(task_id: str, _=Depends(require_auth)):
    if not re.match(r"^[A-Za-z0-9_\-]{1,64}$", task_id or ""):
        raise HTTPException(400, "非法任务 ID")
    pkg_tasks_cleanup()
    t = pkg_task_get(task_id)
    if not t:
        raise HTTPException(404, "任务不存在")
    return t

@app.get("/api/packages/vm-essentials")
def api_pkg_vm_essentials(_=Depends(require_auth)):
    return {"results": check_packages_status(VM_PKGS, VM_PKG_DESC)}

@app.post("/api/packages/install-vm-essentials")
def api_pkg_install_vm_essentials(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    pkgs = (body or {}).get("packages") or list(VM_PKGS)
    pkgs = [p for p in pkgs if pkg_validate_name(p)]
    if not pkgs:
        raise HTTPException(400, "无有效包名")
    cmd = ["apt-get", "install", "-y"] + pkgs
    task_id = pkg_run_task(cmd, "安装虚拟机环境: " + ", ".join(pkgs))
    audit("pkg-install-vm", ", ".join(pkgs))
    return {"task_id": task_id}

@app.get("/api/packages/disk-essentials")
def api_pkg_disk_essentials(_=Depends(require_auth)):
    return {"results": check_packages_status(DISK_PKGS, DISK_PKG_DESC)}

@app.post("/api/packages/install-disk-essentials")
def api_pkg_install_disk_essentials(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    pkgs = (body or {}).get("packages") or list(DISK_PKGS)
    pkgs = [p for p in pkgs if pkg_validate_name(p)]
    if not pkgs:
        raise HTTPException(400, "无有效包名")
    cmd = ["apt-get", "install", "-y"] + pkgs
    task_id = pkg_run_task(cmd, "安装磁盘管理必备: " + ", ".join(pkgs))
    audit("pkg-install-disk", ", ".join(pkgs))
    return {"task_id": task_id}

@app.get("/api/packages/samba-essentials")
def api_pkg_samba_essentials(_=Depends(require_auth)):
    return {"results": check_packages_status(SAMBA_PKGS, SAMBA_PKG_DESC)}

@app.post("/api/packages/install-samba-essentials")
def api_pkg_install_samba_essentials(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    pkgs = (body or {}).get("packages") or list(SAMBA_PKGS)
    pkgs = [p for p in pkgs if pkg_validate_name(p)]
    if not pkgs:
        raise HTTPException(400, "无有效包名")
    cmd = ["apt-get", "install", "-y"] + pkgs
    task_id = pkg_run_task(cmd, "安装文件共享必备: " + ", ".join(pkgs))
    audit("pkg-install-samba", ", ".join(pkgs))
    return {"task_id": task_id}

@app.get("/api/vm/status")
def api_vm_status(_=Depends(require_auth)):
    cfg = load_vm_cfg()
    return {
        "kvm": vm_kvm_available(),
        "root": is_root(),
        "default_bridge": "br-lan",
        "settings": cfg,
        "vnc_range": [VNC_PORT_MIN, VNC_PORT_MAX],
    }

@app.get("/api/vm/settings")
def api_vm_settings_get(_=Depends(require_auth)):
    return {"settings": load_vm_cfg(),
            "kvm": vm_kvm_available(),
            "root": is_root()}

@app.post("/api/vm/settings")
def api_vm_settings_save(body: dict, _=Depends(require_auth)):
    payload = (body or {}).get("settings") or body or {}
    sd = str(payload.get("storage_dir") or "").strip()
    if not sd or not sd.startswith("/"):
        raise HTTPException(400, "存储目录必须为绝对路径")
    if ".." in sd:
        raise HTTPException(400, "存储目录不能包含 ..")
    try:
        Path(sd).mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise HTTPException(400, f"无法创建目录: {e}")
    saved = save_vm_cfg(payload)
    audit("vm-settings", f"storage_dir={saved['storage_dir']}")
    return {"ok": True, "settings": saved}

@app.get("/api/vm/list")
def api_vm_list(_=Depends(require_auth)):
    return {"vms": vm_list()}

@app.get("/api/vm/isos")
def api_vm_isos(_=Depends(require_auth)):
    return {"isos": vm_list_isos(),
            "dirs": load_vm_cfg().get("iso_dirs") or VM_DEFAULT_ISO_DIRS}

@app.get("/api/vm/browse-qcow2")
def api_vm_browse_qcow2(dir: str = "", _=Depends(require_auth)):
    return {"files": vm_browse_qcow2(dir or "")}

@app.get("/api/vm/detail/{name}")
def api_vm_detail(name: str, _=Depends(require_auth)):
    info = vm_info(name)
    if not info:
        raise HTTPException(404, "虚拟机不存在")
    ok, out, _ = _virsh(["dumpxml", name], timeout=5)
    info["xml"] = out if ok else ""
    return info

@app.post("/api/vm/create")
def api_vm_create(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    with _vm_lock:
        return vm_create(body or {})

@app.post("/api/vm/action")
def api_vm_action(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    name = (body or {}).get("name", "")
    action = (body or {}).get("action", "")
    with _vm_lock:
        return vm_action(name, action)

@app.post("/api/vm/delete")
def api_vm_delete(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    name = (body or {}).get("name", "")
    remove_disks = bool((body or {}).get("remove_disks", False))
    with _vm_lock:
        return vm_delete(name, remove_disks)

@app.post("/api/vm/vnc/firewall")
def api_vm_vnc_firewall(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限")
    name = (body or {}).get("name", "")
    enable = bool((body or {}).get("enable", True))
    info = vm_info(name)
    if not info:
        raise HTTPException(404, "虚拟机不存在")
    port = info.get("vnc_port")
    if not port:
        raise HTTPException(400, "该虚拟机未配置 VNC 端口")
    r = _vm_open_vnc_in_firewall(name, port, enable)
    audit("vm-vnc-fw", f"name={name} port={port} enable={enable}")
    return r

@app.post("/api/vm/update-resources")
def api_vm_update_resources(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限")
    name = (body or {}).get("name", "")
    vcpu = (body or {}).get("vcpu")
    memory = (body or {}).get("memory")
    with _vm_lock:
        return vm_update_resources(name, vcpu=vcpu, memory_mb=memory)

@app.post("/api/vm/update-vnc")
def api_vm_update_vnc(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限")
    body = body or {}
    name = body.get("name", "")
    kwargs = {}
    if "vnc_port" in body:
        kwargs["port"] = body["vnc_port"]
    if "vnc_listen" in body:
        kwargs["listen"] = body["vnc_listen"]
    if "vnc_password" in body:
        kwargs["password"] = body["vnc_password"]
    with _vm_lock:
        return vm_update_vnc(name, **kwargs)

@app.post("/api/vm/attach-disk")
def api_vm_attach_disk(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限")
    body = body or {}
    with _vm_lock:
        return vm_attach_disk(
            body.get("name", ""),
            body.get("size_gb", 0),
            body.get("bus", "virtio"),
        )

@app.post("/api/vm/attach-iso")
def api_vm_attach_iso(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限")
    body = body or {}
    with _vm_lock:
        return vm_attach_iso(body.get("name", ""), body.get("iso", ""))

@app.post("/api/vm/detach")
def api_vm_detach(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限")
    body = body or {}
    with _vm_lock:
        return vm_detach(body.get("name", ""), body.get("target", ""))

@app.get("/api/disk/list")
def api_disk_list(_=Depends(require_auth)):
    return list_block_devices()

@app.post("/api/disk/mount")
def api_disk_mount(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    body = body or {}
    try:
        passno = int(body.get("passno", 2))
    except (TypeError, ValueError):
        passno = 2
    return disk_mount(
        body.get("device", ""),
        body.get("mountpoint", ""),
        (body.get("fstype") or "").strip(),
        (body.get("options") or "").strip(),
        bool(body.get("auto", False)),
        passno,
    )

@app.post("/api/disk/umount")
def api_disk_umount(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    body = body or {}
    return disk_umount(
        body.get("target", ""),
        bool(body.get("remove_fstab", True)),
    )

@app.post("/api/disk/format")
def api_disk_format(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    body = body or {}
    return disk_format(
        body.get("device", ""),
        body.get("fstype", ""),
        (body.get("label") or "").strip(),
    )

@app.get("/api/samba/status")
def api_samba_status(_=Depends(require_auth)):
    return samba_status()

@app.post("/api/samba/install")
def api_samba_install(_=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    return samba_install()

@app.post("/api/samba/restart")
def api_samba_restart(_=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限")
    ok, out, err = run_cmd(["systemctl", "restart", "smbd"], timeout=20)
    audit("samba-restart", f"ok={ok}")
    return {"ok": ok,
            "message": (err or out or ("已重启" if ok else "失败")).strip()}

@app.get("/api/samba/guest-policy")
def api_samba_guest_policy_get(_=Depends(require_auth)):
    return samba_get_guest_policy()

@app.post("/api/samba/guest-policy")
def api_samba_guest_policy_set(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    policy = (body or {}).get("policy", "")
    return samba_set_guest_policy(policy)

@app.get("/api/samba/system-users")
def api_samba_system_users(_=Depends(require_auth)):
    return {
        "users": _list_system_users(),
        "groups": _list_system_groups(),
    }

@app.post("/api/samba/share/add")
def api_samba_add(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    body = body or {}
    overwrite = bool(body.get("overwrite", False))
    return samba_add_share(body, overwrite=overwrite)

@app.post("/api/samba/share/remove")
def api_samba_remove(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    return samba_remove_share((body or {}).get("name", ""))

@app.get("/api/samba/users")
def api_samba_users(_=Depends(require_auth)):
    return samba_users_list()

@app.post("/api/samba/users/add")
def api_samba_user_add(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    return samba_user_add(body or {})

@app.post("/api/samba/users/passwd")
def api_samba_user_passwd(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    body = body or {}
    return samba_user_set_password(
        body.get("name", ""), body.get("password", ""))

@app.post("/api/samba/users/toggle")
def api_samba_user_toggle(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    body = body or {}
    return samba_user_toggle(
        body.get("name", ""), bool(body.get("enable", True)))

@app.post("/api/samba/users/remove")
def api_samba_user_remove(body: dict, _=Depends(require_auth)):
    if not is_root():
        raise HTTPException(403, "需要 root 权限（请以 sudo 启动 NetRouter）")
    body = body or {}
    return samba_user_remove(
        body.get("name", ""), bool(body.get("remove_system", False)))

@app.get("/api/speedtest/ping")
def api_speedtest_ping(_=Depends(require_auth)):
    return Response(content=b'{"ok":true}', media_type="application/json")

@app.get("/api/speedtest/download")
def api_speedtest_download(size: int = 8388608, _=Depends(require_auth)):
    size = max(1, min(int(size), SPEEDTEST_MAX_DOWNLOAD))
    def gen():
        remaining = size
        chunk = _SPEED_CHUNK
        clen = len(chunk)
        while remaining > 0:
            if remaining >= clen:
                yield chunk
                remaining -= clen
            else:
                yield chunk[:remaining]
                remaining = 0
    headers = {
        "Cache-Control": "no-store",
        "Content-Encoding": "identity",
        "Content-Length": str(size),
    }
    return StreamingResponse(gen(),
                             media_type="application/octet-stream",
                             headers=headers)

@app.post("/api/speedtest/upload")
async def api_speedtest_upload(request: Request, _=Depends(require_auth)):
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > SPEEDTEST_MAX_UPLOAD:
            raise HTTPException(413, "payload too large")
    return {"received": total}

@app.websocket("/ws/traffic")
async def ws_traffic(ws: WebSocket, token: str = Query(None)):
    if not decode_token(token or ""):
        await ws.close(code=4401)
        return
    await ws.accept()
    sampler = TrafficSampler()
    sampler.sample()
    try:
        while True:
            await asyncio.sleep(1)
            await ws.send_json({"t": time.time(),
                                "ifaces": sampler.sample()})
    except WebSocketDisconnect:
        return
    except Exception:
        try:
            await ws.close()
        except Exception:
            pass

# === END OF PART 3 ===
# ============================================================
# 前端
# ============================================================
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetRouter</title>
<style>
:root{
  --bg:#0a0a0a; --bg-soft:#141414; --bg-card:#1a1a1a;
  --line:#2a2a2a; --fg:#f5f5f5; --fg-dim:#8a8a8a;
  --fg-dimmer:#4a4a4a; --accent:#ffffff; --danger:#ff4d4d;
  --warn:#f5b942; --ok:#4ade80; --purple:#bc8cff;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg);color:var(--fg);
  font-family:-apple-system,"Inter","SF Pro","Helvetica Neue",
  "PingFang SC","Microsoft YaHei",sans-serif;
  font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
.topbar{display:flex;align-items:center;height:56px;padding:0 24px;
  border-bottom:1px solid var(--line);background:var(--bg);
  position:sticky;top:0;z-index:10;flex-wrap:wrap;gap:12px}
.brand{font-weight:700;letter-spacing:.15em;margin-right:24px;font-size:15px}
.brand span{color:var(--fg-dimmer)}
nav{display:flex;gap:2px;flex:1;flex-wrap:wrap}
.tab{background:transparent;border:0;color:var(--fg-dim);
  padding:8px 14px;font-size:12px;letter-spacing:.05em;cursor:pointer;
  border-radius:2px;transition:color .12s,background .12s;font-family:inherit}
.tab:hover{color:var(--fg)}
.tab.active{color:var(--bg);background:var(--accent)}
.clock{color:var(--fg-dimmer);font-variant-numeric:tabular-nums;
  font-size:12px;letter-spacing:.1em}
main{padding:24px 24px 80px;max-width:1360px;margin:0 auto}
.view{display:none}
.view.active{display:block;animation:fade .15s ease}
@keyframes fade{from{opacity:0}to{opacity:1}}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));
  gap:1px;background:var(--line);border:1px solid var(--line);margin-bottom:16px}
.card{background:var(--bg-soft);padding:18px}
.card .label{font-size:11px;letter-spacing:.15em;color:var(--fg-dimmer);
  text-transform:uppercase;margin-bottom:10px;display:flex;align-items:center;gap:6px}
.card .value{font-size:22px;font-weight:600;font-variant-numeric:tabular-nums}
.card .sub{font-size:12px;color:var(--fg-dim);margin-top:4px;
  font-family:ui-monospace,"SF Mono",monospace}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;
  background:var(--fg-dimmer)}
.dot.up{background:var(--ok)}
.dot.down{background:var(--danger)}
.panel{background:var(--bg-soft);border:1px solid var(--line);
  padding:22px;margin-bottom:16px}
.panel h2{font-size:12px;font-weight:600;letter-spacing:.18em;
  text-transform:uppercase;color:var(--fg-dim);margin-bottom:18px;
  display:flex;align-items:center;gap:10px}
.panel h2 .hint{margin-left:auto;font-size:11px;color:var(--fg-dimmer);
  font-weight:400;letter-spacing:0;text-transform:none}
.split{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:900px){.split{grid-template-columns:1fr}}
label{display:flex;flex-direction:column;gap:6px;font-size:12px;
  color:var(--fg-dim);letter-spacing:.05em}
input,select,textarea{background:var(--bg);border:1px solid var(--line);
  color:var(--fg);padding:9px 12px;font-size:13px;font-family:inherit;
  border-radius:2px;outline:none;transition:border-color .12s;width:100%}
input:focus,select:focus,textarea:focus{border-color:var(--fg-dim)}
.form-row{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end}
.form-row>*{flex:1;min-width:110px}
.form-col{display:flex;flex-direction:column;gap:14px}
.actions{display:flex;gap:8px;margin-top:18px;flex-wrap:wrap}
.btn{background:var(--accent);color:var(--bg);border:1px solid var(--accent);
  padding:9px 18px;font-size:12px;letter-spacing:.1em;text-transform:uppercase;
  font-weight:600;cursor:pointer;border-radius:2px;transition:opacity .12s;
  font-family:inherit;white-space:nowrap}
.btn:hover:not(:disabled){opacity:.82}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn-inverse{background:transparent;color:var(--fg);border-color:var(--line)}
.btn-inverse:hover:not(:disabled){border-color:var(--fg-dim);opacity:1}
.btn-danger{background:transparent;color:var(--danger);border-color:var(--line)}
.btn-danger:hover:not(:disabled){border-color:var(--danger);opacity:1}
.btn-sm{padding:5px 10px;font-size:11px;letter-spacing:.06em}
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th,.tbl td{text-align:left;padding:9px 8px;border-bottom:1px solid var(--line)}
.tbl th{font-size:11px;letter-spacing:.12em;text-transform:uppercase;
  color:var(--fg-dimmer);font-weight:500}
.tbl tr:last-child td{border-bottom:0}
.tbl td:first-child{color:var(--fg-dimmer);font-family:ui-monospace,monospace}
.toast{position:fixed;bottom:32px;left:50%;
  transform:translateX(-50%) translateY(20px);
  background:var(--accent);color:var(--bg);padding:12px 22px;
  font-size:13px;letter-spacing:.03em;opacity:0;pointer-events:none;
  transition:opacity .2s,transform .2s;border-radius:2px;max-width:80vw;z-index:2000}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.err{background:var(--danger);color:var(--fg)}
.login-mask{position:fixed;inset:0;background:rgba(0,0,0,.72);display:flex;
  align-items:center;justify-content:center;z-index:1000;transition:opacity .2s}
.login-mask.hidden{opacity:0;pointer-events:none}
.login-card{background:var(--bg-soft);border:1px solid var(--line);
  padding:44px 36px;width:360px}
.login-card .brand{font-size:18px;margin-bottom:30px}
.login-err{color:var(--danger);font-size:12px;margin-top:12px;
  text-align:center;min-height:16px}
.chart-head{display:flex;align-items:center;gap:14px;margin-bottom:14px;flex-wrap:wrap}
.chart-head h2{flex:0 0 auto;margin:0}
.iface-select{width:auto;padding:4px 10px;font-size:12px}
.legend{margin-left:auto;display:flex;gap:16px;font-size:11px;
  font-family:ui-monospace,monospace;letter-spacing:.1em}
.lg-rx{color:var(--fg)}
.lg-tx{color:var(--fg-dim)}
#traffic-chart{width:100%;height:170px;display:block;background:var(--bg);
  border:1px solid var(--line);border-radius:2px}
.chart-readout{display:flex;justify-content:space-between;margin-top:8px;
  font-family:ui-monospace,monospace;font-size:12px;color:var(--fg-dim);
  letter-spacing:.05em}
.item-card{border:1px solid var(--line);padding:16px;margin-bottom:12px}
.item-head{display:flex;align-items:center;justify-content:space-between;
  margin-bottom:14px;gap:12px;flex-wrap:wrap}
.item-head strong{font-family:ui-monospace,monospace;font-size:13px;
  letter-spacing:.05em}
.member-grid{display:grid;
  grid-template-columns:repeat(auto-fill,minmax(150px,1fr));
  gap:6px;margin-top:6px}
.member-grid label{flex-direction:row;align-items:center;gap:6px;
  padding:8px 12px;border:1px solid var(--line);border-radius:2px;
  font-size:12px;color:var(--fg);cursor:pointer;
  transition:border-color .12s,background .12s;
  flex-direction:row !important}
.member-grid label:hover{border-color:var(--fg-dimmer)}
.member-grid label.checked{border-color:var(--fg);background:var(--bg)}
.member-grid label.disabled{opacity:.4;cursor:not-allowed;
  border-color:var(--fg-dimmer)}
.member-grid input[type="checkbox"],
.member-grid input[type="radio"]{width:auto;margin:0}
.member-grid label.disabled input{pointer-events:none}
.checkbox-row{flex-direction:row !important;align-items:center;gap:8px !important}
.checkbox-row input[type="checkbox"]{width:auto;margin:0}
.bar{position:relative;height:6px;background:var(--bg);
  border:1px solid var(--line);border-radius:1px;overflow:hidden;margin:6px 0 4px}
.bar > i{display:block;height:100%;background:var(--fg);
  transition:width .3s ease}
.bar.warn > i{background:var(--warn)}
.bar.crit > i{background:var(--danger)}
.bar-row{display:flex;align-items:center;gap:12px;margin-bottom:10px}
.bar-row .bar-label{flex:0 0 130px;font-family:ui-monospace,monospace;
  font-size:12px;color:var(--fg-dim);overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.bar-row .bar-track{flex:1}
.bar-row .bar-value{flex:0 0 160px;text-align:right;
  font-family:ui-monospace,monospace;font-size:12px;color:var(--fg)}
.kv{display:grid;grid-template-columns:170px 1fr;gap:8px 16px;font-size:13px}
.kv dt{color:var(--fg-dimmer);font-size:11px;letter-spacing:.1em;
  text-transform:uppercase;padding-top:2px}
.kv dd{font-family:ui-monospace,monospace;word-break:break-all}
.fw-table-block{border:1px solid var(--line);margin-bottom:10px}
.fw-table-head{display:flex;align-items:center;padding:12px 16px;
  background:var(--bg);cursor:pointer;gap:12px;user-select:none;flex-wrap:wrap}
.fw-table-head:hover{background:var(--bg-card)}
.fw-table-head .caret{font-family:ui-monospace,monospace;
  color:var(--fg-dim);width:12px;transition:transform .15s}
.fw-table-block.open .caret{transform:rotate(90deg)}
.fw-table-head .title{font-family:ui-monospace,monospace;font-size:13px;
  font-weight:600}
.fw-table-head .badge{font-size:10px;letter-spacing:.1em;padding:2px 8px;
  border:1px solid var(--line);color:var(--fg-dim);text-transform:uppercase}
.fw-table-head .badge.router{color:var(--warn);border-color:var(--warn)}
.fw-table-head .spacer{flex:1}
.fw-table-body{display:none;padding:0 16px 16px;border-top:1px solid var(--line)}
.fw-table-block.open .fw-table-body{display:block}
.chain-block{margin-top:14px}
.chain-title{font-family:ui-monospace,monospace;font-size:12px;color:var(--fg);
  padding:6px 0;border-bottom:1px dashed var(--line);
  display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.chain-title .meta{color:var(--fg-dimmer);font-size:11px}
.chain-block .tbl{margin-top:4px}
.chain-block .tbl th,.chain-block .tbl td{padding:6px 8px;font-size:12px}
.log-box{background:var(--bg);border:1px solid var(--line);
  padding:12px 14px;font-family:ui-monospace,"SF Mono",monospace;
  font-size:12px;line-height:1.6;color:var(--fg-dim);max-height:340px;
  overflow:auto;white-space:pre-wrap;word-break:break-all;border-radius:2px}
.temp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));
  gap:1px;background:var(--line);border:1px solid var(--line)}
.temp-item{background:var(--bg-soft);padding:12px 14px}
.temp-item .name{font-size:11px;letter-spacing:.1em;color:var(--fg-dimmer);
  text-transform:uppercase;margin-bottom:6px;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.temp-item .value{font-family:ui-monospace,monospace;font-size:18px;
  font-weight:600}
.temp-item.hot .value{color:var(--warn)}
.temp-item.crit .value{color:var(--danger)}
.speed-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:16px}
@media (max-width:700px){.speed-grid{grid-template-columns:1fr}}
.speed-metric{text-align:center;padding:18px 12px 14px;
  border-radius:2px;background:var(--bg);border:1px solid var(--line);
  transition:border-color .3s,background .3s}
.speed-metric.active{border-color:var(--accent);background:var(--bg-card)}
.speed-metric .m-label{font-size:11px;color:var(--fg-dim);
  text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.speed-metric .m-value{font-size:32px;font-weight:700;
  font-family:ui-monospace,"SF Mono",Menlo,monospace;line-height:1;
  letter-spacing:-.02em;color:var(--fg)}
.speed-metric .m-unit{font-size:11px;color:var(--fg-dim);margin-top:6px}
.speed-metric .m-sub{font-size:11px;color:var(--fg-dim);margin-top:3px;
  font-family:ui-monospace,monospace}
.steps{display:flex;flex-direction:column;gap:6px;margin-top:14px}
.step{display:flex;align-items:center;gap:10px;padding:8px 12px;
  border:1px solid var(--line);border-radius:2px;font-size:12px;
  font-family:ui-monospace,monospace;background:var(--bg)}
.step .st-ico{width:22px;text-align:center;font-weight:700}
.step.ok .st-ico{color:var(--ok)}
.step.err .st-ico{color:var(--danger)}
.step .st-name{flex:0 0 150px;color:var(--fg)}
.step .st-msg{flex:1;color:var(--fg-dim);word-break:break-all;
  white-space:pre-wrap;font-size:11px}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--line);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:var(--fg-dimmer)}
.warn-box{background:#2a1a1a;border:1px solid var(--danger);
  padding:10px 14px;color:var(--danger);font-size:12px;
  margin-bottom:14px;border-radius:2px}
.proc-tabs{display:flex;gap:6px}
.proc-tabs .subtab{background:transparent;border:1px solid var(--line);
  color:var(--fg-dim);padding:5px 12px;font-size:11px;letter-spacing:.06em;
  cursor:pointer;border-radius:2px;font-family:inherit}
.proc-tabs .subtab:hover{color:var(--fg)}
.proc-tabs .subtab.active{background:var(--accent);color:var(--bg);
  border-color:var(--accent)}
.badge{display:inline-block;font-size:10px;letter-spacing:.08em;
  padding:2px 8px;border:1px solid var(--line);color:var(--fg-dim);
  text-transform:uppercase;border-radius:2px;margin-left:4px}
</style>
</head>
<body>
<div id="chpwd-mask" class="login-mask hidden">
<div class="login-card">
  <div class="brand">修改密码</div>
  <label>旧密码
    <input id="chpwd-old" type="password" autocomplete="current-password">
  </label>
  <label style="margin-top:12px">新密码（≥6 位）
    <input id="chpwd-new" type="password" autocomplete="new-password">
  </label>
  <label style="margin-top:12px">确认新密码
    <input id="chpwd-confirm" type="password" autocomplete="new-password">
  </label>
  <button class="btn" id="btn-chpwd-save" style="width:100%;margin-top:20px">确认修改</button>
  <button class="btn btn-inverse" id="btn-chpwd-cancel" style="width:100%;margin-top:8px">取消</button>
  <div id="chpwd-err" class="login-err"></div>
</div>
</div>

<div id="fw-modal" class="login-mask hidden">
  <div class="login-card" style="width:560px;max-height:86vh;overflow:auto">
    <div class="brand" id="fw-modal-title"
         style="font-size:15px;margin-bottom:20px"></div>
    <div id="fw-modal-body"></div>
    <div class="actions" style="margin-top:20px">
      <button class="btn" id="fw-modal-save">保存</button>
      <button class="btn btn-inverse" id="fw-modal-cancel">取消</button>
    </div>
  </div>
</div>

<div id="vm-modal" class="login-mask hidden">
  <div class="login-card" style="width:620px;max-height:88vh;overflow:auto">
    <div class="brand" id="vm-modal-title"
         style="font-size:15px;margin-bottom:20px"></div>
    <div id="vm-modal-body"></div>
    <div class="actions" style="margin-top:20px">
      <button class="btn" id="vm-modal-save">创建</button>
      <button class="btn btn-inverse" id="vm-modal-cancel">取消</button>
    </div>
  </div>
</div>

<div id="login-mask" class="login-mask hidden">
<div class="login-card">
  <div class="brand">NET<span>ROUTER</span></div>
  <label>密码
    <input id="login-pwd" type="password" autocomplete="current-password">
  </label>
  <button class="btn" id="btn-login" style="width:100%;margin-top:20px">登录</button>
  <div id="login-err" class="login-err"></div>
</div>
</div>

<header class="topbar">
  <div class="brand">NET<span>ROUTER</span></div>
  <nav>
    <button class="tab active" data-view="dashboard">概览</button>
    <button class="tab" data-view="router">路由器</button>
    <button class="tab" data-view="firewall">防火墙</button>
    <button class="tab" data-view="packages">包管理</button>
    <button class="tab" data-view="vms">虚拟机</button>
    <button class="tab" data-view="disks">磁盘管理</button>
    <button class="tab" data-view="shares">文件共享</button>
  </nav>
  <div style="display:flex;align-items:center;gap:12px">
    <button class="btn btn-inverse btn-sm" id="btn-chpwd">修改密码</button>
    <button class="btn btn-inverse btn-sm" id="btn-logout">登出</button>
    <div class="clock" id="clock"></div>
  </div>
</header>
<main>
<!-- 概览 -->
<section id="view-dashboard" class="view active">
<div id="root-warn"></div>
<div class="panel">
  <div class="chart-head">
    <h2>实时流量</h2>
    <select id="chart-iface" class="iface-select"></select>
    <div class="legend">
      <span class="lg-rx">━ RX</span>
      <span class="lg-tx">┅ TX</span>
    </div>
  </div>
  <canvas id="traffic-chart"></canvas>
  <div class="chart-readout">
    <span id="ro-rx">↓ 0 B/s</span>
    <span id="ro-tx">↑ 0 B/s</span>
  </div>
</div>
<div class="cards" id="dash-cards"></div>
<div class="panel">
  <h2>网速测速<span class="hint">浏览器 ⇄ 服务器 · 每项 ≥ 5 秒</span></h2>
  <div class="speed-grid">
    <div class="speed-metric down">
      <div class="m-label">↓ 下载</div>
      <div class="m-value" id="speed-down">—</div>
      <div class="m-unit">Mbps</div>
      <div class="m-sub" id="speed-down-sub">—</div>
    </div>
    <div class="speed-metric up">
      <div class="m-label">↑ 上传</div>
      <div class="m-value" id="speed-up">—</div>
      <div class="m-unit">Mbps</div>
      <div class="m-sub" id="speed-up-sub">—</div>
    </div>
    <div class="speed-metric ping">
      <div class="m-label">延迟</div>
      <div class="m-value" id="speed-ping">—</div>
      <div class="m-unit">ms</div>
      <div class="m-sub" id="speed-ping-sub">往返</div>
    </div>
  </div>
  <div class="actions">
    <button class="btn" id="speed-btn">开始测速</button>
    <div id="speed-status" style="font-size:12px;
      color:var(--fg-dim);font-family:ui-monospace,monospace;align-self:center">
      下载 / 上传测试各持续至少 5 秒
    </div>
  </div>
  <div class="bar" style="margin-top:14px">
    <div id="speed-bar" style="height:100%;background:var(--ok);width:0%"></div>
  </div>
</div>
<div class="split">
  <div class="panel"><h2>CPU</h2><div id="cpu-cores"></div></div>
  <div class="panel"><h2>内存 / 交换</h2><div id="mem-detail"></div></div>
</div>
<div class="panel"><h2>磁盘</h2><div id="disk-list-dash"></div></div>
<div class="panel"><h2>温度传感器</h2><div id="sensor-list"></div></div>
<div class="split">
  <div class="panel"><h2>网络接口</h2><div id="dash-ifaces"></div></div>
  <div class="panel"><h2>WiFi 客户端</h2><div id="dash-wifi"></div></div>
</div>
<div class="split">
  <div class="panel"><h2>WireGuard</h2><div id="dash-wg"></div></div>
  <div class="panel"><h2>DHCP 租约</h2><div id="dash-dhcp"></div></div>
</div>
<div class="panel">
  <h2>系统信息</h2>
  <dl class="kv" id="sys-kv"></dl>
</div>
<div class="panel">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:12px">
    <h2 style="margin:0">进程 Top 20</h2>
    <div class="proc-tabs">
      <button class="subtab active" data-sort="cpu">按 CPU</button>
      <button class="subtab" data-sort="mem">按内存</button>
    </div>
  </div>
  <table class="tbl" id="proc-table">
    <thead><tr><th>PID</th><th>用户</th><th>名称</th>
    <th style="text-align:right">CPU%</th>
    <th style="text-align:right">MEM%</th>
    <th style="text-align:right">RSS</th>
    <th>状态</th></tr></thead>
    <tbody></tbody>
  </table>
</div>
<div class="split">
  <div class="panel">
    <h2>Ping</h2>
    <div class="form-row" style="margin-bottom:12px">
      <input id="ping-host" placeholder="主机名 / IP">
      <input id="ping-count" type="number" value="4" min="1" max="10"
             style="max-width:90px;flex:0 0 90px">
      <button class="btn" id="btn-ping" style="flex:0 0 auto">运行</button>
    </div>
    <div class="log-box" id="ping-out">—</div>
  </div>
  <div class="panel">
    <h2>DNS 查询</h2>
    <div class="form-row" style="margin-bottom:12px">
      <input id="dns-name" placeholder="域名">
      <input id="dns-server" placeholder="DNS 服务器（可选）">
      <button class="btn" id="btn-dns" style="flex:0 0 auto">查询</button>
    </div>
    <div class="log-box" id="dns-out">—</div>
  </div>
</div>
<div class="panel">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
    <h2 style="margin:0">路由表</h2>
    <button class="btn btn-inverse btn-sm" onclick="loadRoutes()">刷新</button>
  </div>
  <table class="tbl" id="route-table">
    <thead><tr><th>族</th><th>目的</th><th>网关</th><th>设备</th>
    <th>协议</th><th>源</th></tr></thead>
    <tbody></tbody>
  </table>
</div>
<div class="panel">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
    <h2 style="margin:0">邻居表 (ARP / NDP)</h2>
    <button class="btn btn-inverse btn-sm" onclick="loadNeighbors()">刷新</button>
  </div>
  <table class="tbl" id="neigh-table">
    <thead><tr><th>族</th><th>IP</th><th>MAC</th><th>设备</th><th>状态</th></tr></thead>
    <tbody></tbody>
  </table>
</div>
</section>

<!-- 路由器 -->
<section id="view-router" class="view">
<div id="router-warn"></div>
<div class="panel" style="padding:12px 22px">
  <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
    <h2 style="margin:0">当前配置</h2>
    <span id="router-status-text"
          style="color:var(--fg-dim);font-size:12px;
                 font-family:ui-monospace,monospace">加载中...</span>
  </div>
</div>
<div class="panel">
  <h2>WAN（广域网）<span class="hint">勾选一个接口作为 WAN</span></h2>
  <div id="wan-iface-list" class="member-grid"></div>
  <div class="form-row" style="margin-top:16px">
    <label style="max-width:220px">接入方式
      <select id="rc-wan-mode" onchange="onWanModeChange()">
        <option value="dhcp">DHCP（自动获取）</option>
        <option value="static">静态 IP</option>
        <option value="pppoe">PPPoE 拨号</option>
      </select>
    </label>
  </div>
  <div id="wan-static-box" style="display:none;margin-top:12px">
    <div class="form-row">
      <label>IP 地址 (CIDR)<input id="rc-wan-ip" placeholder="192.168.1.10/24"></label>
      <label>网关<input id="rc-wan-gw" placeholder="192.168.1.1"></label>
      <label>DNS<input id="rc-wan-dns" placeholder="8.8.8.8, 8.8.4.4"></label>
    </div>
  </div>
  <div id="wan-pppoe-box" style="display:none;margin-top:12px">
    <div class="form-row">
      <label>PPPoE 用户名<input id="rc-pppoe-user" placeholder="宽带账号"></label>
      <label>PPPoE 密码<input id="rc-pppoe-pass" type="password" placeholder="宽带密码"></label>
    </div>
  </div>
</div>
<div class="panel">
  <h2>LAN（局域网）<span class="hint">勾选要加入 br-lan 的接口</span></h2>
  <div id="lan-iface-list" class="member-grid"></div>
  <div class="form-row" style="margin-top:16px">
    <label>桥接名称<input id="rc-br" placeholder="br-lan"></label>
    <label>LAN IP<input id="rc-lanip" placeholder="192.168.10.1"></label>
    <label>掩码<input id="rc-lanmask" placeholder="24"></label>
  </div>
  <div style="margin-top:16px">
    <label class="checkbox-row" style="flex:0 0 auto">
      <input type="checkbox" id="rc-dhcp-enabled" onchange="onDhcpToggle()"> 提供 DHCP 服务
    </label>
  </div>
  <div id="dhcp-box" style="margin-top:12px">
    <div class="form-row">
      <label>地址池起始<input id="rc-dhcp-start" placeholder="192.168.10.100"></label>
      <label>地址池结束<input id="rc-dhcp-end" placeholder="192.168.10.200"></label>
      <label>租期<input id="rc-dhcp-lease" placeholder="12h"></label>
      <label>DNS<input id="rc-dns" placeholder="8.8.8.8 8.8.4.4"></label>
    </div>
  </div>
</div>
<div class="panel">
  <h2>WiFi 热点<span class="hint">LAN 中勾选无线接口后自动作为 AP</span></h2>
  <div id="wifi-hint" style="color:var(--fg-dim);font-size:12px;margin-bottom:12px">—</div>
  <div class="form-row">
    <label>SSID<input id="rc-ssid"></label>
    <label>密码（≥8 位）<input id="rc-wpwd"></label>
  </div>
  <div class="form-row" style="margin-top:12px">
    <label>频段<select id="rc-band">
      <option value="5">5 GHz</option>
      <option value="2.4">2.4 GHz</option>
    </select></label>
    <label>信道<input id="rc-ch" placeholder="149"></label>
    <label>带宽<select id="rc-cw">
      <option value="80">80 MHz</option>
      <option value="40">40 MHz</option>
      <option value="20">20 MHz</option>
    </select></label>
    <label>国家<input id="rc-country" placeholder="CN" style="max-width:90px"></label>
  </div>
</div>
<div class="panel">
  <h2>WireGuard
    <span class="hint">客户端（连远程服务器）或服务器（接受客户端连接）</span>
  </h2>
  <div class="form-row" style="margin-bottom:14px">
    <label style="max-width:180px">工作模式
      <select id="rc-wg-mode" onchange="onWgModeChange()">
        <option value="client">客户端</option>
        <option value="server">服务器</option>
      </select>
    </label>
    <label class="checkbox-row" style="flex:0 0 auto;align-self:flex-end">
      <input type="checkbox" id="rc-wg-enable"> 启用 WireGuard</label>
  </div>
  <div id="wg-client-box">
    <div class="form-row">
      <label>接口<input id="rc-wg-if" placeholder="wg0"></label>
      <label>本机地址<input id="rc-wg-addr" placeholder="10.0.0.2/32"></label>
      <label>对端 Endpoint<input id="rc-wg-end" placeholder="host:port"></label>
    </div>
    <div class="form-row" style="margin-top:12px">
      <label>AllowedIPs<input id="rc-wg-allowed" placeholder="192.168.0.0/24, 10.0.0.0/24"></label>
      <label>服务器公钥<input id="rc-wg-pub"></label>
    </div>
    <div class="form-row" style="margin-top:12px">
      <label>客户端私钥（留空自动生成）<input id="rc-wg-priv"></label>
      <label>Preshared Key（可选）<input id="rc-wg-psk"></label>
      <label>Keepalive<input id="rc-wg-ka" placeholder="25"></label>
    </div>
  </div>
  <div id="wg-server-box" style="display:none">
    <div class="form-row">
      <label>接口<input id="rc-wg-if-srv" placeholder="wg0"></label>
      <label>本机地址 (CIDR)<input id="rc-wg-srv-addr" placeholder="10.0.0.1/24"></label>
      <label>监听端口<input id="rc-wg-srv-port" placeholder="51820"></label>
    </div>
    <div class="form-row" style="margin-top:12px">
      <label>对外 Endpoint<input id="rc-wg-srv-end" placeholder="vpn.example.com 或公网 IP"></label>
      <label>客户端 DNS<input id="rc-wg-client-dns" placeholder="8.8.8.8"></label>
      <label>客户端 AllowedIPs<input id="rc-wg-client-allowed" placeholder="0.0.0.0/0, ::/0"></label>
    </div>
    <div class="form-row" style="margin-top:12px">
      <label>服务器私钥（留空自动生成）<input id="rc-wg-srv-priv"></label>
      <label>Keepalive<input id="rc-wg-ka-srv" placeholder="25"></label>
    </div>
    <div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--line)">
      <div style="display:flex;align-items:center;justify-content:space-between;
                  margin-bottom:12px;flex-wrap:wrap;gap:12px">
        <div>
          <strong style="font-size:12px;letter-spacing:.14em;
                         text-transform:uppercase;color:var(--fg-dim)">对端管理</strong>
          <span style="font-size:11px;color:var(--fg-dimmer);margin-left:10px">
            添加后即可复制或下载客户端配置</span>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-inverse btn-sm" onclick="wgLoadPeers()">刷新</button>
          <button class="btn btn-sm" onclick="wgAddPeer()">+ 添加对端</button>
        </div>
      </div>
      <div id="wg-peers"></div>
    </div>
  </div>
</div>
<div class="panel" style="padding:16px 22px">
  <div class="actions" style="margin:0">
    <button class="btn btn-inverse btn-sm" onclick="routerDetect()">重新检测接口</button>
    <button class="btn btn-inverse btn-sm" onclick="routerLoad()">重新加载</button>
    <button class="btn" id="btn-router-save">保存配置</button>
    <button class="btn" id="btn-router-apply">一键应用（保存+配置+启动）</button>
  </div>
  <div class="steps" id="router-steps"></div>
</div>
</section>

<!-- 防火墙 -->
<section id="view-firewall" class="view">
<div id="fw-root-warn"></div>
<div class="panel">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:12px">
    <h2 style="margin:0">区域设置
      <span class="hint" style="margin-left:10px">将接口划入区域并控制区域间转发策略</span>
    </h2>
    <div style="display:flex;gap:8px">
      <button class="btn btn-sm" onclick="fwAddZone()">+ 添加区域</button>
      <button class="btn btn-inverse btn-sm" onclick="fwLoadZones()">刷新</button>
    </div>
  </div>
  <div id="fw-zones"></div>
  <div style="margin-top:16px;padding:10px 14px;border:1px solid var(--line);
              border-radius:2px;background:var(--bg)">
    <span style="color:var(--ok);font-weight:600">● 区域防火墙已启用</span>
    <span style="color:var(--fg-dimmer);font-size:11.5px;
                 font-family:ui-monospace,monospace;margin-left:10px">
      不可关闭 · 未匹配的 input / forward 流量默认丢弃
    </span>
  </div>
  <div style="color:var(--fg-dimmer);font-size:11.5px;margin-top:10px;
              font-family:ui-monospace,monospace;line-height:1.7">
    路由器「一键应用」时自动创建并同步：<br>
    · <b style="color:var(--fg)">lan</b> ← br-lan（+ wg 服务器接口），input/forward=ACCEPT<br>
    · <b style="color:var(--fg)">wan</b> ← WAN 接口（+ wg 客户端接口），input/forward=REJECT，masq=on<br>
    · 转发 <b style="color:var(--fg)">lan → wan</b> 全部放行；其余因默认 drop 而拒绝<br>
    · 自动添加 <b style="color:var(--fg)">allow-ssh</b>（wan 22/tcp）与
      <b style="color:var(--fg)">allow-mgmt</b>（wan 8080/tcp）
  </div>
</div>
<div class="panel">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:12px">
    <h2 style="margin:0">区域转发
      <span class="hint" style="margin-left:10px">允许源区域向目标区域转发</span>
    </h2>
    <button class="btn btn-sm" onclick="fwAddForwarding()">+ 添加转发</button>
  </div>
  <div id="fw-forwardings"></div>
</div>
<div class="panel">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:12px">
    <h2 style="margin:0">端口转发（DNAT）
      <span class="hint" style="margin-left:10px">将外部端口映射到内网主机</span>
    </h2>
    <button class="btn btn-sm" onclick="fwAddPortForward()">+ 添加规则</button>
  </div>
  <div id="fw-port-forwards"></div>
</div>
<div class="panel">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:12px">
    <h2 style="margin:0">端口开放 / 关闭
      <span class="hint" style="margin-left:10px">按区域和端口控制入向访问</span>
    </h2>
    <button class="btn btn-sm" onclick="fwAddInputRule()">+ 添加规则</button>
  </div>
  <div id="fw-input-rules"></div>
</div>
<div class="panel" style="padding:16px 22px">
  <div class="actions" style="margin:0">
    <button class="btn" id="fw-btn-apply">保存并应用</button>
    <button class="btn btn-inverse" onclick="fwLoadZones()">放弃更改</button>
    <span id="fw-apply-msg" style="font-size:12px;color:var(--fg-dim);
      font-family:ui-monospace,monospace;align-self:center"></span>
  </div>
</div>
<div class="panel">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
    <h2 style="margin:0">规则集合（所有表）</h2>
    <button class="btn btn-inverse btn-sm" onclick="loadFirewallAll()">刷新</button>
  </div>
  <div id="fw-tables"></div>
</div>
</section>

<!-- 包管理 -->
<section id="view-packages" class="view">
<div id="pkg-root-warn"></div>
<div class="panel">
  <h2>路由功能必备<span class="hint">路由器一键应用所需的核心软件包</span></h2>
  <div id="pkg-router-essentials">
    <div style="color:var(--fg-dimmer);font-size:12px">检测中...</div>
  </div>
  <div class="actions" style="margin-top:14px">
    <button class="btn" id="pkg-btn-install-essentials">一键安装全部</button>
    <button class="btn btn-inverse" id="pkg-btn-refresh-essentials">刷新状态</button>
  </div>
</div>
<div class="panel">
  <h2>虚拟机环境必备<span class="hint">QEMU/KVM + libvirt · 约 300MB</span></h2>
  <div id="pkg-vm-essentials">
    <div style="color:var(--fg-dimmer);font-size:12px">检测中...</div>
  </div>
  <div class="actions" style="margin-top:14px">
    <button class="btn" id="pkg-btn-install-vm-essentials">一键安装全部</button>
    <button class="btn btn-inverse" id="pkg-btn-refresh-vm-essentials">刷新状态</button>
  </div>
</div>
<div class="panel">
  <h2>磁盘管理必备<span class="hint">多文件系统格式化 / 检查工具</span></h2>
  <div id="pkg-disk-essentials">
    <div style="color:var(--fg-dimmer);font-size:12px">检测中...</div>
  </div>
  <div class="actions" style="margin-top:14px">
    <button class="btn" id="pkg-btn-install-disk-essentials">一键安装全部</button>
    <button class="btn btn-inverse" id="pkg-btn-refresh-disk-essentials">刷新状态</button>
  </div>
</div>
<div class="panel">
  <h2>文件共享必备<span class="hint">Samba SMB / CIFS 服务</span></h2>
  <div id="pkg-samba-essentials">
    <div style="color:var(--fg-dimmer);font-size:12px">检测中...</div>
  </div>
  <div class="actions" style="margin-top:14px">
    <button class="btn" id="pkg-btn-install-samba-essentials">一键安装全部</button>
    <button class="btn btn-inverse" id="pkg-btn-refresh-samba-essentials">刷新状态</button>
  </div>
</div>
<div class="panel">
  <h2>系统操作</h2>
  <div class="actions" style="margin-top:0">
    <button class="btn" id="pkg-btn-update">更新索引</button>
    <button class="btn" id="pkg-btn-upgrade">升级系统</button>
    <button class="btn btn-inverse" id="pkg-btn-refresh">刷新已安装</button>
  </div>
  <div style="color:var(--fg-dimmer);font-size:11.5px;margin-top:12px;font-family:ui-monospace,monospace">
    apt-get update / apt-get upgrade -y / dpkg-query -W
  </div>
</div>
<div class="panel">
  <h2>搜索软件包</h2>
  <div class="form-row">
    <input id="pkg-search-q" placeholder="包名关键字（至少 2 个字符）"
           onkeydown="if(event.key==='Enter')pkgSearch()">
    <button class="btn" id="pkg-btn-search" style="flex:0 0 auto">搜索</button>
  </div>
  <div id="pkg-search-results" style="margin-top:14px">
    <div style="color:var(--fg-dimmer);font-size:12px">输入关键字开始搜索</div>
  </div>
</div>
<div class="panel">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:12px">
    <h2 style="margin:0">已安装软件包</h2>
    <span id="pkg-installed-count" style="color:var(--fg-dim);font-size:12px;font-family:ui-monospace,monospace"></span>
  </div>
  <div id="pkg-installed-list">
    <div style="color:var(--fg-dimmer);font-size:12px">加载中...</div>
  </div>
</div>
<div class="panel" id="pkg-task-panel" style="display:none">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:12px">
    <h2 style="margin:0" id="pkg-task-title">任务</h2>
    <div style="display:flex;gap:8px;align-items:center">
      <span id="pkg-task-status" style="color:var(--fg-dim);font-size:12px;font-family:ui-monospace,monospace"></span>
      <button class="btn btn-inverse btn-sm" onclick="pkgCloseTask()">关闭</button>
    </div>
  </div>
  <div class="log-box" id="pkg-task-out" style="max-height:520px">—</div>
</div>
</section>

<!-- 虚拟机 -->
<section id="view-vms" class="view">
<div id="vm-root-warn"></div>
<div id="vm-kvm-warn"></div>
<div class="panel">
  <h2>存储设置<span class="hint">新建虚拟机默认落盘位置（每台虚拟机拥有独立子目录）</span></h2>
  <div class="form-row">
    <label>默认存储目录
      <input id="vm-storage-dir" placeholder="/var/lib/libvirt/images">
    </label>
    <button class="btn" id="vm-btn-save-settings" style="flex:0 0 auto">保存</button>
  </div>
  <div style="color:var(--fg-dimmer);font-size:11.5px;margin-top:10px;
              font-family:ui-monospace,monospace;line-height:1.7">
    · 每台虚拟机的磁盘位于 <b style="color:var(--fg)">&lt;存储目录&gt;/&lt;虚拟机名&gt;/&lt;虚拟机名&gt;.qcow2</b><br>
    · 导入已有 QCOW2 时会自动移动到该目录下
  </div>
</div>
<div class="panel">
  <div style="display:flex;align-items:center;justify-content:space-between;
              margin-bottom:14px;flex-wrap:wrap;gap:12px">
    <h2 style="margin:0">虚拟机列表
      <span class="hint" style="margin-left:10px">
        默认网桥 br-lan · VNC 端口 5901-5999</span>
    </h2>
    <div style="display:flex;gap:8px">
      <button class="btn btn-sm" onclick="vmOpenCreate()">+ 新建虚拟机</button>
      <button class="btn btn-inverse btn-sm" onclick="vmLoadList()">刷新</button>
    </div>
  </div>
  <div id="vm-list">
    <div style="color:var(--fg-dimmer);font-size:12px">加载中...</div>
  </div>
</div>
<div class="panel">
  <div style="display:flex;align-items:center;justify-content:space-between;
              margin-bottom:14px;flex-wrap:wrap;gap:12px">
    <h2 style="margin:0">ISO 镜像库
      <span class="hint" style="margin-left:10px">
        仅用于新建时可选挂载，可留空</span>
    </h2>
    <button class="btn btn-inverse btn-sm" onclick="vmLoadIsos()">重新扫描</button>
  </div>
  <div id="vm-isos">
    <div style="color:var(--fg-dimmer);font-size:12px">加载中...</div>
  </div>
</div>
</section>

<!-- 磁盘管理 -->
<section id="view-disks" class="view">
<div id="disk-root-warn"></div>
<div class="panel">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:12px">
    <h2 style="margin:0">块设备
      <span class="hint" style="margin-left:10px">系统盘设备已禁用操作</span>
    </h2>
    <button class="btn btn-inverse btn-sm" onclick="loadDisks()">刷新</button>
  </div>
  <div id="disk-list">
    <div style="color:var(--fg-dimmer);font-size:12px">加载中...</div>
  </div>
</div>
<div class="panel">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:12px">
    <h2 style="margin:0">NetRouter 自动挂载（fstab）</h2>
    <button class="btn btn-inverse btn-sm" onclick="loadDisks()">刷新</button>
  </div>
  <div id="disk-fstab">
    <div style="color:var(--fg-dimmer);font-size:12px">加载中...</div>
  </div>
  <div style="color:var(--fg-dimmer);font-size:11.5px;margin-top:12px;font-family:ui-monospace,monospace;line-height:1.7">
    · 自动挂载写入 /etc/fstab 中的 NetRouter 管理块<br>
    · 原有 fstab 内容不会被修改，仅在该块内追加/更新条目<br>
    · 写入前会执行 fstab 语法校验，失败则回滚，避免开机异常<br>
    · 默认添加 nofail 选项，即使设备缺失也不会阻塞启动<br>
    · 原始 fstab 会备份到 /etc/fstab.netrouter.bak
  </div>
</div>
</section>

<!-- 文件共享 -->
<section id="view-shares" class="view">
<div id="share-root-warn"></div>
<div class="panel">
  <h2>Samba 服务状态<span class="hint">SMB / CIFS 文件共享</span></h2>
  <div id="share-status">
    <div style="color:var(--fg-dimmer);font-size:12px">检测中...</div>
  </div>
</div>
<div class="panel">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:12px">
    <h2 style="margin:0">账户管理
      <span class="hint" style="margin-left:10px">
        Samba 用户与访问凭据</span>
    </h2>
    <div style="display:flex;gap:8px">
      <button class="btn btn-sm" onclick="showAddSambaUser()">+ 添加用户</button>
      <button class="btn btn-inverse btn-sm" onclick="loadSambaUsers()">刷新</button>
    </div>
  </div>
  <div id="share-users">
    <div style="color:var(--fg-dimmer);font-size:12px">加载中...</div>
  </div>
  <div style="color:var(--fg-dimmer);font-size:11.5px;margin-top:12px;font-family:ui-monospace,monospace;line-height:1.7">
    · Samba 用户必须对应一个 Linux 系统账户（可自动创建无登录权限账户）<br>
    · 密码独立于系统密码，使用 smbpasswd 单独维护<br>
    · 客户端连接格式：<b style="color:var(--fg)">\\&lt;IP&gt;\&lt;共享名&gt;</b>，用户名为 Samba 用户名
  </div>
</div>
<div class="panel">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:12px">
    <h2 style="margin:0">共享列表</h2>
    <div style="display:flex;gap:8px">
      <button class="btn btn-sm" onclick="showAddShare()">+ 添加共享</button>
      <button class="btn btn-inverse btn-sm" onclick="loadShares()">刷新</button>
    </div>
  </div>
  <div id="share-list">
    <div style="color:var(--fg-dimmer);font-size:12px">加载中...</div>
  </div>
  <div style="color:var(--fg-dimmer);font-size:11.5px;margin-top:12px;font-family:ui-monospace,monospace;line-height:1.7">
    · 配置写入 /etc/samba/smb.conf 中的 NetRouter 管理块<br>
    · 原有 smb.conf 内容不会被修改<br>
    · 原始 smb.conf 会备份到 /etc/samba/smb.conf.netrouter.bak<br>
    · 访问路径：<b style="color:var(--fg)">\\\\&lt;路由器IP&gt;\&lt;共享名&gt;</b>
  </div>
</div>
</section>
</main>
<div id="toast" class="toast"></div>
<script>
"use strict";
const Token = {
  get(){ return localStorage.getItem("nr_token"); },
  set(t){ localStorage.setItem("nr_token", t); },
  clear(){ localStorage.removeItem("nr_token"); },
};
const api = {
  async _fetch(url, opts){
    opts = opts || {};
    opts.headers = Object.assign({}, opts.headers || {});
    const t = Token.get();
    if (t) opts.headers["Authorization"] = "Bearer " + t;
    const r = await fetch(url, opts);
    if (r.status === 401){ showLogin(); throw new Error("未登录"); }
    return r;
  },
  async get(url){ const r = await this._fetch(url); return r.json(); },
  async post(url, body){
    const r = await this._fetch(url, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body || {}),
    });
    const j = await r.json().catch(()=>({}));
    if (!r.ok) throw new Error(j.detail || "请求失败");
    return j;
  },
};
let toastTimer;
function toast(msg, isErr){
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.classList.toggle("err", !!isErr);
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 2800);
}
function escapeHtml(s){
  return String(s == null ? "" : s).replace(/[&<>"']/g, c => (
    {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function escapeAttr(s){ return escapeHtml(s); }
function fmtBytes(b){
  if (b < 1024) return b + " B";
  if (b < 1024*1024) return (b/1024).toFixed(1) + " KB";
  if (b < 1024*1024*1024) return (b/1024/1024).toFixed(2) + " MB";
  return (b/1024/1024/1024).toFixed(2) + " GB";
}
function fmtRate(bps){
  if (bps < 1024) return bps.toFixed(0) + " B";
  if (bps < 1024*1024) return (bps/1024).toFixed(1) + " KB";
  return (bps/1024/1024).toFixed(2) + " MB";
}
function gb(b){ return (b / 1024 / 1024 / 1024).toFixed(2); }
function mb(b){ return (b / 1024 / 1024).toFixed(1) + " MB"; }
function formatUptime(s){
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  return (d ? d + "d " : "") + h + "h " + m + "m";
}
function card(label, value, sub, dotState){
  const dot = dotState ? '<span class="dot ' + dotState + '"></span>' : '';
  return '<div class="card"><div class="label">' + dot + label + '</div>'
    + '<div class="value">' + value + '</div>'
    + (sub ? '<div class="sub">' + sub + '</div>' : '') + '</div>';
}
function barRow(label, percent, rightText){
  const p = Math.max(0, Math.min(100, percent || 0));
  const cls = p >= 90 ? "crit" : (p >= 75 ? "warn" : "");
  const right = rightText !== undefined ? rightText : p.toFixed(1) + "%";
  return '<div class="bar-row">'
    + '<div class="bar-label" title="' + escapeAttr(label) + '">'
    +   escapeHtml(label) + '</div>'
    + '<div class="bar-track"><div class="bar ' + cls + '">'
    +   '<i style="width:' + p + '%"></i></div></div>'
    + '<div class="bar-value">' + right + '</div></div>';
}
function kv(k, v){
  return '<dt>' + escapeHtml(k) + '</dt><dd>' + escapeHtml(String(v)) + '</dd>';
}
function showLogin(){ document.getElementById("login-mask").classList.remove("hidden"); }
function hideLogin(){ document.getElementById("login-mask").classList.add("hidden"); }
document.getElementById("btn-login").onclick = async () => {
  const pwd = document.getElementById("login-pwd").value;
  const err = document.getElementById("login-err");
  err.textContent = "";
  try {
    const r = await fetch("/api/auth/login", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({password: pwd}),
    });
    if (!r.ok){
      if (r.status === 429) err.textContent = "尝试过多，请稍后再试";
      else err.textContent = "密码错误";
      return;
    }
    const j = await r.json();
    Token.set(j.token);
    document.getElementById("login-pwd").value = "";
    hideLogin();
    boot();
  } catch { err.textContent = "网络错误"; }
};
document.getElementById("login-pwd").addEventListener("keydown", e => {
  if (e.key === "Enter") document.getElementById("btn-login").click();
});
document.getElementById("btn-logout").onclick = () => {
  Token.clear();
  if (trafficWS){ try { trafficWS.close(); } catch(_){} trafficWS = null; }
  trafficChart = null;
  showLogin();
};
setInterval(() => {
  document.getElementById("clock").textContent =
    new Date().toTimeString().slice(0, 8);
}, 1000);

document.getElementById("btn-chpwd").onclick = () => {
  document.getElementById("chpwd-old").value = "";
  document.getElementById("chpwd-new").value = "";
  document.getElementById("chpwd-confirm").value = "";
  document.getElementById("chpwd-err").textContent = "";
  document.getElementById("chpwd-mask").classList.remove("hidden");
};
document.getElementById("btn-chpwd-cancel").onclick = () => {
  document.getElementById("chpwd-mask").classList.add("hidden");
};
document.getElementById("btn-chpwd-save").onclick = async () => {
  const oldPwd = document.getElementById("chpwd-old").value;
  const newPwd = document.getElementById("chpwd-new").value;
  const confirmPwd = document.getElementById("chpwd-confirm").value;
  const err = document.getElementById("chpwd-err");
  err.textContent = "";
  if (!oldPwd){ err.textContent = "请输入旧密码"; return; }
  if (!newPwd || newPwd.length < 6){ err.textContent = "新密码至少 6 位"; return; }
  if (newPwd !== confirmPwd){ err.textContent = "两次输入的新密码不一致"; return; }
  try {
    await api.post("/api/auth/change-password", {
      old_password: oldPwd, new_password: newPwd,
    });
    toast("密码已修改，请重新登录");
    document.getElementById("chpwd-mask").classList.add("hidden");
    Token.clear();
    if (trafficWS){ try { trafficWS.close(); } catch(_){} trafficWS = null; }
    trafficChart = null;
    showLogin();
  } catch(e){ err.textContent = e.message; }
};
document.getElementById("chpwd-confirm").addEventListener("keydown", e => {
  if (e.key === "Enter") document.getElementById("btn-chpwd-save").click();
});

document.querySelectorAll(".tab").forEach(t => {
  t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(x => x.classList.remove("active"));
    document.querySelectorAll(".view").forEach(x => x.classList.remove("active"));
    t.classList.add("active");
    document.getElementById("view-" + t.dataset.view).classList.add("active");
    loadView(t.dataset.view);
  });
});
function loadView(v){
  if (v === "dashboard") loadDashboard();
  else if (v === "router") routerLoad();
  else if (v === "firewall"){ loadFirewallAll(); fwLoadZones(); }
  else if (v === "packages") loadPackages();
  else if (v === "vms") loadVms();
  else if (v === "disks") loadDisks();
  else if (v === "shares") loadShares();
}
async function loadDashboard(){
  try {
    const data = await api.get("/api/stats");
    renderDashCards(data);
    renderDashIfaces(data.interfaces || []);
    renderDashWifi(data.wifi_ap, data.wifi_clients || []);
    renderDashWg(data.wireguard || []);
    renderDashDhcp(data.dhcp_leases || []);
    renderCpuCores(data);
    renderMemDetail(data);
    renderDisks(data);
    renderSensors(data);
    renderSystemKv(data);
    await loadProcesses();
    loadRoutes();
    loadNeighbors();
  } catch(e){}
}
function renderDashCards(d){
  const s = d.system, m = d.memory, sw = d.swap;
  const load = s.load || [0,0,0];
  const cores = s.cpu_cores || 1;
  const loadColor = load[0] > cores * 2 ? "var(--danger)"
    : load[0] > cores ? "var(--warn)" : "var(--ok)";
  let html = "";
  html += card("主机名", escapeHtml(s.hostname),
    escapeHtml(s.distro) + " · " + escapeHtml(s.kernel));
  html += card("运行时间", formatUptime(s.uptime_sec),
    "启动于 " + escapeHtml(s.boot_time));
  html += '<div class="card"><div class="label">负载</div>'
    + '<div class="value" style="color:' + loadColor + '">'
    + load[0].toFixed(2) + '</div>'
    + '<div class="sub">' + load[1].toFixed(2) + ' / '
    + load[2].toFixed(2) + ' · ' + cores + ' 核</div></div>';
  html += card("CPU", d.cpu_percent.toFixed(1) + "%",
    escapeHtml(s.cpu_model).slice(0, 40));
  html += card("内存", m.percent.toFixed(0) + "%",
    gb(m.used) + " / " + gb(m.total) + " GB");
  if (sw.total > 0){
    html += card("交换分区", sw.percent.toFixed(0) + "%",
      gb(sw.used) + " / " + gb(sw.total) + " GB");
  }
  for (const dk of d.disks || []){
    html += card("磁盘 " + dk.mount, dk.percent.toFixed(0) + "%",
      gb(dk.used) + " / " + gb(dk.total) + " GB");
  }
  document.getElementById("dash-cards").innerHTML = html;
}
function renderDashIfaces(ifaces){
  if (!ifaces.length){
    document.getElementById("dash-ifaces").innerHTML =
      '<div style="color:var(--fg-dimmer);font-size:12px">无接口</div>';
    return;
  }
  let html = "";
  for (const it of ifaces){
    const tags = [];
    if (it.wireless) tags.push('<span class="badge">无线</span>');
    if (it.master) tags.push('<span class="badge">->' + escapeHtml(it.master) + '</span>');
    const dot = it.carrier ? "up" : "down";
    const addrs = (it.addresses || []).map(a =>
      (a.family === "inet" ? "IPv4 " : "IPv6 ") + escapeHtml(a.address)
      + "/" + a.prefixlen).join("  ") || "无 IP";
    html += '<div class="item-card" style="padding:12px;margin-bottom:8px">'
      + '<div class="item-head" style="margin-bottom:6px">'
      + '<strong><span class="dot ' + dot + '"></span> '
      + escapeHtml(it.name) + '</strong>' + tags.join("") + '</div>'
      + '<div style="font-size:12px;color:var(--fg-dim);font-family:ui-monospace,monospace">'
      + 'MAC ' + escapeHtml(it.mac) + ' · MTU ' + it.mtu
      + (it.speed_mbps ? ' · ' + it.speed_mbps + 'Mbps' : '') + '</div>'
      + '<div style="font-size:12px;color:var(--fg-dim);font-family:ui-monospace,monospace;margin-top:3px">'
      + addrs + '</div>'
      + '<div style="font-size:12px;color:var(--fg-dim);font-family:ui-monospace,monospace;margin-top:3px">'
      + '↓' + fmtBytes(it.rx_bytes) + ' ↑' + fmtBytes(it.tx_bytes) + '</div></div>';
  }
  document.getElementById("dash-ifaces").innerHTML = html;
}
function renderDashWifi(ap, clients){
  const el = document.getElementById("dash-wifi");
  if (!ap){
    el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">未检测到 WiFi 接口</div>';
    return;
  }
  let html = "";
  if (ap.ssid)    html += '<div class="bar-row"><div class="bar-label">SSID</div><div class="bar-value" style="flex:1;text-align:left;color:var(--fg)">' + escapeHtml(ap.ssid) + '</div></div>';
  if (ap.type)    html += '<div class="bar-row"><div class="bar-label">模式</div><div class="bar-value" style="flex:1;text-align:left;color:var(--fg)">' + escapeHtml(ap.type) + '</div></div>';
  if (ap.channel) html += '<div class="bar-row"><div class="bar-label">信道</div><div class="bar-value" style="flex:1;text-align:left;color:var(--fg)">' + ap.channel + ' (' + (ap.freq_mhz || "-") + ' MHz / ' + (ap.width_mhz || "-") + ' MHz)</div></div>';
  html += '<div style="color:var(--fg-dim);font-size:12px;margin-top:8px">已连接客户端 <b style="color:var(--fg)">' + clients.length + '</b></div>';
  for (const c of clients){
    const bits = [];
    if (c.signal) bits.push('信号 ' + c.signal);
    if (c["rx bitrate"]) bits.push('↓ ' + c["rx bitrate"]);
    if (c["tx bitrate"]) bits.push('↑ ' + c["tx bitrate"]);
    html += '<div class="item-card" style="padding:8px 12px;margin-bottom:6px;font-family:ui-monospace,monospace;font-size:12px">'
      + '<b>' + escapeHtml(c.mac) + '</b> '
      + '<span style="color:var(--fg-dim);margin-left:8px">'
      + escapeHtml(bits.join(" · ") || "—") + '</span></div>';
  }
  el.innerHTML = html;
}
function renderDashWg(wgs){
  const el = document.getElementById("dash-wg");
  if (!wgs.length){
    el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">无活动隧道</div>';
    return;
  }
  let html = "";
  for (const w of wgs){
    html += '<div style="margin-bottom:12px">'
      + '<div style="font-weight:600;font-family:ui-monospace,monospace;color:var(--fg);margin-bottom:8px">'
      + escapeHtml(w.name) + ' · 端口 ' + escapeHtml(w.listen_port) + '</div>';
    for (const p of w.peers){
      html += '<div class="item-card" style="padding:10px 12px;margin-bottom:6px;font-family:ui-monospace,monospace;font-size:12px">'
        + '<div>端点 ' + escapeHtml(p.endpoint) + '</div>'
        + '<div>Allowed ' + escapeHtml(p.allowed_ips) + '</div>'
        + '<div>握手 ' + escapeHtml(p.handshake_ago) + '</div>'
        + '<div>↓' + fmtBytes(p.rx_bytes) + ' ↑' + fmtBytes(p.tx_bytes) + '</div>'
        + '</div>';
    }
    html += '</div>';
  }
  el.innerHTML = html;
}
function renderDashDhcp(leases){
  const el = document.getElementById("dash-dhcp");
  if (!leases.length){
    el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">无租约</div>';
    return;
  }
  let html = '<table class="tbl"><thead><tr><th>IP</th><th>MAC</th><th>主机名</th><th>剩余</th></tr></thead><tbody>';
  for (const l of leases){
    html += '<tr><td>' + escapeHtml(l.ip) + '</td>'
      + '<td>' + escapeHtml(l.mac) + '</td>'
      + '<td>' + escapeHtml(l.hostname || "—") + '</td>'
      + '<td>' + escapeHtml(l.left) + '</td></tr>';
  }
  html += '</tbody></table>';
  el.innerHTML = html;
}
function renderCpuCores(d){
  document.getElementById("cpu-cores").innerHTML =
    barRow("全核", d.cpu_percent, d.cpu_percent.toFixed(1) + "%");
}
function renderMemDetail(d){
  const m = d.memory, sw = d.swap;
  document.getElementById("mem-detail").innerHTML =
    barRow("内存", m.percent, gb(m.used) + " / " + gb(m.total) + " GB")
    + (sw.total > 0
      ? barRow("交换", sw.percent, gb(sw.used) + " / " + gb(sw.total) + " GB")
      : "")
    + '<dl class="kv" style="margin-top:16px">'
    + kv("可用", gb(m.available) + " GB")
    + kv("空闲", gb(m.free) + " GB")
    + kv("缓存", gb(m.cached) + " GB")
    + '</dl>';
}
function renderDisks(d){
  const list = d.disks || [];
  document.getElementById("disk-list-dash").innerHTML = list.length
    ? list.map(x => barRow(x.mount + " (" + x.fstype + ")", x.percent,
        gb(x.used) + " / " + gb(x.total) + " GB")).join("")
    : '<div style="color:var(--fg-dimmer)">未发现磁盘</div>';
}
function renderSensors(d){
  const list = d.sensors || [];
  document.getElementById("sensor-list").innerHTML = list.length
    ? '<div class="temp-grid">' + list.map(x => {
        const cls = x.temp >= 80 ? "crit" : (x.temp >= 65 ? "hot" : "");
        return '<div class="temp-item ' + cls + '"><div class="name">'
          + escapeHtml(x.name) + '</div><div class="value">'
          + x.temp.toFixed(1) + ' C</div></div>';
      }).join("") + '</div>'
    : '<div style="color:var(--fg-dimmer)">无温度传感器</div>';
}
function renderSystemKv(d){
  const s = d.system;
  document.getElementById("sys-kv").innerHTML =
    kv("CPU 型号", s.cpu_model)
    + kv("核心数", (s.cpu_cores || 1) + " 逻辑核")
    + kv("内核", s.kernel)
    + kv("发行版", s.distro)
    + kv("架构", s.arch);
}
let procSort = "cpu";
document.addEventListener("click", e => {
  const t = e.target.closest(".subtab[data-sort]");
  if (!t) return;
  document.querySelectorAll(".subtab[data-sort]").forEach(x => x.classList.remove("active"));
  t.classList.add("active");
  procSort = t.dataset.sort;
  loadProcesses();
});
async function loadProcesses(){
  try {
    const list = await api.get("/api/system/processes?sort=" + procSort + "&limit=20");
    document.querySelector("#proc-table tbody").innerHTML = list.map(p =>
      '<tr><td>' + p.pid + '</td>'
      + '<td>' + escapeHtml(p.user) + '</td>'
      + '<td title="' + escapeAttr(p.cmdline) + '">' + escapeHtml(p.name) + '</td>'
      + '<td style="text-align:right">' + p.cpu.toFixed(1) + '</td>'
      + '<td style="text-align:right">' + p.mem.toFixed(1) + '</td>'
      + '<td style="text-align:right">' + mb(p.rss) + '</td>'
      + '<td>' + escapeHtml(p.status) + '</td></tr>'
    ).join("") || '<tr><td colspan="7" style="color:var(--fg-dimmer)">无数据</td></tr>';
  } catch(_){}
}
async function loadRoutes(){
  try {
    const routes = await api.get("/api/network/routes");
    document.querySelector("#route-table tbody").innerHTML = routes.map(r =>
      '<tr><td>' + escapeHtml(r.family) + '</td>'
      + '<td>' + escapeHtml(r.dst || "default") + '</td>'
      + '<td>' + escapeHtml(r.gateway || "—") + '</td>'
      + '<td>' + escapeHtml(r.dev || "—") + '</td>'
      + '<td>' + escapeHtml(r.protocol || "—") + '</td>'
      + '<td>' + escapeHtml(r.preferred_src || "—") + '</td></tr>'
    ).join("") || '<tr><td colspan="6" style="color:var(--fg-dimmer)">无路由</td></tr>';
  } catch(e){ toast(e.message, true); }
}
async function loadNeighbors(){
  try {
    const ns = await api.get("/api/network/neighbors");
    document.querySelector("#neigh-table tbody").innerHTML = ns.map(n =>
      '<tr><td>' + escapeHtml(n.family) + '</td>'
      + '<td>' + escapeHtml(n.dst || "") + '</td>'
      + '<td>' + escapeHtml(n.lladdr || "—") + '</td>'
      + '<td>' + escapeHtml(n.dev || "—") + '</td>'
      + '<td>' + escapeHtml((n.state || []).join(",") || "—") + '</td></tr>'
    ).join("") || '<tr><td colspan="5" style="color:var(--fg-dimmer)">无邻居</td></tr>';
  } catch(e){ toast(e.message, true); }
}
document.getElementById("btn-ping").onclick = async () => {
  const host = document.getElementById("ping-host").value.trim();
  const count = parseInt(document.getElementById("ping-count").value) || 4;
  if (!host){ toast("请输入主机名", true); return; }
  const out = document.getElementById("ping-out");
  out.textContent = "运行中...";
  try {
    const r = await api.post("/api/tools/ping", {host, count});
    out.textContent = r.output || "(无输出)";
  } catch(e){ out.textContent = e.message; }
};
document.getElementById("btn-dns").onclick = async () => {
  const name = document.getElementById("dns-name").value.trim();
  const server = document.getElementById("dns-server").value.trim();
  if (!name){ toast("请输入域名", true); return; }
  const out = document.getElementById("dns-out");
  out.textContent = "查询中...";
  try {
    const r = await api.post("/api/tools/dns", {name, server});
    out.textContent = r.output || "(无结果)";
  } catch(e){ out.textContent = e.message; }
};
class TrafficChart {
  constructor(canvas){
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.maxPoints = 90;
    this.series = {rx: [], tx: []};
    this.resize();
    window.addEventListener("resize", () => this.resize());
  }
  resize(){
    const dpr = window.devicePixelRatio || 1;
    const rect = this.canvas.getBoundingClientRect();
    this.canvas.width = rect.width * dpr;
    this.canvas.height = rect.height * dpr;
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.w = rect.width;
    this.h = rect.height;
    this.draw();
  }
  push(rx, tx){
    this.series.rx.push(rx);
    this.series.tx.push(tx);
    if (this.series.rx.length > this.maxPoints){
      this.series.rx.shift();
      this.series.tx.shift();
    }
    this.draw();
  }
  clear(){ this.series.rx = []; this.series.tx = []; this.draw(); }
  draw(){
    const ctx = this.ctx, w = this.w, h = this.h;
    ctx.clearRect(0, 0, w, h);
    ctx.strokeStyle = "rgba(255,255,255,0.06)";
    ctx.lineWidth = 1;
    for (let i = 1; i < 4; i++){
      const y = Math.round((h / 4) * i) + 0.5;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
    }
    const all = this.series.rx.concat(this.series.tx);
    const max = Math.max.apply(null, all.concat([1024]));
    this._line(this.series.rx, max, "#f5f5f5", 2, []);
    this._line(this.series.tx, max, "#8a8a8a", 1.5, [5, 4]);
    ctx.fillStyle = "#8a8a8a";
    ctx.font = "11px ui-monospace, monospace";
    ctx.fillText(fmtRate(max) + "/s", 8, 14);
  }
  _line(data, max, color, width, dash){
    if (data.length < 2) return;
    const ctx = this.ctx, w = this.w, h = this.h;
    ctx.strokeStyle = color;
    ctx.lineWidth = width;
    ctx.setLineDash(dash);
    ctx.beginPath();
    const step = w / (this.maxPoints - 1);
    const pad = 6;
    for (let i = 0; i < data.length; i++){
      const x = i * step;
      const y = h - pad - (data[i] / max) * (h - pad * 2);
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    }
    ctx.stroke();
    ctx.setLineDash([]);
  }
}
let trafficChart = null;
let trafficWS = null;
let currentIface = null;
function connectTrafficWS(){
  const token = Token.get();
  if (!token) return;
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const url = proto + "://" + location.host + "/ws/traffic?token="
    + encodeURIComponent(token);
  trafficWS = new WebSocket(url);
  trafficWS.onopen = () => {
    if (!trafficChart){
      const cv = document.getElementById("traffic-chart");
      trafficChart = new TrafficChart(cv);
    }
  };
  trafficWS.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    const ifaces = msg.ifaces || {};
    const names = Object.keys(ifaces);
    const sel = document.getElementById("chart-iface");
    if (sel.options.length !== names.length){
      const keep = sel.value;
      sel.innerHTML = names.map(n =>
        '<option value="' + escapeAttr(n) + '">' + escapeHtml(n) + '</option>'
      ).join("");
      if (keep && names.indexOf(keep) >= 0) sel.value = keep;
      else if (names.length) sel.value = names[0];
      currentIface = sel.value;
      sel.onchange = () => {
        currentIface = sel.value;
        if (trafficChart) trafficChart.clear();
      };
    }
    if (!currentIface) return;
    const d = ifaces[currentIface];
    if (!d) return;
    if (trafficChart) trafficChart.push(d.rx, d.tx);
    document.getElementById("ro-rx").textContent = "↓ " + fmtRate(d.rx) + "/s";
    document.getElementById("ro-tx").textContent = "↑ " + fmtRate(d.tx) + "/s";
  };
  trafficWS.onclose = (ev) => {
    trafficChart = null;
    if (ev.code === 4401){ showLogin(); return; }
    setTimeout(connectTrafficWS, 3000);
  };
  trafficWS.onerror = () => { try { trafficWS.close(); } catch(_){} };
}
const SPEED_MIN_SECONDS = 5.0;
const SPEED_DOWNLOAD_MAX = 1 * 1024 * 1024 * 1024;
const SPEED_UPLOAD_CHUNK_MAX = 64 * 1024 * 1024;
const SPEED_STATE = { running: false };
function setSpeedStatus(t){ document.getElementById("speed-status").textContent = t; }
function setSpeedBar(p){
  p = Math.max(0, Math.min(100, Number(p) || 0));
  document.getElementById("speed-bar").style.width = p.toFixed(1) + "%";
}
function setActiveMetric(name){
  document.querySelectorAll(".speed-metric").forEach(el => el.classList.remove("active"));
  if (name){
    const el = document.querySelector(".speed-metric." + name);
    if (el) el.classList.add("active");
  }
}
function resetSpeedUI(){
  document.getElementById("speed-down").textContent = "—";
  document.getElementById("speed-up").textContent = "—";
  document.getElementById("speed-ping").textContent = "—";
  document.getElementById("speed-down-sub").textContent = "—";
  document.getElementById("speed-up-sub").textContent = "—";
  document.getElementById("speed-ping-sub").textContent = "往返";
  setSpeedBar(0);
}
async function measurePing(rounds = 6){
  const times = [];
  for (let i = 0; i < rounds; i++){
    const t0 = performance.now();
    try {
      await api._fetch("/api/speedtest/ping?r=" + Math.random(),
                       { cache: "no-store" });
    } catch(e){}
    times.push(performance.now() - t0);
  }
  times.sort((a, b) => a - b);
  const keep = times.slice(0, Math.max(1, times.length - 2));
  return keep.reduce((a, b) => a + b, 0) / keep.length;
}
async function downloadOnce(bytes, overallT0, baseBytes, minSeconds, onProgress){
  const url = "/api/speedtest/download?size=" + bytes + "&r=" + Math.random();
  const t0 = performance.now();
  const resp = await api._fetch(url, { cache: "no-store" });
  if (!resp.ok) throw new Error("HTTP " + resp.status);
  let received = 0, lastT = t0, lastB = 0, aborted = false;
  const reader = resp.body.getReader();
  try {
    while (true){
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      const now = performance.now();
      const totalElapsed = (now - overallT0) / 1000;
      if (now - lastT >= 150){
        const inst = (received - lastB) * 8 / ((now - lastT) / 1000) / 1e6;
        if (onProgress) onProgress(inst, baseBytes + received, totalElapsed);
        lastT = now; lastB = received;
      }
      if (totalElapsed >= minSeconds){
        try { await reader.cancel(); } catch(e){}
        aborted = true;
        break;
      }
    }
  } catch(e){}
  const reqSeconds = (performance.now() - t0) / 1000;
  return { bytes: received, seconds: reqSeconds, aborted };
}
async function downloadTest(onProgress){
  const overallT0 = performance.now();
  let totalBytes = 0;
  let size = 64 * 1024 * 1024;
  for (let attempt = 0; attempt < 5; attempt++){
    const elapsed = (performance.now() - overallT0) / 1000;
    if (elapsed >= SPEED_MIN_SECONDS) break;
    const result = await downloadOnce(size, overallT0, totalBytes,
                                      SPEED_MIN_SECONDS, onProgress);
    totalBytes += result.bytes;
    const totalElapsed = (performance.now() - overallT0) / 1000;
    if (totalElapsed >= SPEED_MIN_SECONDS) break;
    if (result.bytes < size) break;
    if (size >= SPEED_DOWNLOAD_MAX) break;
    const ratio = SPEED_MIN_SECONDS / Math.max(result.seconds, 0.1);
    const next = Math.ceil(size * ratio * 1.2);
    size = Math.min(next, SPEED_DOWNLOAD_MAX);
  }
  const seconds = (performance.now() - overallT0) / 1000;
  return { mbps: seconds > 0 ? totalBytes * 8 / seconds / 1e6 : 0,
           bytes: totalBytes, seconds };
}
const _RANDOM_CHUNK = (() => {
  const c = new Uint8Array(65536);
  if (window.crypto && crypto.getRandomValues) crypto.getRandomValues(c);
  else for (let i = 0; i < c.length; i++) c[i] = (Math.random() * 256) | 0;
  return c;
})();
function makePayload(size){
  const chunk = _RANDOM_CHUNK;
  const parts = [];
  let remaining = size;
  while (remaining > 0){
    const n = Math.min(chunk.length, remaining);
    parts.push(n === chunk.length ? chunk : chunk.subarray(0, n));
    remaining -= n;
  }
  return new Blob(parts);
}
function uploadOnce(bytes, overallT0, baseBytes, minSeconds, onProgress){
  return new Promise((resolve, reject) => {
    let payload;
    try { payload = makePayload(bytes); } catch(e){ return reject(e); }
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/speedtest/upload?r=" + Math.random(), true);
    const t = Token.get();
    if (t) xhr.setRequestHeader("Authorization", "Bearer " + t);
    xhr.timeout = 120000;
    const t0 = performance.now();
    let lastLoaded = 0, lastT = t0, lastB = 0;
    let resolved = false, aborted = false;
    function finish(){
      if (resolved) return;
      resolved = true;
      const reqSeconds = (performance.now() - t0) / 1000;
      const sent = lastLoaded > 0 ? lastLoaded : (aborted ? 0 : bytes);
      resolve({ bytes: sent, seconds: reqSeconds, aborted });
    }
    xhr.upload.onprogress = (e) => {
      lastLoaded = e.loaded;
      const now = performance.now();
      const totalElapsed = (now - overallT0) / 1000;
      if (now - lastT >= 150){
        const inst = (e.loaded - lastB) * 8 / ((now - lastT) / 1000) / 1e6;
        if (onProgress) onProgress(inst, baseBytes + e.loaded, totalElapsed);
        lastT = now; lastB = e.loaded;
      }
      if (totalElapsed >= minSeconds){
        aborted = true;
        try { xhr.abort(); } catch(err){}
      }
    };
    xhr.onload = finish;
    xhr.onabort = finish;
    xhr.onerror = () => { if (!resolved){ resolved = true; reject(new Error("网络错误")); } };
    xhr.ontimeout = () => { if (!resolved){ resolved = true; reject(new Error("超时")); } };
    try { xhr.send(payload); } catch(e){ if (!resolved){ resolved = true; reject(e); } }
  });
}
async function uploadTest(onProgress){
  const overallT0 = performance.now();
  let totalBytes = 0;
  let chunkBytes = 4 * 1024 * 1024;
  for (let attempt = 0; attempt < 30; attempt++){
    const elapsed = (performance.now() - overallT0) / 1000;
    if (elapsed >= SPEED_MIN_SECONDS) break;
    if (totalBytes > 0 && elapsed > 0.3){
      const remaining = SPEED_MIN_SECONDS - elapsed;
      const bps = totalBytes / elapsed;
      const ideal = Math.ceil(bps * remaining * 1.15);
      chunkBytes = Math.max(1024 * 1024, Math.min(ideal, SPEED_UPLOAD_CHUNK_MAX));
    }
    const result = await uploadOnce(chunkBytes, overallT0, totalBytes,
                                    SPEED_MIN_SECONDS, onProgress);
    totalBytes += result.bytes;
    if (result.bytes === 0) break;
  }
  const seconds = (performance.now() - overallT0) / 1000;
  return { mbps: seconds > 0 ? totalBytes * 8 / seconds / 1e6 : 0,
           bytes: totalBytes, seconds };
}
async function runSpeedtest(){
  if (SPEED_STATE.running) return;
  SPEED_STATE.running = true;
  const btn = document.getElementById("speed-btn");
  btn.disabled = true; btn.textContent = "测速中...";
  resetSpeedUI();
  try {
    setActiveMetric("ping");
    setSpeedStatus("测量延迟...");
    const ping = await measurePing();
    document.getElementById("speed-ping").textContent = ping.toFixed(1);
    setSpeedBar(10);
    setActiveMetric("down");
    setSpeedStatus("测试下载速度（至少 5 秒）...");
    const dl = await downloadTest((inst, loaded, elapsed) => {
      document.getElementById("speed-down").textContent = inst.toFixed(1);
      document.getElementById("speed-down-sub").textContent =
        (inst / 8).toFixed(2) + " MB/s · " + (elapsed / SPEED_MIN_SECONDS * 100).toFixed(0) + "%";
      setSpeedBar(10 + Math.min(elapsed / SPEED_MIN_SECONDS, 1) * 40);
      setSpeedStatus("下载中... " + inst.toFixed(1) + " Mbps（" + elapsed.toFixed(1) + "s）");
    });
    document.getElementById("speed-down").textContent = dl.mbps.toFixed(1);
    document.getElementById("speed-down-sub").textContent =
      (dl.mbps / 8).toFixed(2) + " MB/s · 用时 " + dl.seconds.toFixed(1) + "s";
    setSpeedBar(50);
    setActiveMetric("up");
    setSpeedStatus("测试上传速度（至少 5 秒）...");
    const ul = await uploadTest((inst, loaded, elapsed) => {
      document.getElementById("speed-up").textContent = inst.toFixed(1);
      document.getElementById("speed-up-sub").textContent =
        (inst / 8).toFixed(2) + " MB/s · " + (elapsed / SPEED_MIN_SECONDS * 100).toFixed(0) + "%";
      setSpeedBar(50 + Math.min(elapsed / SPEED_MIN_SECONDS, 1) * 45);
      setSpeedStatus("上传中... " + inst.toFixed(1) + " Mbps（" + elapsed.toFixed(1) + "s）");
    });
    document.getElementById("speed-up").textContent = ul.mbps.toFixed(1);
    document.getElementById("speed-up-sub").textContent =
      (ul.mbps / 8).toFixed(2) + " MB/s · 用时 " + ul.seconds.toFixed(1) + "s";
    setSpeedBar(100);
    setSpeedStatus("完成 · 延迟 " + ping.toFixed(1) + " ms · 下载 "
      + dl.mbps.toFixed(1) + " Mbps · 上传 " + ul.mbps.toFixed(1) + " Mbps");
  } catch(e){
    setSpeedStatus("测速失败：" + (e && e.message ? e.message : e));
    setSpeedBar(0);
  } finally {
    SPEED_STATE.running = false;
    setActiveMetric(null);
    btn.disabled = false; btn.textContent = "重新测速";
  }
}
document.getElementById("speed-btn").addEventListener("click", runSpeedtest);

let _routerCfg = {};
let _routerIfaces = [];
async function routerLoad(){
  try {
    const r = await api.get("/api/router/config");
    _routerCfg = r.config || {};
    const w = document.getElementById("router-warn");
    w.innerHTML = r.root ? "" :
      '<div class="warn-box">当前进程非 root 运行，应用路由器配置需要以 sudo 启动 NetRouter。</div>';
    await routerDetect();
    fillRouterForm(_routerCfg);
    const st = document.getElementById("router-status-text");
    if (_routerCfg.applied){
      const wgDesc = _routerCfg.wg_enabled
        ? ` · WG ${_routerCfg.wg_mode === "server" ? "服务器" : "客户端"} ${_routerCfg.wg_interface}`
        : "";
      st.innerHTML = '<span style="color:var(--ok)">✓ 已应用</span>'
        + ' · ' + escapeHtml(_routerCfg.applied_at || '')
        + ' · WAN: ' + escapeHtml(_routerCfg.wan_if || '未配置')
        + ' [' + escapeHtml(_routerCfg.wan_mode || 'dhcp') + ']'
        + ' · LAN: ' + escapeHtml(_routerCfg.lan_ifs || '未配置')
        + wgDesc;
    } else {
      st.innerHTML = '<span style="color:var(--warn)">⚠ 尚未应用</span>';
    }
    if ((_routerCfg.wg_mode || "client") === "server") {
      wgLoadPeers();
    }
  } catch(e){ toast(e.message, true); }
}
async function routerDetect(){
  try {
    const d = await api.get("/api/router/detect");
    _routerIfaces = d.interfaces || [];
    const wanSel = _routerCfg.wan_if || "";
    const lanSel = (_routerCfg.lan_ifs || "").split(/\s+/).filter(Boolean);
    renderWanList(wanSel);
    renderLanList(lanSel);
    updateWifiHint();
  } catch(e){ toast(e.message, true); }
}
function ifaceLabel(i){
  const wifiTag = i.wireless ? ' <span style="color:var(--purple)">[W]</span>' : '';
  const carrier = i.carrier ? ' <span style="color:var(--ok)">*</span>' : '';
  const state = '<span style="color:var(--fg-dimmer);font-size:10px;margin-left:4px">'
    + escapeHtml(i.state) + carrier + '</span>';
  return escapeHtml(i.name) + wifiTag + state;
}
function renderWanList(selected){
  const el = document.getElementById("wan-iface-list");
  if (!_routerIfaces.length){
    el.innerHTML = '<div style="color:var(--fg-dimmer)">无可用接口</div>';
    return;
  }
  el.innerHTML = _routerIfaces.map(i => {
    const on = i.name === selected;
    return '<label class="' + (on ? 'checked' : '') + '">'
      + '<input type="radio" name="wan-iface" value="' + escapeAttr(i.name) + '"'
      + (on ? ' checked' : '')
      + ' onchange="onWanSelect(this.value)">'
      + ifaceLabel(i) + '</label>';
  }).join("");
}
function renderLanList(selected){
  const el = document.getElementById("lan-iface-list");
  const wanEl = document.querySelector('input[name="wan-iface"]:checked');
  const wan = wanEl ? wanEl.value : "";
  if (!_routerIfaces.length){
    el.innerHTML = '<div style="color:var(--fg-dimmer)">无可用接口</div>';
    return;
  }
  el.innerHTML = _routerIfaces.map(i => {
    const on = selected.indexOf(i.name) >= 0;
    const isWan = (i.name === wan);
    return '<label class="' + (on ? 'checked' : '')
      + (isWan ? ' disabled' : '') + '">'
      + '<input type="checkbox" value="' + escapeAttr(i.name) + '"'
      + (on ? ' checked' : '')
      + (isWan ? ' disabled' : '')
      + ' onchange="onLanToggle()">'
      + ifaceLabel(i) + '</label>';
  }).join("");
  updateWifiHint();
}
function onWanSelect(name){
  const lanSel = getSelectedLan().filter(x => x !== name);
  _routerCfg.wan_if = name;
  renderWanList(name);
  renderLanList(lanSel);
}
function onLanToggle(){
  document.querySelectorAll('#lan-iface-list label').forEach(lbl => {
    const cb = lbl.querySelector('input[type="checkbox"]');
    if (cb) lbl.classList.toggle('checked', cb.checked && !cb.disabled);
  });
  updateWifiHint();
}
function getSelectedLan(){
  const boxes = document.querySelectorAll(
    '#lan-iface-list input[type="checkbox"]:checked');
  return Array.from(boxes).map(b => b.value);
}
function updateWifiHint(){
  const el = document.getElementById("wifi-hint");
  if (!el) return;
  const lanNames = getSelectedLan();
  const wifi = _routerIfaces.find(i => i.wireless && lanNames.indexOf(i.name) >= 0);
  if (wifi){
    el.innerHTML = 'LAN 中已包含无线接口 <b style="color:var(--fg)">'
      + escapeHtml(wifi.name) + '</b>，将作为 AP 启用';
    el.style.color = "var(--ok)";
  } else {
    el.innerHTML = 'LAN 中未勾选任何无线接口，hostapd 将被跳过';
    el.style.color = "var(--warn)";
  }
}
function onWanModeChange(){
  const mode = document.getElementById("rc-wan-mode").value;
  document.getElementById("wan-static-box").style.display =
    (mode === "static") ? "" : "none";
  document.getElementById("wan-pppoe-box").style.display =
    (mode === "pppoe") ? "" : "none";
}
function onDhcpToggle(){
  const on = document.getElementById("rc-dhcp-enabled").checked;
  document.getElementById("dhcp-box").style.display = on ? "" : "none";
}
function onWgModeChange(){
  const mode = document.getElementById("rc-wg-mode").value;
  document.getElementById("wg-client-box").style.display =
    (mode === "client") ? "" : "none";
  document.getElementById("wg-server-box").style.display =
    (mode === "server") ? "" : "none";
  if (mode === "server") wgLoadPeers();
}
function fillRouterForm(c){
  const setVal = (id, v) => {
    const el = document.getElementById(id);
    if (el) el.value = v == null ? "" : v;
  };
  const setChk = (id, v) => {
    const el = document.getElementById(id);
    if (el) el.checked = !!v;
  };
  setVal("rc-wan-mode", c.wan_mode || "dhcp");
  setVal("rc-wan-ip", c.wan_ip);
  setVal("rc-wan-gw", c.wan_gateway);
  setVal("rc-wan-dns", c.wan_dns);
  setVal("rc-pppoe-user", c.wan_pppoe_user);
  setVal("rc-pppoe-pass", c.wan_pppoe_pass);
  setVal("rc-br", c.br_name);
  setVal("rc-lanip", c.lan_ip);
  setVal("rc-lanmask", c.lan_netmask);
  setChk("rc-dhcp-enabled", c.lan_dhcp_enabled !== false);
  setVal("rc-dhcp-start", c.dhcp_start);
  setVal("rc-dhcp-end", c.dhcp_end);
  setVal("rc-dhcp-lease", c.dhcp_lease);
  setVal("rc-dns", c.dns_servers);
  setVal("rc-ssid", c.wifi_ssid);
  setVal("rc-wpwd", c.wifi_passphrase);
  setVal("rc-country", c.wifi_country);
  setVal("rc-band", c.wifi_band);
  setVal("rc-ch", c.wifi_channel);
  setVal("rc-cw", c.wifi_channel_width);
  setChk("rc-wg-enable", c.wg_enabled);
  setVal("rc-wg-mode", c.wg_mode || "client");
  setVal("rc-wg-if", c.wg_interface || "wg0");
  setVal("rc-wg-addr", c.wg_address);
  setVal("rc-wg-end", c.wg_endpoint);
  setVal("rc-wg-allowed", c.wg_allowed_ips);
  setVal("rc-wg-pub", c.wg_server_pubkey);
  setVal("rc-wg-priv", c.wg_private_key);
  setVal("rc-wg-psk", c.wg_preshared_key);
  setVal("rc-wg-ka", c.wg_keepalive);
  setVal("rc-wg-if-srv", c.wg_interface || "wg0");
  setVal("rc-wg-srv-addr", c.wg_server_address);
  setVal("rc-wg-srv-port", c.wg_server_port);
  setVal("rc-wg-srv-end", c.wg_server_endpoint);
  setVal("rc-wg-client-dns", c.wg_client_dns);
  setVal("rc-wg-client-allowed", c.wg_client_allowed_ips);
  setVal("rc-wg-srv-priv", c.wg_server_private_key);
  setVal("rc-wg-ka-srv", c.wg_keepalive);
  onWanModeChange();
  onDhcpToggle();
  onWgModeChange();
}
function collectRouterForm(){
  const wanEl = document.querySelector('input[name="wan-iface"]:checked');
  const wanIf = wanEl ? wanEl.value : "";
  const wgMode = document.getElementById("rc-wg-mode").value;
  const wgIf = (wgMode === "server")
    ? (document.getElementById("rc-wg-if-srv").value.trim() || "wg0")
    : (document.getElementById("rc-wg-if").value.trim() || "wg0");
  return {
    wan_if: wanIf,
    wan_mode: document.getElementById("rc-wan-mode").value,
    wan_ip: document.getElementById("rc-wan-ip").value.trim(),
    wan_gateway: document.getElementById("rc-wan-gw").value.trim(),
    wan_dns: document.getElementById("rc-wan-dns").value.trim(),
    wan_pppoe_user: document.getElementById("rc-pppoe-user").value.trim(),
    wan_pppoe_pass: document.getElementById("rc-pppoe-pass").value,
    lan_ifs: getSelectedLan().join(" "),
    br_name: document.getElementById("rc-br").value.trim() || "br-lan",
    lan_ip: document.getElementById("rc-lanip").value.trim(),
    lan_netmask: document.getElementById("rc-lanmask").value.trim(),
    lan_dhcp_enabled: document.getElementById("rc-dhcp-enabled").checked,
    dhcp_start: document.getElementById("rc-dhcp-start").value.trim(),
    dhcp_end: document.getElementById("rc-dhcp-end").value.trim(),
    dhcp_lease: document.getElementById("rc-dhcp-lease").value.trim(),
    dns_servers: document.getElementById("rc-dns").value.trim(),
    wifi_ssid: document.getElementById("rc-ssid").value.trim(),
    wifi_passphrase: document.getElementById("rc-wpwd").value,
    wifi_country: document.getElementById("rc-country").value.trim() || "CN",
    wifi_band: document.getElementById("rc-band").value,
    wifi_channel: document.getElementById("rc-ch").value.trim(),
    wifi_channel_width: document.getElementById("rc-cw").value,
    wg_enabled: document.getElementById("rc-wg-enable").checked,
    wg_mode: wgMode,
    wg_interface: wgIf,
    wg_keepalive: (wgMode === "server")
      ? (document.getElementById("rc-wg-ka-srv").value.trim() || "25")
      : (document.getElementById("rc-wg-ka").value.trim() || "25"),
    wg_address: document.getElementById("rc-wg-addr").value.trim(),
    wg_endpoint: document.getElementById("rc-wg-end").value.trim(),
    wg_allowed_ips: document.getElementById("rc-wg-allowed").value.trim(),
    wg_server_pubkey: document.getElementById("rc-wg-pub").value.trim(),
    wg_private_key: document.getElementById("rc-wg-priv").value.trim(),
    wg_preshared_key: document.getElementById("rc-wg-psk").value.trim(),
    wg_server_address: document.getElementById("rc-wg-srv-addr").value.trim(),
    wg_server_port: document.getElementById("rc-wg-srv-port").value.trim() || "51820",
    wg_server_endpoint: document.getElementById("rc-wg-srv-end").value.trim(),
    wg_client_dns: document.getElementById("rc-wg-client-dns").value.trim(),
    wg_client_allowed_ips: document.getElementById("rc-wg-client-allowed").value.trim(),
    wg_server_private_key: document.getElementById("rc-wg-srv-priv").value.trim(),
  };
}
document.getElementById("btn-router-save").onclick = async () => {
  const cfg = collectRouterForm();
  try {
    await api.post("/api/router/config", cfg);
    toast("配置已保存");
  } catch(e){ toast(e.message, true); }
};
document.getElementById("btn-router-apply").onclick = async () => {
  const cfg = collectRouterForm();
  if (!cfg.wan_if){ toast("请选择 WAN 接口", true); return; }
  if (!cfg.lan_ifs){ toast("请至少勾选一个 LAN 接口", true); return; }
  if (cfg.wan_mode === "static" && (!cfg.wan_ip || !cfg.wan_gateway)){
    toast("静态 IP 模式需填写 IP 和网关", true); return;
  }
  if (cfg.wan_mode === "pppoe"
      && (!cfg.wan_pppoe_user || !cfg.wan_pppoe_pass)){
    toast("PPPoE 模式需填写用户名和密码", true); return;
  }
  if (cfg.wg_enabled){
    if (cfg.wg_mode === "server" && !cfg.wg_server_address){
      toast("服务器模式需填写本机地址", true); return;
    }
    if (cfg.wg_mode === "client"
        && (!cfg.wg_server_pubkey || !cfg.wg_endpoint)){
      toast("客户端模式需填写服务器公钥和 Endpoint", true); return;
    }
  }
  if (!confirm("即将保存配置并应用网络/防火墙/WiFi/WireGuard 设置。\n"
    + "（不安装包，请先在「包管理」中安装）\n"
    + "将自动创建基础防火墙区域（lan→wan 放行、其余拒绝），\n"
    + "并默认放行 wan TCP 22 与管理端口。\n"
    + "可能导致当前网络中断，是否继续？")) return;
  const btn = document.getElementById("btn-router-apply");
  btn.disabled = true; btn.textContent = "应用中...";
  const stepsEl = document.getElementById("router-steps");
  stepsEl.innerHTML = "";
  try {
    const r = await api.post("/api/router/apply",
      {config: cfg, install: false, apply_network: true});
    renderSteps(r.steps || []);
    toast(r.ok ? "应用完成" : ("失败：" + r.message), !r.ok);
    if (r.ok) routerLoad();
  } catch(e){ toast(e.message, true); }
  finally { btn.disabled = false; btn.textContent = "一键应用（保存+配置+启动）"; }
};
function renderSteps(steps){
  const el = document.getElementById("router-steps");
  el.innerHTML = steps.map(s => {
    const cls = s.ok ? "ok" : "err";
    const ico = s.ok ? "OK" : "!!";
    return '<div class="step ' + cls + '">'
      + '<span class="st-ico">' + ico + '</span>'
      + '<span class="st-name">' + escapeHtml(s.name || "") + '</span>'
      + '<span class="st-msg">' + escapeHtml((s.message || "").slice(0, 600)) + '</span>'
      + '</div>';
  }).join("");
}

let _wgPeers = [];
async function wgLoadPeers(){
  const el = document.getElementById("wg-peers");
  if (!el) return;
  el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">加载中...</div>';
  try {
    const r = await api.get("/api/wireguard/peers");
    _wgPeers = r.peers || [];
    renderWgPeers();
  } catch(e){
    el.innerHTML = '<div style="color:var(--danger)">' + escapeHtml(e.message) + '</div>';
  }
}
function renderWgPeers(){
  const el = document.getElementById("wg-peers");
  if (!_wgPeers.length){
    el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px;padding:6px 0">'
      + '暂无对端。点击「+ 添加对端」创建第一个客户端。</div>';
    return;
  }
  let html = '<table class="tbl"><thead><tr>'
    + '<th>名称</th><th>地址</th><th>公钥</th>'
    + '<th>创建时间</th><th style="width:250px"></th>'
    + '</tr></thead><tbody>';
  for (const p of _wgPeers){
    const shortPub = (p.public_key || "").slice(0, 20) + "...";
    html += '<tr>'
      + '<td style="color:var(--fg);font-weight:600">' + escapeHtml(p.name) + '</td>'
      + '<td style="font-family:ui-monospace,monospace">' + escapeHtml(p.address) + '</td>'
      + '<td style="font-family:ui-monospace,monospace;font-size:11px" title="'
      +   escapeAttr(p.public_key) + '">' + escapeHtml(shortPub) + '</td>'
      + '<td style="font-size:11px;color:var(--fg-dim)">' + escapeHtml(p.created_at || "") + '</td>'
      + '<td style="text-align:right;white-space:nowrap">'
      + '<button class="btn btn-inverse btn-sm" onclick="wgShowPeerConfig(\''
      +   escapeAttr(p.id) + '\')">查看配置</button> '
      + '<button class="btn btn-danger btn-sm" onclick="wgDeletePeer(\''
      +   escapeAttr(p.id) + '\',\'' + escapeAttr(p.name) + '\')">删除</button>'
      + '</td></tr>';
  }
  html += '</tbody></table>';
  el.innerHTML = html;
}
async function wgAddPeer(){
  const name = prompt("对端名称（字母、数字、_.-）", "");
  if (name === null) return;
  if (!name.trim()){ toast("名称不能为空", true); return; }
  try {
    const r = await api.post("/api/wireguard/peer/add", {name: name.trim()});
    toast("已添加对端：" + r.peer.name);
    await wgLoadPeers();
    wgShowConfigDialog(r.peer.name, r.config);
  } catch(e){ toast(e.message, true); }
}
async function wgDeletePeer(id, name){
  if (!confirm("删除对端 " + name + " ？\n删除后需重新应用配置生效。")) return;
  try {
    await api.post("/api/wireguard/peer/remove", {id});
    toast("已删除");
    await wgLoadPeers();
  } catch(e){ toast(e.message, true); }
}
async function wgShowPeerConfig(id){
  try {
    const r = await api.get("/api/wireguard/peer/"
      + encodeURIComponent(id) + "/config");
    wgShowConfigDialog(r.name, r.config);
  } catch(e){ toast(e.message, true); }
}
function wgShowConfigDialog(name, config){
  const title = "客户端配置 · " + name;
  const body = ''
    + '<div style="color:var(--fg-dim);font-size:12px;margin-bottom:10px">'
    + '将该文本保存为 <code style="background:var(--bg);padding:2px 6px;'
    + 'border-radius:2px">' + escapeHtml(name) + '.conf</code> '
    + '导入 WireGuard 客户端即可。</div>'
    + '<textarea id="wg-cfg-text" readonly '
    + 'style="width:100%;height:280px;font-family:ui-monospace,monospace;'
    + 'font-size:12px;resize:vertical;line-height:1.5">'
    + escapeHtml(config) + '</textarea>'
    + '<div class="actions" style="margin-top:12px">'
    + '<button class="btn" id="wg-cfg-copy" type="button">复制</button>'
    + '<button class="btn btn-inverse" id="wg-cfg-dl" type="button">下载 .conf</button>'
    + '</div>';
  fwOpenModal("wg", -1, title, body, () => { fwCloseModal(); });
  document.getElementById("fw-modal-save").textContent = "关闭";
  document.getElementById("wg-cfg-copy").onclick = async () => {
    try {
      await navigator.clipboard.writeText(config);
      toast("已复制到剪贴板");
    } catch(_){
      const ta = document.getElementById("wg-cfg-text");
      ta.select(); document.execCommand("copy"); toast("已复制");
    }
  };
  document.getElementById("wg-cfg-dl").onclick = () => {
    const blob = new Blob([config], {type: "text/plain"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name + ".conf";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
}

let _fwCfg = {enabled: true, zones: [], forwardings: [],
              port_forwards: [], input_rules: []};
let _fwIfaces = [];
let _fwModal = {mode: null, idx: -1};

async function fwLoadZones(){
  try {
    const [cfgR, ifR] = await Promise.all([
      api.get("/api/firewall/zones"),
      api.get("/api/firewall/interfaces"),
    ]);
    _fwCfg = cfgR.config || {};
    _fwCfg.zones = _fwCfg.zones || [];
    _fwCfg.forwardings = _fwCfg.forwardings || [];
    _fwCfg.port_forwards = _fwCfg.port_forwards || [];
    _fwCfg.input_rules = _fwCfg.input_rules || [];
    _fwCfg.enabled = true;
    _fwIfaces = (ifR.interfaces || []).map(x => x.name);
    fwRenderZones();
    fwRenderForwardings();
    fwRenderPortForwards();
    fwRenderInputRules();
  } catch(e){ toast(e.message, true); }
}
function fwRenderZones(){
  const el = document.getElementById("fw-zones");
  const zones = _fwCfg.zones;
  if (!zones.length){
    el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px;padding:6px 0">'
      + '尚未定义区域。请先在「路由器」页执行一键应用，自动创建基础区域。</div>';
    return;
  }
  let html = '<table class="tbl"><thead><tr>'
    + '<th>名称</th><th>接口</th><th>输入</th><th>输出</th><th>转发</th>'
    + '<th>地址伪装</th><th style="width:130px"></th></tr></thead><tbody>';
  zones.forEach((z, i) => {
    html += '<tr>'
      + '<td style="color:var(--fg);font-weight:600">' + escapeHtml(z.name) + '</td>'
      + '<td style="font-size:12px">' + escapeHtml((z.interfaces||[]).join(", ") || "—") + '</td>'
      + '<td style="font-size:11px">' + escapeHtml(z.input || "ACCEPT") + '</td>'
      + '<td style="font-size:11px">' + escapeHtml(z.output || "ACCEPT") + '</td>'
      + '<td style="font-size:11px">' + escapeHtml(z.forward || "ACCEPT") + '</td>'
      + '<td>' + (z.masq ? '<span style="color:var(--ok)">✓</span>' : '—') + '</td>'
      + '<td style="text-align:right;white-space:nowrap">'
      + '<button class="btn btn-inverse btn-sm" onclick="fwEditZone(' + i + ')">编辑</button> '
      + '<button class="btn btn-danger btn-sm" onclick="fwDeleteZone(' + i + ')">删除</button>'
      + '</td></tr>';
  });
  html += '</tbody></table>';
  el.innerHTML = html;
}
function fwRenderForwardings(){
  const el = document.getElementById("fw-forwardings");
  const list = _fwCfg.forwardings || [];
  if (!list.length){
    el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px;padding:6px 0">'
      + '尚未定义转发规则。典型：<b style="color:var(--fg)">lan → wan</b></div>';
    return;
  }
  let html = '<table class="tbl"><thead><tr>'
    + '<th>源区域</th><th>目标区域</th><th>状态</th>'
    + '<th style="width:170px"></th></tr></thead><tbody>';
  list.forEach((f, i) => {
    html += '<tr>'
      + '<td style="color:var(--fg)">' + escapeHtml(f.src) + '</td>'
      + '<td style="color:var(--fg)">' + escapeHtml(f.dest) + '</td>'
      + '<td>' + (f.enabled !== false
          ? '<span style="color:var(--ok)">启用</span>'
          : '<span style="color:var(--fg-dim)">禁用</span>') + '</td>'
      + '<td style="text-align:right;white-space:nowrap">'
      + '<button class="btn btn-inverse btn-sm" onclick="fwToggleForwarding(' + i + ')">'
      +   (f.enabled !== false ? "禁用" : "启用") + '</button> '
      + '<button class="btn btn-danger btn-sm" onclick="fwDeleteForwarding(' + i + ')">删除</button>'
      + '</td></tr>';
  });
  html += '</tbody></table>';
  el.innerHTML = html;
}
function fwRenderPortForwards(){
  const el = document.getElementById("fw-port-forwards");
  const list = _fwCfg.port_forwards || [];
  if (!list.length){
    el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px;padding:6px 0">'
      + '尚未定义端口转发规则</div>';
    return;
  }
  let html = '<table class="tbl"><thead><tr>'
    + '<th>名称</th><th>协议</th><th>源区域</th><th>外部端口</th>'
    + '<th>内部地址</th><th>内部端口</th><th>状态</th>'
    + '<th style="width:170px"></th></tr></thead><tbody>';
  list.forEach((p, i) => {
    html += '<tr>'
      + '<td style="color:var(--fg);font-weight:600">' + escapeHtml(p.name) + '</td>'
      + '<td>' + escapeHtml((p.proto || "tcp").toUpperCase()) + '</td>'
      + '<td>' + escapeHtml(p.src_zone) + '</td>'
      + '<td style="font-family:ui-monospace,monospace">' + p.src_port + '</td>'
      + '<td style="font-family:ui-monospace,monospace">' + escapeHtml(p.dest_ip) + '</td>'
      + '<td style="font-family:ui-monospace,monospace">' + p.dest_port + '</td>'
      + '<td>' + (p.enabled !== false
          ? '<span style="color:var(--ok)">启用</span>'
          : '<span style="color:var(--fg-dim)">禁用</span>') + '</td>'
      + '<td style="text-align:right;white-space:nowrap">'
      + '<button class="btn btn-inverse btn-sm" onclick="fwEditPortForward(' + i + ')">编辑</button> '
      + '<button class="btn btn-danger btn-sm" onclick="fwDeletePortForward(' + i + ')">删除</button>'
      + '</td></tr>';
  });
  html += '</tbody></table>';
  el.innerHTML = html;
}
function fwRenderInputRules(){
  const el = document.getElementById("fw-input-rules");
  const list = _fwCfg.input_rules || [];
  if (!list.length){
    el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px;padding:6px 0">'
      + '尚未添加端口规则。示例：wan 区域放行 <b style="color:var(--fg)">22/tcp</b></div>';
    return;
  }
  let html = '<table class="tbl"><thead><tr>'
    + '<th>名称</th><th>区域</th><th>协议</th><th>端口</th>'
    + '<th>源 IP</th><th>动作</th><th>状态</th>'
    + '<th style="width:230px"></th></tr></thead><tbody>';
  list.forEach((r, i) => {
    const zoneLabel = (r.zone === "*" || !r.zone) ? "全局" : r.zone;
    const actColor = r.action === "ACCEPT" ? "var(--ok)"
                   : (r.action === "DROP"   ? "var(--danger)"
                                            : "var(--warn)");
    html += '<tr>'
      + '<td style="color:var(--fg);font-weight:600">' + escapeHtml(r.name) + '</td>'
      + '<td>' + escapeHtml(zoneLabel) + '</td>'
      + '<td>' + escapeHtml((r.proto || "tcp").toUpperCase()) + '</td>'
      + '<td style="font-family:ui-monospace,monospace">' + escapeHtml(r.port) + '</td>'
      + '<td style="font-family:ui-monospace,monospace">' + escapeHtml(r.src_ip || "任意") + '</td>'
      + '<td><span style="color:' + actColor + '">' + escapeHtml(r.action) + '</span></td>'
      + '<td>' + (r.enabled !== false
          ? '<span style="color:var(--ok)">启用</span>'
          : '<span style="color:var(--fg-dim)">禁用</span>') + '</td>'
      + '<td style="text-align:right;white-space:nowrap">'
      + '<button class="btn btn-inverse btn-sm" onclick="fwToggleInputRule(' + i + ')">'
      +   (r.enabled !== false ? "禁用" : "启用") + '</button> '
      + '<button class="btn btn-inverse btn-sm" onclick="fwEditInputRule(' + i + ')">编辑</button> '
      + '<button class="btn btn-danger btn-sm" onclick="fwDeleteInputRule(' + i + ')">删除</button>'
      + '</td></tr>';
  });
  html += '</tbody></table>';
  el.innerHTML = html;
}
function fwOpenModal(mode, idx, title, bodyHtml, onSave){
  _fwModal = {mode, idx};
  document.getElementById("fw-modal-title").textContent = title;
  document.getElementById("fw-modal-body").innerHTML = bodyHtml;
  document.getElementById("fw-modal").classList.remove("hidden");
  document.getElementById("fw-modal-save").onclick = onSave;
}
function fwCloseModal(){
  document.getElementById("fw-modal").classList.add("hidden");
  const btn = document.getElementById("fw-modal-save");
  if (btn) btn.textContent = "保存";
  _fwModal = {mode: null, idx: -1};
}
document.getElementById("fw-modal-cancel").onclick = fwCloseModal;
function _fwZoneOptions(selected, includeEmpty){
  let h = includeEmpty ? '<option value="">— 请选择 —</option>' : '';
  for (const z of _fwCfg.zones){
    h += '<option value="' + escapeAttr(z.name) + '"'
       + (z.name === selected ? ' selected' : '') + '>'
       + escapeHtml(z.name) + '</option>';
  }
  return h;
}
function fwAddZone(){ fwEditZone(-1); }
function fwEditZone(idx){
  const z = idx >= 0 ? _fwCfg.zones[idx] : {
    name: "", interfaces: [], input: "ACCEPT",
    output: "ACCEPT", forward: "ACCEPT", masq: false, mtu_fix: false
  };
  const zc = JSON.parse(JSON.stringify(z));
  const ifacesHtml = _fwIfaces.length
    ? _fwIfaces.map(name => {
        const on = (zc.interfaces || []).indexOf(name) >= 0;
        return '<label class="checkbox-row" style="padding:7px 10px;'
          + 'border:1px solid var(--line);border-radius:2px;font-size:12px">'
          + '<input type="checkbox" value="' + escapeAttr(name) + '"'
          + (on ? ' checked' : '') + '> ' + escapeHtml(name) + '</label>';
      }).join("")
    : '<div style="color:var(--fg-dimmer);font-size:12px">未检测到接口</div>';
  const opts = (v) => ["ACCEPT", "REJECT", "DROP"]
    .map(a => '<option value="' + a + '"'
      + (a === v ? ' selected' : '') + '>' + a + '</option>').join("");
  const body = '<div class="form-col">'
    + '<label>区域名称'
    + '<input id="z-name" value="' + escapeAttr(zc.name) + '"'
    + (idx >= 0 ? ' disabled' : '')
    + ' placeholder="lan / wan / guest"></label>'
    + '<div><div style="font-size:12px;color:var(--fg-dim);margin-bottom:6px">接口</div>'
    + '<div class="member-grid" id="z-ifaces" '
    + 'style="grid-template-columns:repeat(auto-fill,minmax(140px,1fr))">'
    + ifacesHtml + '</div></div>'
    + '<div class="form-row">'
    + '<label>输入策略<select id="z-input">' + opts(zc.input) + '</select></label>'
    + '<label>输出策略<select id="z-output">' + opts(zc.output) + '</select></label>'
    + '<label>转发策略<select id="z-forward">' + opts(zc.forward) + '</select></label>'
    + '</div>'
    + '<label class="checkbox-row" style="flex-direction:row">'
    + '<input type="checkbox" id="z-masq"' + (zc.masq ? ' checked' : '') + '> '
    + '启用地址伪装 (masquerade)</label>'
    + '<label class="checkbox-row" style="flex-direction:row">'
    + '<input type="checkbox" id="z-mtu"' + (zc.mtu_fix ? ' checked' : '') + '> '
    + 'MSS 钳制（MTU 修复）</label>'
    + '<div style="color:var(--warn);font-size:11.5px;line-height:1.6">'
    + '提示：input 策略为 DROP 的区域将无法直连路由器本机服务；'
    + '可在「端口开放 / 关闭」中单独放行。</div>'
    + '</div>';
  fwOpenModal("zone", idx, idx >= 0 ? "编辑区域" : "添加区域", body, () => {
    const name = (document.getElementById("z-name").value || "").trim();
    if (!/^[A-Za-z0-9_-]{1,32}$/.test(name)){
      toast("区域名需为 1-32 位字母/数字/-/_", true); return;
    }
    const ifs = Array.from(
      document.querySelectorAll('#z-ifaces input[type="checkbox"]:checked')
    ).map(x => x.value);
    const zone = {
      name, interfaces: ifs,
      input:   document.getElementById("z-input").value,
      output:  document.getElementById("z-output").value,
      forward: document.getElementById("z-forward").value,
      masq:    document.getElementById("z-masq").checked,
      mtu_fix: document.getElementById("z-mtu").checked,
    };
    if (idx >= 0){
      _fwCfg.zones[idx] = zone;
    } else {
      if (_fwCfg.zones.some(z => z.name === name)){
        toast("区域名已存在", true); return;
      }
      _fwCfg.zones.push(zone);
    }
    fwRenderZones(); fwRenderForwardings();
    fwRenderPortForwards(); fwRenderInputRules();
    fwCloseModal();
  });
}
function fwDeleteZone(idx){
  const z = _fwCfg.zones[idx];
  if (!z) return;
  if (!confirm("删除区域 " + z.name + " ？\n引用该区域的转发 / 端口规则也会被移除。")) return;
  const name = z.name;
  _fwCfg.zones.splice(idx, 1);
  _fwCfg.forwardings = _fwCfg.forwardings.filter(f => f.src !== name && f.dest !== name);
  _fwCfg.port_forwards = _fwCfg.port_forwards.filter(p => p.src_zone !== name);
  _fwCfg.input_rules = _fwCfg.input_rules.filter(r => r.zone !== name);
  fwRenderZones(); fwRenderForwardings();
  fwRenderPortForwards(); fwRenderInputRules();
}
function fwAddForwarding(){
  if (_fwCfg.zones.length < 2){
    toast("至少需要 2 个区域才能添加转发", true); return;
  }
  const body = '<div class="form-col">'
    + '<div class="form-row">'
    + '<label>源区域<select id="f-src">' + _fwZoneOptions("", true) + '</select></label>'
    + '<label>目标区域<select id="f-dest">' + _fwZoneOptions("", true) + '</select></label>'
    + '</div>'
    + '<label class="checkbox-row" style="flex-direction:row">'
    + '<input type="checkbox" id="f-enabled" checked> 启用</label>'
    + '</div>';
  fwOpenModal("forwarding", -1, "添加区域转发", body, () => {
    const src  = document.getElementById("f-src").value;
    const dest = document.getElementById("f-dest").value;
    if (!src || !dest){ toast("请选择源/目标区域", true); return; }
    if (src === dest){ toast("源与目标区域不能相同", true); return; }
    if (_fwCfg.forwardings.some(f => f.src === src && f.dest === dest)){
      toast("该转发规则已存在", true); return;
    }
    _fwCfg.forwardings.push({
      src, dest,
      enabled: document.getElementById("f-enabled").checked,
    });
    fwRenderForwardings(); fwCloseModal();
  });
}
function fwToggleForwarding(i){
  const f = _fwCfg.forwardings[i];
  if (!f) return;
  f.enabled = !(f.enabled !== false);
  fwRenderForwardings();
}
function fwDeleteForwarding(i){
  const f = _fwCfg.forwardings[i];
  if (!f) return;
  if (!confirm("删除转发规则 " + f.src + " → " + f.dest + " ？")) return;
  _fwCfg.forwardings.splice(i, 1);
  fwRenderForwardings();
}
function fwAddPortForward(){ fwEditPortForward(-1); }
function fwEditPortForward(idx){
  if (!_fwCfg.zones.length){
    toast("请先定义至少一个区域", true); return;
  }
  const p = idx >= 0 ? _fwCfg.port_forwards[idx] : {
    name: "", proto: "tcp", src_zone: _fwCfg.zones[0].name,
    src_port: 0, dest_ip: "", dest_port: 0,
    src_ip: "", enabled: true,
  };
  const pc = JSON.parse(JSON.stringify(p));
  const body = '<div class="form-col">'
    + '<label>规则名称<input id="p-name" value="' + escapeAttr(pc.name)
    + '" placeholder="例如 web-server"></label>'
    + '<div class="form-row">'
    + '<label>协议<select id="p-proto">'
    +   ["tcp", "udp", "tcp+udp"].map(v =>
        '<option value="' + v + '"' + (v === pc.proto ? ' selected' : '') + '>'
        + v.toUpperCase() + '</option>').join("")
    + '</select></label>'
    + '<label>源区域<select id="p-zone">'
    +   _fwZoneOptions(pc.src_zone, false)
    + '</select></label>'
    + '</div>'
    + '<div class="form-row">'
    + '<label>外部端口<input id="p-sport" type="number" min="1" max="65535" value="'
    +   (pc.src_port || "") + '"></label>'
    + '<label>内部 IP<input id="p-dip" value="' + escapeAttr(pc.dest_ip)
    +   '" placeholder="192.168.10.100"></label>'
    + '<label>内部端口<input id="p-dport" type="number" min="1" max="65535" value="'
    +   (pc.dest_port || "") + '"></label>'
    + '</div>'
    + '<label>源 IP 限制（可选）'
    + '<input id="p-sip" value="' + escapeAttr(pc.src_ip || "")
    + '" placeholder="203.0.113.5"></label>'
    + '<label class="checkbox-row" style="flex-direction:row">'
    + '<input type="checkbox" id="p-enabled"'
    +   (pc.enabled !== false ? ' checked' : '') + '> 启用</label>'
    + '</div>';
  fwOpenModal("port", idx, idx >= 0 ? "编辑端口转发" : "添加端口转发", body, () => {
    const name = (document.getElementById("p-name").value || "").trim() || "rule";
    const proto = document.getElementById("p-proto").value;
    const src_zone = document.getElementById("p-zone").value;
    const src_port = parseInt(document.getElementById("p-sport").value, 10);
    const dest_ip = (document.getElementById("p-dip").value || "").trim();
    const dest_port = parseInt(document.getElementById("p-dport").value, 10);
    const src_ip = (document.getElementById("p-sip").value || "").trim();
    if (!src_zone){ toast("请选择源区域", true); return; }
    if (!(src_port > 0 && src_port < 65536)){ toast("外部端口无效", true); return; }
    if (!(dest_port > 0 && dest_port < 65536)){ toast("内部端口无效", true); return; }
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(dest_ip) && dest_ip.indexOf(":") < 0){
      toast("内部 IP 格式无效", true); return;
    }
    if (src_ip && !/^(\d{1,3}\.){3}\d{1,3}$/.test(src_ip)
        && src_ip.indexOf(":") < 0){
      toast("源 IP 格式无效", true); return;
    }
    const rule = {
      name, proto, src_zone, src_port, dest_ip, dest_port,
      enabled: document.getElementById("p-enabled").checked,
    };
    if (src_ip) rule.src_ip = src_ip;
    if (idx >= 0) _fwCfg.port_forwards[idx] = rule;
    else _fwCfg.port_forwards.push(rule);
    fwRenderPortForwards(); fwCloseModal();
  });
}
function fwDeletePortForward(i){
  const p = _fwCfg.port_forwards[i];
  if (!p) return;
  if (!confirm("删除端口转发 " + p.name + " ？")) return;
  _fwCfg.port_forwards.splice(i, 1);
  fwRenderPortForwards();
}
function fwAddInputRule(){ fwEditInputRule(-1); }
function fwEditInputRule(idx){
  if (!_fwCfg.zones.length){
    toast("请先定义至少一个区域", true); return;
  }
  const r = idx >= 0 ? _fwCfg.input_rules[idx] : {
    name: "", zone: _fwCfg.zones[0].name, proto: "tcp",
    port: "", src_ip: "", action: "ACCEPT", enabled: true,
  };
  const rc = JSON.parse(JSON.stringify(r));
  const zoneOpts = _fwCfg.zones.map(z =>
    '<option value="' + escapeAttr(z.name) + '"'
    + (z.name === rc.zone ? ' selected' : '') + '>'
    + escapeHtml(z.name) + '</option>').join("");
  const actionOpts = ["ACCEPT", "REJECT", "DROP"].map(a =>
    '<option value="' + a + '"' + (a === rc.action ? ' selected' : '') + '>'
    + a + '</option>').join("");
  const body = '<div class="form-col">'
    + '<label>规则名称<input id="ir-name" value="' + escapeAttr(rc.name)
    + '" placeholder="例如 allow-ssh"></label>'
    + '<div class="form-row">'
    + '<label>区域<select id="ir-zone">' + zoneOpts + '</select></label>'
    + '<label>协议<select id="ir-proto">'
    +   ["tcp", "udp", "tcp+udp"].map(v =>
        '<option value="' + v + '"' + (v === rc.proto ? ' selected' : '') + '>'
        + v.toUpperCase() + '</option>').join("")
    + '</select></label>'
    + '</div>'
    + '<div class="form-row">'
    + '<label>端口<input id="ir-port" value="' + escapeAttr(rc.port)
    +   '" placeholder="22 或 8000-8100"></label>'
    + '<label>源 IP（可选）<input id="ir-sip" value="' + escapeAttr(rc.src_ip || "")
    +   '" placeholder="留空表示任意"></label>'
    + '</div>'
    + '<div class="form-row">'
    + '<label>动作<select id="ir-action">' + actionOpts + '</select></label>'
    + '<label class="checkbox-row" style="flex:0 0 auto;align-self:flex-end">'
    +   '<input type="checkbox" id="ir-enabled"'
    +   (rc.enabled !== false ? ' checked' : '') + '> 启用</label>'
    + '</div>'
    + '<div style="color:var(--fg-dimmer);font-size:11.5px;line-height:1.7">'
    + '规则按列表顺序匹配。ACCEPT 放行；DROP/REJECT 显式拒绝。'
    + '</div>'
    + '</div>';
  fwOpenModal("input", idx, idx >= 0 ? "编辑端口规则" : "添加端口规则", body, () => {
    const name = (document.getElementById("ir-name").value || "").trim() || "rule";
    const zone = document.getElementById("ir-zone").value;
    const proto = document.getElementById("ir-proto").value;
    const port = (document.getElementById("ir-port").value || "").trim();
    const sip = (document.getElementById("ir-sip").value || "").trim();
    const action = document.getElementById("ir-action").value;
    if (!/^\d{1,5}(-\d{1,5})?$/.test(port)){
      toast("端口格式：单个数字或范围（如 22 或 8000-8100）", true); return;
    }
    const parts = port.split("-");
    const lo = parseInt(parts[0], 10);
    const hi = parts.length > 1 ? parseInt(parts[1], 10) : lo;
    if (!(lo > 0 && lo < 65536) || !(hi > 0 && hi < 65536) || lo > hi){
      toast("端口超出范围（1-65535）", true); return;
    }
    const rule = {
      name, zone, proto,
      port: (lo === hi ? String(lo) : lo + "-" + hi),
      action,
      enabled: document.getElementById("ir-enabled").checked,
    };
    if (sip){
      if (sip.indexOf(":") >= 0){
        if (!/^[0-9a-fA-F:]+$/.test(sip)){ toast("IPv6 地址格式无效", true); return; }
      } else if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(sip)){
        toast("IPv4 地址格式无效", true); return;
      }
      rule.src_ip = sip;
    }
    if (idx >= 0) _fwCfg.input_rules[idx] = rule;
    else _fwCfg.input_rules.push(rule);
    fwRenderInputRules(); fwCloseModal();
  });
}
function fwToggleInputRule(i){
  const r = _fwCfg.input_rules[i];
  if (!r) return;
  r.enabled = !(r.enabled !== false);
  fwRenderInputRules();
}
function fwDeleteInputRule(i){
  const r = _fwCfg.input_rules[i];
  if (!r) return;
  if (!confirm("删除端口规则 " + r.name + " ？")) return;
  _fwCfg.input_rules.splice(i, 1);
  fwRenderInputRules();
}
document.getElementById("fw-btn-apply").onclick = async () => {
  const btn = document.getElementById("fw-btn-apply");
  const msg = document.getElementById("fw-apply-msg");
  btn.disabled = true;
  const old = btn.textContent;
  btn.textContent = "应用中...";
  msg.textContent = "";
  try {
    const r = await api.post("/api/firewall/apply-zones", {config: _fwCfg});
    msg.textContent = r.message || "";
    msg.style.color = r.ok ? "var(--ok)" : "var(--danger)";
    toast(r.ok ? "已应用" : ("失败：" + r.message), !r.ok);
    if (r.config){
      _fwCfg = r.config;
      _fwCfg.zones = _fwCfg.zones || [];
      _fwCfg.forwardings = _fwCfg.forwardings || [];
      _fwCfg.port_forwards = _fwCfg.port_forwards || [];
      _fwCfg.input_rules = _fwCfg.input_rules || [];
      fwRenderZones(); fwRenderForwardings();
      fwRenderPortForwards(); fwRenderInputRules();
    }
    loadFirewallAll();
  } catch(e){
    msg.textContent = e.message;
    msg.style.color = "var(--danger)";
    toast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = old;
  }
};
async function loadFirewallAll(){
  try {
    const data = await api.get("/api/firewall/all");
    const root = document.getElementById("fw-tables");
    if (data.error){
      root.innerHTML = '<div style="color:var(--danger)">' + escapeHtml(data.error) + '</div>';
      return;
    }
    if (!data.tables.length){
      root.innerHTML = '<div style="color:var(--fg-dimmer)">未发现 nftables 表</div>';
      return;
    }
    root.innerHTML = data.tables.map(t => renderFwTable(t)).join("");
    root.querySelectorAll(".fw-table-block").forEach(b => {
      if (b.dataset.router === "1") b.classList.add("open");
    });
  } catch(e){ toast(e.message, true); }
}
function renderFwTable(t){
  const totalRules = t.chains.reduce((s,c)=>s+(c.rules||[]).length, 0);
  const chainsHtml = t.chains.map(c => {
    const meta = [];
    if (c.type) meta.push("type=" + c.type);
    if (c.hook) meta.push("hook=" + c.hook);
    if (c.prio !== undefined && c.prio !== null) meta.push("prio=" + c.prio);
    if (c.policy) meta.push("policy=" + c.policy);
    const rulesHtml = (c.rules||[]).length
      ? '<table class="tbl"><thead><tr><th style="width:60px">#</th><th>规则</th></tr></thead><tbody>'
      + c.rules.map(r => '<tr><td>' + r.handle + '</td><td>'
      + escapeHtml(r.expr || "(empty)") + '</td></tr>').join("")
      + '</tbody></table>'
      : '<div style="color:var(--fg-dimmer);font-size:12px;padding:4px 0">无规则</div>';
    return '<div class="chain-block"><div class="chain-title">' + escapeHtml(c.name)
      + (meta.length ? '<span class="meta">' + escapeHtml(meta.join("  ")) + '</span>' : '')
      + '</div>' + rulesHtml + '</div>';
  }).join("") || '<div style="color:var(--fg-dimmer)">无链</div>';
  const setsHtml = t.sets.length
    ? '<div style="margin-top:12px;font-size:12px;font-family:ui-monospace,monospace;color:var(--fg-dim);line-height:1.9">'
    + t.sets.map(s => 'set <b style="color:var(--fg);font-weight:500">'
    + escapeHtml(s.name) + '</b> · type=' + escapeHtml(s.type)
    + ' · ' + s.count + ' 元素').join("<br>") + '</div>'
    : "";
  const showFlush = !t.router
    && t.name !== "filter" && t.name !== "nat"
    && t.name !== "mangle" && t.name !== "raw";
  return '<div class="fw-table-block" data-router="' + (t.router?"1":"0") + '">'
    + '<div class="fw-table-head" onclick="toggleFwTable(this)">'
    + '<span class="caret">></span>'
    + '<span class="title">' + escapeHtml(t.family + " " + t.name) + '</span>'
    + (t.router ? '<span class="badge router">ROUTER</span>' : '')
    + '<span class="badge">' + t.chains.length + ' 链</span>'
    + '<span class="badge">' + totalRules + ' 规则</span>'
    + '<span class="spacer"></span>'
    + (showFlush ? '<button class="btn btn-danger btn-sm" onclick="event.stopPropagation();flushFwTable(\''
    + escapeAttr(t.family) + '\',\'' + escapeAttr(t.name) + '\')">清空表</button>' : '')
    + '</div><div class="fw-table-body">'
    + chainsHtml + setsHtml + '</div></div>';
}
window.toggleFwTable = (head) => { head.parentElement.classList.toggle("open"); };
window.flushFwTable = async (family, name) => {
  if (!confirm("清空 " + family + " " + name + " ？不可恢复")) return;
  try {
    const r = await api.post("/api/firewall/flush", {family, name});
    toast(r.message); loadFirewallAll();
  } catch(e){ toast(e.message, true); }
};

let _pkgPollTimer = null;
let _pkgCurrentTask = null;
async function loadRouterEssentials(){
  const el = document.getElementById("pkg-router-essentials");
  el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">检测中...</div>';
  try {
    const r = await api.get("/api/packages/router-essentials");
    const list = r.results || [];
    if (!list.length){
      el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">无数据</div>';
      return;
    }
    const ok = list.filter(p => p.installed).length;
    const all = ok === list.length;
    let html = '<div style="margin-bottom:10px;font-size:12px;color:'
      + (all ? 'var(--ok)' : 'var(--warn)') + '">'
      + (all ? '✓ 全部已安装，可直接使用一键应用'
             : '已安装 ' + ok + '/' + list.length + '，请先安装缺失包')
      + '</div>';
    html += '<table class="tbl"><thead><tr>'
      + '<th style="width:240px">包名</th>'
      + '<th style="width:110px">状态</th>'
      + '<th>说明</th></tr></thead><tbody>';
    for (const p of list){
      const st = p.installed
        ? '<span style="color:var(--ok)">✓ 已安装</span>'
        : '<span style="color:var(--danger)">✗ 未安装</span>';
      html += '<tr>'
        + '<td style="color:var(--fg);font-weight:600">' + escapeHtml(p.name) + '</td>'
        + '<td>' + st + '</td>'
        + '<td style="color:var(--fg-dim);font-size:12px">' + escapeHtml(p.desc) + '</td>'
        + '</tr>';
    }
    html += '</tbody></table>';
    el.innerHTML = html;
  } catch(e){
    el.innerHTML = '<div style="color:var(--danger)">' + escapeHtml(e.message) + '</div>';
  }
}
function renderEssentials(elId, apiPath, readyText){
  return async function(){
    const el = document.getElementById(elId);
    if (!el) return;
    el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">检测中...</div>';
    try {
      const r = await api.get(apiPath);
      const list = r.results || [];
      if (!list.length){
        el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">无数据</div>';
        return;
      }
      const okCount = list.filter(p => p.installed).length;
      const all = okCount === list.length;
      let html = '<div style="margin-bottom:10px;font-size:12px;color:'
        + (all ? 'var(--ok)' : 'var(--warn)') + '">'
        + (all ? ('✓ ' + readyText)
               : '已安装 ' + okCount + '/' + list.length + '，请先安装缺失包')
        + '</div>';
      html += '<table class="tbl"><thead><tr>'
        + '<th style="width:240px">包名</th>'
        + '<th style="width:110px">状态</th>'
        + '<th>说明</th></tr></thead><tbody>';
      for (const p of list){
        const st = p.installed
          ? '<span style="color:var(--ok)">✓ 已安装</span>'
          : '<span style="color:var(--danger)">✗ 未安装</span>';
        html += '<tr>'
          + '<td style="color:var(--fg);font-weight:600">' + escapeHtml(p.name) + '</td>'
          + '<td>' + st + '</td>'
          + '<td style="color:var(--fg-dim);font-size:12px">' + escapeHtml(p.desc) + '</td>'
          + '</tr>';
      }
      html += '</tbody></table>';
      el.innerHTML = html;
    } catch(e){
      el.innerHTML = '<div style="color:var(--danger)">' + escapeHtml(e.message) + '</div>';
    }
  };
}
const loadVmEssentials = renderEssentials(
  "pkg-vm-essentials", "/api/packages/vm-essentials",
  "全部已安装，可在「虚拟机」标签创建虚拟机");
const loadDiskEssentials = renderEssentials(
  "pkg-disk-essentials", "/api/packages/disk-essentials",
  "全部已安装，可在「磁盘管理」标签操作磁盘");
const loadSambaEssentials = renderEssentials(
  "pkg-samba-essentials", "/api/packages/samba-essentials",
  "全部已安装，可在「文件共享」标签配置 Samba");
async function installRouterEssentials(){
  if (!confirm("安装路由功能必备软件包？\n将执行 apt-get install -y")) return;
  try {
    const r = await api.post("/api/packages/install-router-essentials", {});
    pkgStartTask(r.task_id);
    const poll = setInterval(async () => {
      if (!_pkgCurrentTask){ clearInterval(poll); loadRouterEssentials(); }
    }, 2000);
  } catch(e){ toast(e.message, true); }
}
async function installEssentials(apiPath, packages, confirmText, refreshFn){
  if (!confirm(confirmText)) return;
  try {
    const body = packages ? {packages} : {};
    const r = await api.post(apiPath, body);
    pkgStartTask(r.task_id);
    const poll = setInterval(async () => {
      if (!_pkgCurrentTask){ clearInterval(poll); refreshFn(); }
    }, 2000);
  } catch(e){ toast(e.message, true); }
}
async function installVmEssentials(){
  await installEssentials(
    "/api/packages/install-vm-essentials", null,
    "安装虚拟机环境必备软件包？\n将执行 apt-get install -y\n"
      + "（qemu-system-x86 / libvirt / virt-install / ovmf 等，约 300MB+）",
    loadVmEssentials);
}
async function installDiskEssentials(){
  await installEssentials(
    "/api/packages/install-disk-essentials", null,
    "安装磁盘管理必备软件包？\n将执行 apt-get install -y\n"
      + "（dosfstools / exfatprogs / ntfs-3g / xfsprogs / btrfs-progs / f2fs-tools）",
    loadDiskEssentials);
}
async function installSambaEssentials(){
  await installEssentials(
    "/api/packages/install-samba-essentials", null,
    "安装文件共享必备软件包？\n将执行 apt-get install -y\n"
      + "（samba / samba-common-bin / smbclient）",
    loadSambaEssentials);
}
document.getElementById("pkg-btn-install-essentials").onclick = installRouterEssentials;
document.getElementById("pkg-btn-refresh-essentials").onclick = loadRouterEssentials;
document.getElementById("pkg-btn-install-vm-essentials").onclick = installVmEssentials;
document.getElementById("pkg-btn-refresh-vm-essentials").onclick = loadVmEssentials;
document.getElementById("pkg-btn-install-disk-essentials").onclick = installDiskEssentials;
document.getElementById("pkg-btn-refresh-disk-essentials").onclick = loadDiskEssentials;
document.getElementById("pkg-btn-install-samba-essentials").onclick = installSambaEssentials;
document.getElementById("pkg-btn-refresh-samba-essentials").onclick = loadSambaEssentials;
async function loadPackages(){
  api.get("/api/router/config").then(r => {
    document.getElementById("pkg-root-warn").innerHTML = r.root ? "" :
      '<div class="warn-box">当前进程非 root 运行，安装/卸载/更新操作需要以 sudo 启动 NetRouter。</div>';
  }).catch(()=>{});
  loadRouterEssentials();
  loadVmEssentials();
  loadDiskEssentials();
  loadSambaEssentials();
  await pkgLoadInstalled();
}
async function pkgLoadInstalled(){
  const el = document.getElementById("pkg-installed-list");
  el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">加载中...</div>';
  try {
    const r = await api.get("/api/packages/installed");
    const list = r.results || [];
    document.getElementById("pkg-installed-count").textContent =
      "共 " + list.length + " 个";
    if (!list.length){
      el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">无数据</div>';
      return;
    }
    el.innerHTML = '<table class="tbl"><thead><tr>'
      + '<th style="width:280px">包名</th>'
      + '<th style="width:180px">版本</th>'
      + '<th>描述</th>'
      + '<th style="width:90px"></th>'
      + '</tr></thead><tbody>'
      + list.map(p =>
        '<tr>'
        + '<td style="color:var(--fg);font-weight:600">' + escapeHtml(p.name) + '</td>'
        + '<td>' + escapeHtml(p.version) + '</td>'
        + '<td style="color:var(--fg-dim);font-size:12px">' + escapeHtml(p.summary) + '</td>'
        + '<td style="text-align:right">'
        + '<button class="btn btn-danger btn-sm" onclick="pkgRemove(\''
        + escapeAttr(p.name) + '\')">卸载</button>'
        + '</td></tr>'
      ).join("")
      + '</tbody></table>';
  } catch(e){
    el.innerHTML = '<div style="color:var(--danger)">' + escapeHtml(e.message) + '</div>';
  }
}
async function pkgSearch(){
  const q = document.getElementById("pkg-search-q").value.trim();
  if (!q || q.length < 2){ toast("请输入至少 2 个字符", true); return; }
  const el = document.getElementById("pkg-search-results");
  el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">搜索中...</div>';
  try {
    const r = await api.get("/api/packages/search?q=" + encodeURIComponent(q));
    const list = r.results || [];
    if (!list.length){
      el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">无结果</div>';
      return;
    }
    el.innerHTML = '<div style="color:var(--fg-dim);font-size:12px;margin-bottom:8px">'
      + '找到 ' + list.length + ' 个结果</div>'
      + '<table class="tbl"><thead><tr>'
      + '<th style="width:280px">包名</th>'
      + '<th>描述</th>'
      + '<th style="width:90px"></th>'
      + '</tr></thead><tbody>'
      + list.map(p =>
        '<tr>'
        + '<td style="color:var(--fg);font-weight:600">' + escapeHtml(p.name) + '</td>'
        + '<td style="color:var(--fg-dim);font-size:12px">' + escapeHtml(p.desc) + '</td>'
        + '<td style="text-align:right">'
        + '<button class="btn btn-sm" onclick="pkgInstall(\''
        + escapeAttr(p.name) + '\')">安装</button>'
        + '</td></tr>'
      ).join("")
      + '</tbody></table>';
  } catch(e){
    el.innerHTML = '<div style="color:var(--danger)">' + escapeHtml(e.message) + '</div>';
  }
}
async function pkgInstall(name){
  if (!confirm("安装 " + name + " ？")) return;
  try {
    const r = await api.post("/api/packages/install", {packages: [name]});
    pkgStartTask(r.task_id);
  } catch(e){ toast(e.message, true); }
}
async function pkgRemove(name){
  if (!confirm("卸载 " + name + " ？\n（保留配置文件）")) return;
  try {
    const r = await api.post("/api/packages/remove", {packages: [name]});
    pkgStartTask(r.task_id);
  } catch(e){ toast(e.message, true); }
}
async function pkgUpdate(){
  if (!confirm("更新软件包索引？")) return;
  try {
    const r = await api.post("/api/packages/update", {});
    pkgStartTask(r.task_id);
  } catch(e){ toast(e.message, true); }
}
async function pkgUpgrade(){
  if (!confirm("升级所有软件包？\n可能需要几分钟。")) return;
  try {
    const r = await api.post("/api/packages/upgrade", {});
    pkgStartTask(r.task_id);
  } catch(e){ toast(e.message, true); }
}
function pkgStartTask(taskId){
  _pkgCurrentTask = taskId;
  const panel = document.getElementById("pkg-task-panel");
  panel.style.display = "";
  document.getElementById("pkg-task-out").textContent = "";
  document.getElementById("pkg-task-status").textContent = "运行中...";
  document.getElementById("pkg-task-title").textContent = "任务";
  panel.scrollIntoView({behavior: "smooth", block: "start"});
  pkgPollTask();
}
async function pkgPollTask(){
  if (_pkgPollTimer){ clearTimeout(_pkgPollTimer); _pkgPollTimer = null; }
  if (!_pkgCurrentTask) return;
  try {
    const t = await api.get("/api/packages/task/" + _pkgCurrentTask);
    document.getElementById("pkg-task-title").textContent = t.label || "任务";
    const out = document.getElementById("pkg-task-out");
    out.textContent = t.output || "(等待输出...)";
    out.scrollTop = out.scrollHeight;
    if (t.status === "done"){
      document.getElementById("pkg-task-status").textContent =
        (t.ok ? "完成 (rc=0)" : "失败 (rc=" + (t.returncode === null || t.returncode === undefined ? "?" : t.returncode) + ")");
      _pkgCurrentTask = null;
      if (t.ok) await pkgLoadInstalled();
      return;
    }
    document.getElementById("pkg-task-status").textContent = "运行中...";
    _pkgPollTimer = setTimeout(pkgPollTask, 1000);
  } catch(e){
    document.getElementById("pkg-task-status").textContent = "错误：" + e.message;
    _pkgCurrentTask = null;
  }
}
function pkgCloseTask(){
  if (_pkgPollTimer){ clearTimeout(_pkgPollTimer); _pkgPollTimer = null; }
  _pkgCurrentTask = null;
  document.getElementById("pkg-task-panel").style.display = "none";
}
document.getElementById("pkg-btn-update").onclick = pkgUpdate;
document.getElementById("pkg-btn-upgrade").onclick = pkgUpgrade;
document.getElementById("pkg-btn-refresh").onclick = pkgLoadInstalled;
document.getElementById("pkg-btn-search").onclick = pkgSearch;

/* ==================== 虚拟机 ==================== */
let _vmList = [];
let _vmIsos = [];
let _vmSettings = { storage_dir: "/var/lib/libvirt/images" };

async function loadVms(){
  try {
    const cfg = await api.get("/api/router/config");
    document.getElementById("vm-root-warn").innerHTML = cfg.root ? "" :
      '<div class="warn-box">当前进程非 root 运行，创建 / 启动虚拟机需要以 sudo 启动 NetRouter。</div>';
  } catch(_){}
  try {
    const st = await api.get("/api/vm/status");
    _vmSettings = (st && st.settings) || _vmSettings;
    const el = document.getElementById("vm-storage-dir");
    if (el) el.value = _vmSettings.storage_dir || "";
    const w = document.getElementById("vm-kvm-warn");
    if (st.kvm && !st.kvm.available){
      w.innerHTML = '<div class="warn-box">未检测到 KVM 硬件加速：'
        + escapeHtml(st.kvm.reason || "未知原因")
        + '<br><span style="color:var(--fg-dim)">仍可创建虚拟机，但性能将大幅下降。</span></div>';
    } else {
      w.innerHTML = "";
    }
  } catch(_){}
  vmLoadList();
  vmLoadIsos();
}
async function saveVmSettings(){
  const sd = (document.getElementById("vm-storage-dir").value || "").trim();
  if (!sd || !sd.startsWith("/")){
    toast("存储目录必须为绝对路径", true); return;
  }
  try {
    const r = await api.post("/api/vm/settings", { settings: { storage_dir: sd } });
    _vmSettings = r.settings || _vmSettings;
    toast("存储设置已保存");
  } catch(e){ toast(e.message, true); }
}
async function vmLoadList(){
  const el = document.getElementById("vm-list");
  if (!el) return;
  el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">加载中...</div>';
  try {
    const r = await api.get("/api/vm/list");
    _vmList = r.vms || [];
    if (!_vmList.length){
      el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px;padding:8px 0">'
        + '暂无虚拟机。点击「+ 新建虚拟机」开始。</div>';
      return;
    }
    let html = '<table class="tbl"><thead><tr>'
      + '<th>名称</th><th>状态</th><th>vCPU</th><th>内存</th>'
      + '<th>磁盘</th><th>网络</th><th>VNC</th>'
      + '<th style="width:370px"></th></tr></thead><tbody>';
    for (const v of _vmList){
      const stateColor = v.running ? 'var(--ok)' : 'var(--fg-dim)';
      const disks = (v.disks || []).filter(d => d.device === 'disk');
      const diskText = disks.map(d => (d.path || '').split('/').pop())
        .join(', ') || '—';
      const nets = (v.interfaces || []).map(i => i.source || i.type || '')
        .filter(Boolean).join(', ') || '—';
      const vnc = v.vnc_port
        ? '<span style="color:var(--warn)">:' + v.vnc_port + '</span>'
        : '—';
      const mem = v.running
        ? ((v.memory_mb || 0) + ' MB')
        : (v.max_memory_mb ? (v.max_memory_mb + ' MB') : '—');
      let btns = '';
      if (v.running){
        btns += '<button class="btn btn-inverse btn-sm" onclick="vmAction(\''
             + escapeAttr(v.name) + '\',\'shutdown\')">关机</button> ';
        btns += '<button class="btn btn-danger btn-sm" onclick="vmAction(\''
             + escapeAttr(v.name) + '\',\'destroy\')">强制停止</button> ';
        btns += '<button class="btn btn-inverse btn-sm" onclick="vmAction(\''
             + escapeAttr(v.name) + '\',\'reboot\')">重启</button> ';
      } else {
        btns += '<button class="btn btn-sm" onclick="vmAction(\''
             + escapeAttr(v.name) + '\',\'start\')">启动</button> ';
      }
      btns += '<button class="btn btn-inverse btn-sm" onclick="vmShowDetail(\''
           + escapeAttr(v.name) + '\')">详情</button> ';
      btns += '<button class="btn btn-danger btn-sm" onclick="vmDelete(\''
           + escapeAttr(v.name) + '\')">删除</button>';
      html += '<tr>'
        + '<td style="color:var(--fg);font-weight:600">' + escapeHtml(v.name) + '</td>'
        + '<td><span style="color:' + stateColor + '">'
        + escapeHtml(v.state) + '</span></td>'
        + '<td>' + (v.vcpu || '—') + '</td>'
        + '<td>' + mem + '</td>'
        + '<td style="font-size:11px;font-family:ui-monospace,monospace" title="'
        + escapeAttr(disks.map(d => d.path).join('\n')) + '">'
        + escapeHtml(diskText) + '</td>'
        + '<td style="font-size:11px;font-family:ui-monospace,monospace">'
        + escapeHtml(nets) + '</td>'
        + '<td style="font-size:11px;font-family:ui-monospace,monospace">'
        + vnc + '</td>'
        + '<td style="text-align:right;white-space:nowrap">' + btns + '</td>'
        + '</tr>';
    }
    html += '</tbody></table>';
    el.innerHTML = html;
  } catch(e){
    el.innerHTML = '<div style="color:var(--danger)">' + escapeHtml(e.message) + '</div>';
  }
}
async function vmLoadIsos(){
  const el = document.getElementById("vm-isos");
  if (!el) return;
  el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">扫描中...</div>';
  try {
    const r = await api.get("/api/vm/isos");
    const list = r.isos || [];
    _vmIsos = list;
    if (!list.length){
      el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">'
        + '未发现 ISO 镜像（可选）。如需挂载安装盘，请将 .iso 放入 <b style="color:var(--fg)">'
        + escapeHtml((r.dirs || []).join(" / "))
        + '</b> 后重新扫描。</div>';
      return;
    }
    el.innerHTML = '<table class="tbl"><thead><tr>'
      + '<th>文件名</th>'
      + '<th style="width:120px">大小</th>'
      + '<th>路径</th></tr></thead><tbody>'
      + list.map(i => '<tr>'
        + '<td style="color:var(--fg);font-weight:600">' + escapeHtml(i.name) + '</td>'
        + '<td>' + (i.size / 1024 / 1024 / 1024).toFixed(2) + ' GB</td>'
        + '<td style="font-size:11px;font-family:ui-monospace,monospace">'
        + escapeHtml(i.path) + '</td></tr>').join('')
      + '</tbody></table>';
  } catch(e){
    el.innerHTML = '<div style="color:var(--danger)">' + escapeHtml(e.message) + '</div>';
  }
}
function vmOpenModal(title, bodyHtml, onSave, hideSaveBtn){
  document.getElementById("vm-modal-title").textContent = title;
  document.getElementById("vm-modal-body").innerHTML = bodyHtml;
  document.getElementById("vm-modal").classList.remove("hidden");
  const sb = document.getElementById("vm-modal-save");
  sb.onclick = onSave;
  sb.style.display = hideSaveBtn ? "none" : "";
}
function vmCloseModal(){
  document.getElementById("vm-modal").classList.add("hidden");
}
document.getElementById("vm-modal-cancel").onclick = vmCloseModal;
function vmOpenCreate(){
  Promise.all([
    api.get("/api/vm/isos").catch(() => ({ isos: [] })),
    api.get("/api/vm/status").catch(() => ({})),
  ]).then(([isoR, stR]) => {
    _vmIsos = isoR.isos || [];
    _vmSettings = (stR.settings) || _vmSettings;
    vmRenderCreateDialog();
  });
}
function vmRenderCreateDialog(){
  const isoOpts = ['<option value="">— 不附加 ISO（可稍后手动处理）—</option>']
    .concat(_vmIsos.map(i =>
      '<option value="' + escapeAttr(i.path) + '">'
      + escapeHtml(i.name) + ' · '
      + (i.size / 1024 / 1024 / 1024).toFixed(2) + ' GB</option>'))
    .join('');
  const osVariants = [
    "generic", "ubuntu22.04", "ubuntu24.04", "ubuntu20.04",
    "debian12", "debian11", "centos-stream9", "rocky9",
    "fedora39", "win10", "win11", "win2k22",
  ];
  const body = ''
    + '<div class="form-col">'
    + '<label>虚拟机名称'
    + '<input id="v-name" placeholder="vm-ubuntu-01"></label>'
    + '<div class="form-row">'
    +   '<label>vCPU<input id="v-vcpu" type="number" min="1" max="64" value="2"></label>'
    +   '<label>内存 (MB)<input id="v-mem" type="number" min="128" max="262144" value="2048"></label>'
    + '</div>'
    + '<div>'
    +   '<div style="font-size:12px;color:var(--fg-dim);margin-bottom:8px">磁盘</div>'
    +   '<div style="display:flex;gap:14px;flex-wrap:wrap;margin-bottom:12px">'
    +     '<label class="checkbox-row"><input type="radio" name="v-disk-mode" value="new" checked> 新建磁盘</label>'
    +     '<label class="checkbox-row"><input type="radio" name="v-disk-mode" value="import"> 导入已有 QCOW2</label>'
    +     '<label class="checkbox-row"><input type="radio" name="v-disk-mode" value="none"> 不创建磁盘</label>'
    +   '</div>'
    +   '<div id="v-disk-new-box">'
    +     '<label>磁盘容量 (GB)<input id="v-disk" type="number" min="1" max="4096" value="20"></label>'
    +   '</div>'
    +   '<div id="v-disk-import-box" style="display:none">'
    +     '<label>QCOW2 文件路径'
    +     '<input id="v-import-path" placeholder="/path/to/existing.qcow2"></label>'
    +     '<div class="actions" style="margin-top:8px">'
    +       '<button class="btn btn-inverse btn-sm" type="button" '
    +       'onclick="vmBrowseQcow2()">浏览磁盘文件</button>'
    +     '</div>'
    +     '<div id="v-import-list" style="margin-top:10px"></div>'
    +     '<div style="color:var(--warn);font-size:11.5px;margin-top:8px;line-height:1.7">'
    +       '⚠ 导入的磁盘文件会<strong>移动</strong>到该虚拟机的专属目录，'
    +       '原路径将不再存在。<br>'
    +       '⚠ 导入模式将直接从该磁盘启动（跳过安装），无需选择 ISO。'
    +     '</div>'
    +   '</div>'
    + '</div>'
    + '<label>安装 ISO（可选）'
    + '<select id="v-iso">' + isoOpts + '</select></label>'
    + '<div class="form-row">'
    +   '<label>网络桥接<input id="v-bridge" value="br-lan"></label>'
    +   '<label>OS 类型<select id="v-osvar">'
    +     osVariants.map(v => '<option value="' + v + '">' + v + '</option>').join('')
    +   '</select></label>'
    + '</div>'
    + '<div class="form-row">'
    +   '<label>VNC 端口（留空自动分配）'
    +   '<input id="v-vnc" type="number" min="5901" max="5999" placeholder="自动"></label>'
    +   '<label>VNC 密码（可选 4-8 位）'
    +   '<input id="v-vncpwd" maxlength="8" placeholder="留空则无密码"></label>'
    + '</div>'
    + '<div style="color:var(--fg-dimmer);font-size:11.5px;line-height:1.8;'
    + 'margin-top:6px;font-family:ui-monospace,monospace">'
    + '· 磁盘将写入 <b style="color:var(--fg)">' + escapeHtml(_vmSettings.storage_dir || '') + '/&lt;名称&gt;/</b><br>'
    + '· 网卡接入 <b style="color:var(--fg)">br-lan</b>，与 LAN 同网段<br>'
    + '· VNC 端口 <b style="color:var(--warn)">不会</b>自动放行到 wan，'
    +    '需要时请在详情中手动开放'
    + '</div>'
    + '</div>';
  vmOpenModal("新建虚拟机", body, vmCreateSubmit);
  document.getElementById("vm-modal-save").textContent = "创建";
}
document.addEventListener("change", (e) => {
  if (!e.target || e.target.name !== "v-disk-mode") return;
  const m = e.target.value;
  const newBox = document.getElementById("v-disk-new-box");
  const impBox = document.getElementById("v-disk-import-box");
  if (newBox) newBox.style.display = (m === "new") ? "" : "none";
  if (impBox) impBox.style.display = (m === "import") ? "" : "none";
});
async function vmBrowseQcow2(){
  const listEl = document.getElementById("v-import-list");
  listEl.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">扫描中...</div>';
  try {
    const r = await api.get("/api/vm/browse-qcow2");
    const files = r.files || [];
    if (!files.length){
      listEl.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">'
        + '未发现 QCOW2 文件。可在上方直接输入绝对路径。</div>';
      return;
    }
    listEl.innerHTML = '<div style="font-size:11.5px;color:var(--fg-dim);margin-bottom:6px">'
      + '发现 ' + files.length + ' 个文件（点击选择）</div>'
      + '<div style="max-height:220px;overflow:auto;border:1px solid var(--line);'
      + 'border-radius:2px;padding:4px">'
      + files.map((f, i) => '<div style="display:flex;align-items:center;gap:8px;'
        + 'padding:6px 8px;border-bottom:1px solid var(--line)">'
        + '<div style="flex:1;min-width:0;overflow:hidden">'
        + '<div style="font-size:12px;color:var(--fg);font-family:ui-monospace,monospace;'
        + 'white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="'
        + escapeAttr(f.path) + '">' + escapeHtml(f.name) + '</div>'
        + '<div style="font-size:10.5px;color:var(--fg-dimmer);font-family:ui-monospace,monospace;'
        + 'white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="'
        + escapeAttr(f.path) + '">' + escapeHtml(f.path) + '</div>'
        + '</div>'
        + '<div style="font-size:11px;color:var(--fg-dim);white-space:nowrap">'
        + (f.size / 1024 / 1024 / 1024).toFixed(2) + ' GB</div>'
        + '<button class="btn btn-inverse btn-sm" type="button" '
        + 'onclick="vmPickQcow2(\'' + escapeAttr(f.path) + '\')">选择</button>'
        + '</div>').join('')
      + '</div>';
  } catch(e){
    listEl.innerHTML = '<div style="color:var(--danger)">' + escapeHtml(e.message) + '</div>';
  }
}
function vmPickQcow2(path){
  const inp = document.getElementById("v-import-path");
  if (inp) inp.value = path;
}
async function vmCreateSubmit(){
  const name = (document.getElementById("v-name").value || "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$/.test(name)){
    toast("名称需以字母/数字开头，1-64 位", true); return;
  }
  const diskModeEl = document.querySelector('input[name="v-disk-mode"]:checked');
  const diskMode = diskModeEl ? diskModeEl.value : "new";
  const payload = {
    name,
    vcpu: parseInt(document.getElementById("v-vcpu").value, 10) || 2,
    memory: parseInt(document.getElementById("v-mem").value, 10) || 2048,
    bridge: (document.getElementById("v-bridge").value || "br-lan").trim(),
    os_variant: document.getElementById("v-osvar").value,
    iso: document.getElementById("v-iso").value || "",
    vnc_password: (document.getElementById("v-vncpwd").value || "").trim(),
    disk_mode: diskMode,
  };
  if (diskMode === "new"){
    payload.disk_size = parseInt(document.getElementById("v-disk").value, 10) || 20;
  } else if (diskMode === "import"){
    const ip = (document.getElementById("v-import-path").value || "").trim();
    if (!ip){ toast("请填写或选择要导入的 QCOW2 文件路径", true); return; }
    payload.import_path = ip;
  }
  const vncEl = document.getElementById("v-vnc").value;
  if (vncEl) payload.vnc_port = parseInt(vncEl, 10);
  const btn = document.getElementById("vm-modal-save");
  btn.disabled = true; btn.textContent = "创建中...";
  try {
    const r = await api.post("/api/vm/create", payload);
    if (r.ok){
      toast(r.message || "已创建");
      vmCloseModal();
      vmLoadList();
    } else {
      toast(r.message || "创建失败", true);
    }
  } catch(e){ toast(e.message, true); }
  finally { btn.disabled = false; btn.textContent = "创建"; }
}
async function vmAction(name, action){
  if (action === 'destroy'
      && !confirm("强制停止 " + name + " ？\n可能导致客户机数据损坏。")) return;
  if (action === 'shutdown'
      && !confirm("向 " + name + " 发送关机信号？")) return;
  try {
    const r = await api.post("/api/vm/action", {name, action});
    toast(r.message || "完成", !r.ok);
    setTimeout(vmLoadList, 600);
  } catch(e){ toast(e.message, true); }
}
async function vmDelete(name){
  if (!confirm("删除虚拟机 " + name + " ？\n\n请确保虚拟机已关机。")) return;
  const removeDisks = confirm(
    "是否同时删除该虚拟机的磁盘文件？\n\n"
    + "「确定」= 删除磁盘（不可恢复）\n"
    + "「取消」= 仅删除定义，保留磁盘文件");
  try {
    const r = await api.post("/api/vm/delete",
      {name, remove_disks: removeDisks});
    toast(r.message || "已删除", !r.ok);
    vmLoadList();
  } catch(e){ toast(e.message, true); }
}
async function vmShowDetail(name){
  try {
    const d = await api.get("/api/vm/detail/" + encodeURIComponent(name));
    vmRenderDetailDialog(d);
  } catch(e){ toast(e.message, true); }
}
function vmRenderDetailDialog(d){
  const name = d.name;
  const running = !!d.running;
  const resourcesHtml = ''
    + '<div class="form-row" style="gap:10px">'
    +   '<label>vCPU<input id="d-vcpu" type="number" min="1" max="64" value="'
    +     (d.vcpu || 1) + '"></label>'
    +   '<label>内存 (MB)<input id="d-mem" type="number" min="128" max="262144" value="'
    +     (d.max_memory_mb || d.memory_mb || 512) + '"></label>'
    +   '<label style="flex:0 0 130px">自启动'
    +     '<select id="d-autostart">'
    +       '<option value="on"' + (d.autostart ? ' selected' : '') + '>启用</option>'
    +       '<option value="off"' + (!d.autostart ? ' selected' : '') + '>禁用</option>'
    +     '</select></label>'
    +   '<button class="btn btn-sm" style="flex:0 0 auto;align-self:flex-end" '
    +     'onclick="vmSaveResources(\'' + escapeAttr(name) + '\')">应用</button>'
    + '</div>';
  const vncPlaceholder = d.vnc_password ? '已设置（留空则不修改）' : '留空则无密码';
  const vncHtml = ''
    + '<div class="form-row" style="gap:10px">'
    +   '<label>VNC 端口<input id="d-vnc" type="number" min="5901" max="5999" '
    +     'value="' + (d.vnc_port || '') + '" placeholder="留空自动"></label>'
    +   '<label>VNC 监听<input id="d-vnc-listen" value="'
    +     escapeAttr(d.vnc_listen || '') + '" placeholder="0.0.0.0"></label>'
    +   '<label>VNC 密码<input id="d-vnc-pwd" maxlength="8" '
    +     'placeholder="' + vncPlaceholder + '"></label>'
    +   '<button class="btn btn-sm" style="flex:0 0 auto;align-self:flex-end" '
    +     'onclick="vmSaveVnc(\'' + escapeAttr(name) + '\')">应用</button>'
    + '</div>'
    + '<div style="color:var(--fg-dimmer);font-size:11px;margin-top:6px;line-height:1.7">'
    +   '修改 VNC 端口 / 监听 / 密码后需 <b style="color:var(--warn)">重启虚拟机</b> 才生效。'
    + '</div>';
  const disks = d.disks || [];
  let diskHtml = '';
  if (disks.length){
    diskHtml = '<table class="tbl"><thead><tr>'
      + '<th>类型</th><th>目标</th><th>路径</th>'
      + '<th style="width:110px"></th></tr></thead><tbody>';
    for (const dk of disks){
      const isCd = dk.device === 'cdrom';
      diskHtml += '<tr>'
        + '<td>' + escapeHtml(dk.device) + '</td>'
        + '<td style="font-family:ui-monospace,monospace">'
        +   escapeHtml(dk.target || '—') + '</td>'
        + '<td style="font-family:ui-monospace,monospace;font-size:11px;word-break:break-all">'
        +   escapeHtml(dk.path || '—') + '</td>'
        + '<td style="text-align:right">'
        + '<button class="btn btn-danger btn-sm" '
        +   'onclick="vmDetach(\'' + escapeAttr(name) + '\',\''
        +   escapeAttr(dk.target || '') + '\',' + (isCd ? 'true' : 'false') + ')">'
        +   (isCd ? '卸载' : '移除') + '</button>'
        + '</td></tr>';
    }
    diskHtml += '</tbody></table>';
  } else {
    diskHtml = '<div style="color:var(--fg-dimmer);font-size:12px">无磁盘设备</div>';
  }
  const diskActions = ''
    + '<div class="actions" style="margin-top:10px">'
    +   '<button class="btn btn-sm" '
    +     'onclick="vmAddDisk(\'' + escapeAttr(name) + '\')">+ 添加新磁盘</button>'
    +   '<button class="btn btn-inverse btn-sm" '
    +     'onclick="vmMountIso(\'' + escapeAttr(name) + '\')">挂载 ISO</button>'
    + '</div>';
  let netHtml = '';
  if (d.interfaces && d.interfaces.length){
    netHtml = '<table class="tbl"><thead><tr>'
      + '<th>类型</th><th>源</th><th>MAC</th></tr></thead><tbody>';
    for (const i of d.interfaces){
      netHtml += '<tr><td>' + escapeHtml(i.type) + '</td>'
        + '<td style="font-family:ui-monospace,monospace">'
        +   escapeHtml(i.source || '—') + '</td>'
        + '<td style="font-family:ui-monospace,monospace;font-size:11px">'
        +   escapeHtml(i.mac || '—') + '</td></tr>';
    }
    netHtml += '</tbody></table>';
  } else {
    netHtml = '<div style="color:var(--fg-dimmer);font-size:12px">无网卡</div>';
  }
  let ctrl = '';
  if (running){
    ctrl = ''
      + '<button class="btn btn-inverse btn-sm" onclick="vmAction(\''
      +   escapeAttr(name) + '\',\'shutdown\');vmCloseModal()">关机</button> '
      + '<button class="btn btn-danger btn-sm" onclick="vmAction(\''
      +   escapeAttr(name) + '\',\'destroy\');vmCloseModal()">强制停止</button> '
      + '<button class="btn btn-inverse btn-sm" onclick="vmAction(\''
      +   escapeAttr(name) + '\',\'reboot\');vmCloseModal()">重启</button>';
  } else {
    ctrl = '<button class="btn btn-sm" onclick="vmAction(\''
      + escapeAttr(name) + '\',\'start\');vmCloseModal()">启动</button>';
  }
  if (d.vnc_port){
    ctrl += ' '
      + '<button class="btn btn-inverse btn-sm" onclick="vmVncFw(\''
      + escapeAttr(name) + '\',true)">放行 wan → VNC</button> '
      + '<button class="btn btn-inverse btn-sm" onclick="vmVncFw(\''
      + escapeAttr(name) + '\',false)">撤销放行</button>';
  }
  const sectionTitle = (s) =>
    '<div style="font-size:11px;color:var(--fg-dim);letter-spacing:.1em;'
    + 'text-transform:uppercase;margin:18px 0 8px">' + s + '</div>';
  const html = ''
    + '<div style="color:var(--fg-dim);font-size:11.5px;'
    +    'font-family:ui-monospace,monospace;margin-bottom:12px;line-height:1.7">'
    +   '状态 <b style="color:' + (running ? 'var(--ok)' : 'var(--fg-dim)') + '">'
    +   escapeHtml(d.state) + '</b> · UUID ' + escapeHtml(d.uuid || '—') + '</div>'
    + '<div style="font-size:11px;color:var(--fg-dim);letter-spacing:.1em;'
    +    'text-transform:uppercase;margin-bottom:8px">资源与自启动</div>'
    + resourcesHtml
    + sectionTitle('VNC 控制台')
    + vncHtml
    + sectionTitle('磁盘设备')
    + diskHtml + diskActions
    + sectionTitle('网络')
    + netHtml
    + sectionTitle('控制')
    + '<div class="actions" style="margin-top:0">' + ctrl + '</div>'
    + '<details style="margin-top:18px">'
    +   '<summary style="cursor:pointer;font-size:12px;color:var(--fg-dim)">'
    +     'libvirt XML 定义</summary>'
    +   '<div class="log-box" style="margin-top:8px;max-height:320px">'
    +     escapeHtml(d.xml || '') + '</div>'
    + '</details>';
  vmOpenModal("虚拟机 · " + name, html, () => vmCloseModal(), true);
}
async function vmSaveResources(name){
  const vcpu = parseInt(document.getElementById("d-vcpu").value, 10);
  const mem  = parseInt(document.getElementById("d-mem").value, 10);
  const as   = document.getElementById("d-autostart").value;
  if (!(vcpu > 0 && vcpu <= 64)){ toast("vCPU 范围 1-64", true); return; }
  if (!(mem >= 128 && mem <= 262144)){ toast("内存范围 128-262144 MB", true); return; }
  try {
    const r = await api.post("/api/vm/update-resources",
      {name, vcpu, memory: mem});
    if (!r.ok){ toast(r.message || "更新失败", true); return; }
    try {
      await api.post("/api/vm/action",
        {name, action: as === "on" ? "autostart-on" : "autostart-off"});
    } catch(_){}
    toast("已更新");
    setTimeout(() => vmShowDetail(name), 200);
  } catch(e){ toast(e.message, true); }
}
async function vmSaveVnc(name){
  const portEl = document.getElementById("d-vnc");
  const listenEl = document.getElementById("d-vnc-listen");
  const pwdEl = document.getElementById("d-vnc-pwd");
  const body = { name };
  if (portEl && portEl.value.trim() !== ""){
    body.vnc_port = parseInt(portEl.value.trim(), 10);
  }
  if (listenEl){ body.vnc_listen = listenEl.value.trim(); }
  if (pwdEl && pwdEl.value.trim() !== ""){
    body.vnc_password = pwdEl.value.trim();
  }
  try {
    const r = await api.post("/api/vm/update-vnc", body);
    toast(r.message || (r.ok ? "已更新" : "失败"), !r.ok);
    if (r.ok) setTimeout(() => vmShowDetail(name), 200);
  } catch(e){ toast(e.message, true); }
}
async function vmAddDisk(name){
  const sizeStr = prompt("新磁盘容量 (GB，1-4096)：", "20");
  if (sizeStr === null) return;
  const size = parseInt(sizeStr, 10);
  if (!(size > 0 && size <= 4096)){ toast("容量范围 1-4096 GB", true); return; }
  try {
    const r = await api.post("/api/vm/attach-disk",
      {name, size_gb: size, bus: "virtio"});
    toast(r.message || (r.ok ? "已添加" : "失败"), !r.ok);
    if (r.ok) setTimeout(() => vmShowDetail(name), 200);
  } catch(e){ toast(e.message, true); }
}
async function vmMountIso(name){
  try {
    const r = await api.get("/api/vm/isos");
    const list = r.isos || [];
    let body;
    if (!list.length){
      body = '<div style="color:var(--fg-dimmer);font-size:12px">'
        + '未发现 ISO 文件。请将 .iso 放入 '
        + escapeHtml((r.dirs || []).join(" / "))
        + ' 后重新扫描。</div>'
        + '<div class="actions" style="margin-top:12px">'
        + '<button class="btn btn-inverse btn-sm" type="button" '
        + 'onclick="vmMountIso(\'' + escapeAttr(name) + '\')">重新扫描</button>'
        + '</div>';
    } else {
      body = '<div style="color:var(--fg-dim);font-size:12px;margin-bottom:8px">'
        + '选择要挂载到 ' + escapeHtml(name) + ' 的 ISO：</div>'
        + '<div style="max-height:320px;overflow:auto;border:1px solid var(--line);'
        + 'border-radius:2px;padding:4px">'
        + list.map(f => '<div style="display:flex;align-items:center;gap:8px;'
          + 'padding:8px 10px;border-bottom:1px solid var(--line)">'
          + '<div style="flex:1;min-width:0;overflow:hidden">'
          + '<div style="font-size:12px;color:var(--fg);font-family:ui-monospace,monospace;'
          + 'white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'
          + escapeHtml(f.name) + '</div>'
          + '<div style="font-size:10.5px;color:var(--fg-dimmer);font-family:ui-monospace,monospace;'
          + 'white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'
          + escapeHtml(f.path) + '</div>'
          + '</div>'
          + '<div style="font-size:11px;color:var(--fg-dim);white-space:nowrap">'
          + (f.size / 1024 / 1024 / 1024).toFixed(2) + ' GB</div>'
          + '<button class="btn btn-sm" type="button" '
          + 'onclick="vmAttachIso(\'' + escapeAttr(name) + '\',\''
          + escapeAttr(f.path) + '\')">挂载</button>'
          + '</div>').join('')
        + '</div>'
        + '<div class="actions" style="margin-top:12px">'
        + '<button class="btn btn-inverse btn-sm" type="button" '
        + 'onclick="vmMountIso(\'' + escapeAttr(name) + '\')">重新扫描</button>'
        + '</div>';
    }
    vmOpenModal("挂载 ISO 到 " + name, body, () => vmCloseModal(), true);
  } catch(e){ toast(e.message, true); }
}
async function vmAttachIso(name, iso){
  try {
    const r = await api.post("/api/vm/attach-iso", {name, iso});
    toast(r.message || (r.ok ? "已挂载" : "失败"), !r.ok);
    if (r.ok){
      vmCloseModal();
      setTimeout(() => vmShowDetail(name), 150);
    }
  } catch(e){ toast(e.message, true); }
}
async function vmDetach(name, target, isCd){
  const label = isCd ? "卸载光驱" : "移除磁盘";
  if (!confirm(label + " " + target + " ？"
      + (isCd ? "" : "\n\n注意：磁盘文件也会被删除（如位于本虚拟机目录内）。"))) return;
  try {
    const r = await api.post("/api/vm/detach", {name, target});
    toast(r.message || (r.ok ? "已操作" : "失败"), !r.ok);
    if (r.ok) setTimeout(() => vmShowDetail(name), 200);
  } catch(e){ toast(e.message, true); }
}
async function vmVncFw(name, enable){
  try {
    const r = await api.post("/api/vm/vnc/firewall", {name, enable});
    toast(r.message || (enable ? "已放行" : "已撤销"), !r.ok);
  } catch(e){ toast(e.message, true); }
}
document.getElementById("vm-btn-save-settings").onclick = saveVmSettings;

/* ==================== 磁盘管理 ==================== */
let _diskData = null;
async function loadDisks(){
  try {
    const cfg = await api.get("/api/router/config");
    document.getElementById("disk-root-warn").innerHTML = cfg.root ? "" :
      '<div class="warn-box">当前进程非 root 运行，挂载 / 格式化 / 写入 fstab 需要 sudo 启动 NetRouter。</div>';
  } catch(_){}
  const el = document.getElementById("disk-list");
  el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">加载中...</div>';
  try {
    const r = await api.get("/api/disk/list");
    _diskData = r;
    if (r.error){
      el.innerHTML = '<div style="color:var(--danger)">' + escapeHtml(r.error) + '</div>';
      return;
    }
    const devs = r.devices || [];
    if (!devs.length){
      el.innerHTML = '<div style="color:var(--fg-dimmer)">未发现块设备</div>';
      return;
    }
    el.innerHTML = devs.map(d => renderDevice(d, 0)).join("");
    renderFstabManaged(r);
  } catch(e){
    el.innerHTML = '<div style="color:var(--danger)">' + escapeHtml(e.message) + '</div>';
  }
}
function renderDevice(node, depth){
  const rows = [];
  const sizeStr = fmtDiskSize(node.size);
  const tags = [];
  if (node.is_system) tags.push('<span class="badge" style="color:var(--danger);border-color:var(--danger)">系统</span>');
  if (node.ro) tags.push('<span class="badge">只读</span>');
  if (node.rm) tags.push('<span class="badge">可移动</span>');
  if (node.in_managed) tags.push('<span class="badge" style="color:var(--ok);border-color:var(--ok)">自动挂载</span>');
  else if (node.in_fstab) tags.push('<span class="badge">fstab</span>');
  const mp = node.mountpoint || '';
  const fs = node.fstype || '—';
  const label = node.label || '';
  const hasChildren = (node.children || []).length > 0;
  const canOperate = !node.is_system && (
    node.type === 'part' || (node.type === 'disk' && !hasChildren)
  );
  let btns = '';
  if (mp){
    if (canOperate){
      btns += '<button class="btn btn-inverse btn-sm" onclick="diskUmount(\''
           + escapeAttr(mp) + '\')">卸载</button> ';
    }
  } else if (canOperate){
    btns += '<button class="btn btn-sm" onclick="diskMountDialog(\''
         + escapeAttr(node.path) + '\',false)">挂载</button> ';
    btns += '<button class="btn btn-inverse btn-sm" onclick="diskMountDialog(\''
         + escapeAttr(node.path) + '\',true)">自动挂载</button> ';
  }
  if (canOperate){
    btns += '<button class="btn btn-danger btn-sm" onclick="diskFormatDialog(\''
         + escapeAttr(node.path) + '\')">格式化</button>';
  }
  const indent = 'padding-left:' + (12 + depth * 22) + 'px';
  rows.push(
    '<div style="display:flex;align-items:center;gap:10px;padding:10px 0;'
    + 'border-bottom:1px solid var(--line);' + indent + '">'
    + '<div style="flex:1;min-width:0">'
    +   '<div style="font-family:ui-monospace,monospace;font-size:13px;color:var(--fg)">'
    +     escapeHtml(node.name)
    +     ' <span style="color:var(--fg-dimmer);font-size:11px">' + escapeHtml(node.type) + '</span>'
    +     ' ' + tags.join(' ')
    +   '</div>'
    +   '<div style="font-size:11px;color:var(--fg-dim);font-family:ui-monospace,monospace;margin-top:3px;word-break:break-all">'
    +     escapeHtml(node.path) + ' · ' + sizeStr
    +     ' · FS: ' + escapeHtml(fs)
    +     (label ? ' · 标签: ' + escapeHtml(label) : '')
    +     (mp ? ' · <span style="color:var(--ok)">挂载于 ' + escapeHtml(mp) + '</span>' : '')
    +     (node.model ? ' · ' + escapeHtml(node.model) : '')
    +   '</div>'
    + '</div>'
    + (btns ? '<div style="flex:0 0 auto;display:flex;gap:4px;white-space:nowrap">' + btns + '</div>' : '')
    + '</div>'
  );
  for (const c of node.children || []){
    rows.push(renderDevice(c, depth + 1));
  }
  return rows.join('');
}
function fmtDiskSize(b){
  if (!b) return '—';
  if (b < 1024) return b + ' B';
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1024 * 1024 * 1024) return (b / 1024 / 1024).toFixed(1) + ' MB';
  if (b < 1024 * 1024 * 1024 * 1024) return (b / 1024 / 1024 / 1024).toFixed(2) + ' GB';
  return (b / 1024 / 1024 / 1024 / 1024).toFixed(2) + ' TB';
}
function renderFstabManaged(r){
  const el = document.getElementById("disk-fstab");
  const entries = [];
  const walk = (node) => {
    if (node.in_managed) entries.push(node);
    for (const c of node.children || []) walk(c);
  };
  for (const d of r.devices || []) walk(d);
  if (!entries.length){
    el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">'
      + '暂无 NetRouter 管理的挂载点</div>';
    return;
  }
  let html = '<table class="tbl"><thead><tr>'
    + '<th>设备</th><th>挂载点</th><th>文件系统</th><th>状态</th>'
    + '<th style="width:150px"></th></tr></thead><tbody>';
  for (const e of entries){
    const mounted = !!(e.mountpoint && e.mountpoint !== '');
    html += '<tr>'
      + '<td style="font-family:ui-monospace,monospace">' + escapeHtml(e.name) + '</td>'
      + '<td style="font-family:ui-monospace,monospace">' + escapeHtml(e.mountpoint || '—') + '</td>'
      + '<td>' + escapeHtml(e.fstype || '—') + '</td>'
      + '<td>' + (mounted
          ? '<span style="color:var(--ok)">已挂载</span>'
          : '<span style="color:var(--fg-dim)">未挂载</span>') + '</td>'
      + '<td style="text-align:right">'
      + '<button class="btn btn-danger btn-sm" onclick="diskUmount(\''
      +   escapeAttr(e.mountpoint || e.path) + '\')">卸载并移除</button>'
      + '</td></tr>';
  }
  html += '</tbody></table>';
  el.innerHTML = html;
}
function diskMountDialog(device, auto){
  const title = auto ? '自动挂载（写入 fstab）' : '临时挂载';
  const defMp = '/mnt/' + (device.split('/').pop() || 'disk');
  const body = ''
    + '<div class="form-col">'
    +   '<div style="color:var(--fg-dim);font-size:12px;font-family:ui-monospace,monospace">'
    +     '设备：' + escapeHtml(device) + '</div>'
    +   '<label>挂载点'
    +     '<input id="dm-mp" value="' + escapeAttr(defMp) + '" placeholder="/mnt/data"></label>'
    +   '<div class="form-row">'
    +     '<label>文件系统（留空自动）'
    +       '<input id="dm-fs" placeholder="ext4"></label>'
    +     '<label>挂载选项'
    +       '<input id="dm-opts" value="' + (auto ? 'defaults,nofail' : 'defaults') + '"></label>'
    +   '</div>'
    +   (auto
          ? '<div style="color:var(--warn);font-size:11.5px;line-height:1.7;'
            + 'border:1px solid var(--warn);padding:8px 10px;border-radius:2px">'
            + '⚠ 将写入 <b>UUID=...</b> 到 /etc/fstab 的 NetRouter 管理块。<br>'
            + '写入前会校验 fstab，失败自动回滚；默认添加 nofail 防止开机失败。'
            + '</div>'
          : '<div style="color:var(--fg-dimmer);font-size:11.5px;line-height:1.7">'
            + '临时挂载不会写入 fstab，重启后失效。'
            + '</div>')
    + '</div>';
  vmOpenModal(title, body, async () => {
    const mp = (document.getElementById("dm-mp").value || "").trim();
    const fs = (document.getElementById("dm-fs").value || "").trim();
    const opts = (document.getElementById("dm-opts").value || "").trim();
    if (!mp){ toast("请填写挂载点", true); return; }
    try {
      const r = await api.post("/api/disk/mount",
        {device, mountpoint: mp, fstype: fs, options: opts, auto});
      toast(r.message || (r.ok ? "已挂载" : "失败"), !r.ok);
      if (r.ok){
        vmCloseModal();
        loadDisks();
      }
    } catch(e){ toast(e.message, true); }
  });
}
async function diskUmount(mpOrDev){
  if (!confirm("卸载 " + mpOrDev + " ？\n（若为自动挂载，同时从 fstab 移除条目）")) return;
  try {
    const r = await api.post("/api/disk/umount", {target: mpOrDev});
    toast(r.message || (r.ok ? "已卸载" : "失败"), !r.ok);
    if (r.ok) loadDisks();
  } catch(e){ toast(e.message, true); }
}
function diskFormatDialog(device){
  const fsList = ['ext4', 'xfs', 'btrfs', 'vfat', 'exfat', 'ntfs', 'f2fs'];
  const body = ''
    + '<div class="form-col">'
    +   '<div style="color:var(--danger);font-size:12.5px;line-height:1.7;'
    +      'border:1px solid var(--danger);padding:10px 12px;border-radius:2px">'
    +     '⚠ <b>此操作将永久删除设备上的所有数据！</b><br>'
    +     '设备：<span style="font-family:ui-monospace,monospace">'
    +       escapeHtml(device) + '</span>'
    +   '</div>'
    +   '<div class="form-row">'
    +     '<label>文件系统<select id="df-fs">'
    +       fsList.map(f => '<option value="' + f + '">' + f + '</option>').join('')
    +     + '</select></label>'
    +     '<label>卷标（可选）'
    +       '<input id="df-label" maxlength="16" placeholder="DATA"></label>'
    +   '</div>'
    +   '<label>请输入 <b style="color:var(--danger)">FORMAT</b> 以确认'
    +     '<input id="df-confirm" placeholder="FORMAT"></label>'
    + '</div>';
  vmOpenModal("格式化 " + device, body, async () => {
    const confirmText = (document.getElementById("df-confirm").value || "").trim();
    if (confirmText !== "FORMAT"){
      toast("请输入 FORMAT 确认", true); return;
    }
    const fs = document.getElementById("df-fs").value;
    const label = (document.getElementById("df-label").value || "").trim();
    try {
      const r = await api.post("/api/disk/format",
        {device, fstype: fs, label});
      toast(r.message || (r.ok ? "格式化完成" : "失败"), !r.ok);
      if (r.ok){
        vmCloseModal();
        loadDisks();
      }
    } catch(e){ toast(e.message, true); }
  });
}

/* ==================== 文件共享 ==================== */
let _shareData = null;
async function loadShares(){
  try {
    const cfg = await api.get("/api/router/config");
    document.getElementById("share-root-warn").innerHTML = cfg.root ? "" :
      '<div class="warn-box">当前进程非 root 运行，配置 Samba 需要 sudo 启动 NetRouter。</div>';
  } catch(_){}
  const el = document.getElementById("share-status");
  el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">检测中...</div>';
  try {
    const r = await api.get("/api/samba/status");
    _shareData = r;
    if (!r.installed){
      el.innerHTML = '<div style="color:var(--warn);font-size:12px;margin-bottom:12px">'
        + 'Samba 未安装。可点击下方按钮安装，或前往「包管理 → 文件共享必备」一键安装。</div>'
        + '<div class="actions" style="margin-top:0">'
        + '<button class="btn" onclick="installSamba()">立即安装 Samba</button>'
        + '</div>';
      document.getElementById("share-list").innerHTML =
        '<div style="color:var(--fg-dimmer);font-size:12px">请先安装 Samba</div>';
      return;
    }
    el.innerHTML = ''
      + '<div style="font-size:12px;color:var(--fg-dim);line-height:1.9">'
      +   '状态：'
      +   (r.running
          ? '<span style="color:var(--ok)">● 运行中</span>'
          : '<span style="color:var(--warn)">● 未运行</span>')
      +   '<br>'
      +   '配置文件：<span style="font-family:ui-monospace,monospace">'
      +     escapeHtml(r.conf_path || '') + '</span>'
      + '</div>'
      + '<div class="actions" style="margin-top:12px">'
      +   '<button class="btn btn-inverse btn-sm" onclick="sambaRestart()">重启服务</button>'
      + '</div>'
      + '<div id="share-guest-policy" '
      +   'style="margin-top:16px;padding-top:16px;border-top:1px solid var(--line)">'
      +   '<div style="color:var(--fg-dimmer);font-size:11px">加载策略...</div>'
      + '</div>';
    renderShareList(r.shares || []);
    loadGuestPolicy();
  } catch(e){
    el.innerHTML = '<div style="color:var(--danger)">' + escapeHtml(e.message) + '</div>';
  }
  loadSambaUsers();
}
function renderShareList(shares){
  const el = document.getElementById("share-list");
  if (!shares.length){
    el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">'
      + '暂无共享。点击「+ 添加共享」创建第一个。</div>';
    return;
  }
  let html = '<table class="tbl"><thead><tr>'
    + '<th>名称</th><th>路径</th><th>只读</th><th>访客</th>'
    + '<th>force user</th>'
    + '<th style="width:160px"></th></tr></thead><tbody>';
  for (const sh of shares){
    const p = sh.params || {};
    const ro = (p["read only"] || "no").toLowerCase() === "yes";
    const guest = (p["guest ok"] || "no").toLowerCase() === "yes";
    const fu = p["force user"] || "";
    const fg = p["force group"] || "";
    const forceLabel = fu
      ? '<span style="color:var(--ok)">' + escapeHtml(fu) + '</span>'
        + (fg ? ' : <span style="color:var(--ok)">' + escapeHtml(fg) + '</span>' : '')
      : '<span style="color:var(--fg-dimmer)">—</span>';
    html += '<tr>'
      + '<td style="color:var(--fg);font-weight:600">' + escapeHtml(sh.name) + '</td>'
      + '<td style="font-family:ui-monospace,monospace;font-size:11px;word-break:break-all">'
      +   escapeHtml(p.path || '') + '</td>'
      + '<td>' + (ro
          ? '<span style="color:var(--warn)">是</span>'
          : '<span style="color:var(--ok)">否</span>') + '</td>'
      + '<td>' + (guest
          ? '<span style="color:var(--warn)">允许</span>'
          : '<span style="color:var(--fg-dim)">否</span>') + '</td>'
      + '<td style="font-family:ui-monospace,monospace;font-size:11px">'
      +   forceLabel + '</td>'
      + '<td style="text-align:right;white-space:nowrap">'
      + '<button class="btn btn-inverse btn-sm" onclick="editShare(\''
      +   escapeAttr(sh.name) + '\')">编辑</button> '
      + '<button class="btn btn-danger btn-sm" onclick="removeShare(\''
      +   escapeAttr(sh.name) + '\')">删除</button>'
      + '</td></tr>';
  }
  html += '</tbody></table>';
  el.innerHTML = html;
}
async function installSamba(){
  if (!confirm("安装 Samba？\n将执行 apt-get install -y samba samba-common-bin smbclient")) return;
  try {
    const r = await api.post("/api/samba/install", {});
    toast(r.message || (r.ok ? "已安装" : "失败"), !r.ok);
    if (r.ok) loadShares();
  } catch(e){ toast(e.message, true); }
}
async function sambaRestart(){
  if (!confirm("重启 smbd 服务？")) return;
  try {
    const r = await api.post("/api/samba/restart", {});
    toast(r.message || (r.ok ? "已重启" : "失败"), !r.ok);
  } catch(e){ toast(e.message, true); }
}
async function _loadSystemUsersCache(){
  if (window._sysUsersCache) return window._sysUsersCache;
  try {
    const r = await api.get("/api/samba/system-users");
    window._sysUsersCache = r;
    return r;
  } catch(_) {
    return {users: [], groups: []};
  }
}

function _buildShareForm(sh, opts){
  opts = opts || {};
  const isEdit = !!opts.isEdit;
  const usersHtml = (window._sysUsersCache && window._sysUsersCache.users || [])
    .map(u => '<option value="' + escapeAttr(u.name) + '">'
      + escapeHtml(u.name) + ' (uid ' + u.uid + ')</option>').join('');
  const groupsHtml = (window._sysUsersCache && window._sysUsersCache.groups || [])
    .map(g => '<option value="' + escapeAttr(g.name) + '">'
      + escapeHtml(g.name) + ' (gid ' + g.gid + ')</option>').join('');
  const forceUserVal = (sh.params && (sh.params["force user"] || sh.params["force user"])) || '';
  const forceGroupVal = (sh.params && (sh.params["force group"] || "")) || "";
  const comment = (sh.params && sh.params["comment"]) || "";
  const readonly = (sh.params && (sh.params["read only"] || "no").toLowerCase() === "yes");
  const guest = (sh.params && (sh.params["guest ok"] || "no").toLowerCase() === "yes");
  const browse = (sh.params && (sh.params["browseable"] || "yes").toLowerCase() !== "no");
  const validUsers = (sh.params && sh.params["valid users"]) || "";

  return ''
    + '<div class="form-col">'
    +   '<label>共享名（1-32 位字母数字 _ - .）'
    +     '<input id="sh-name" value="' + escapeAttr(sh.name || '') + '" '
    +     (isEdit ? 'disabled' : '')
    +     ' placeholder="public"></label>'
    +   '<label>共享目录（绝对路径）'
    +     '<input id="sh-path" value="' + escapeAttr((sh.params && sh.params.path) || '') + '" '
    +     'placeholder="/srv/share"></label>'
    +   '<label>备注（可选）'
    +     '<input id="sh-comment" maxlength="64" value="' + escapeAttr(comment) + '"></label>'
    +   '<div style="display:flex;gap:16px;flex-wrap:wrap">'
    +     '<label class="checkbox-row" style="flex-direction:row">'
    +       '<input type="checkbox" id="sh-ro"' + (readonly ? ' checked' : '') + '> 只读</label>'
    +     '<label class="checkbox-row" style="flex-direction:row">'
    +       '<input type="checkbox" id="sh-guest"' + (guest ? ' checked' : '') + '> 允许访客（免密码）</label>'
    +     '<label class="checkbox-row" style="flex-direction:row">'
    +       '<input type="checkbox" id="sh-browse"' + (browse ? ' checked' : '') + '> 网络邻居可见</label>'
    +   '</div>'
    +   '<label>Valid users（可选，空格分隔）'
    +     '<input id="sh-valid" value="' + escapeAttr(validUsers) + '" '
    +     'placeholder="alice bob"></label>'
    +   '<div style="padding:12px;border:1px solid var(--line);border-radius:2px;'
    +     'background:var(--bg);display:flex;flex-direction:column;gap:12px">'
    +     '<div style="font-size:12px;color:var(--fg-dim);letter-spacing:.06em">'
    +       'FORCE USER / GROUP — 以指定身份访问文件（解决权限问题）</div>'
    +     '<div class="form-row">'
    +       '<label>force user'
    +         '<input id="sh-force-user" list="sys-users-list" '
    +         'value="' + escapeAttr(forceUserVal) + '" '
    +         'placeholder="ldy（可选）"></label>'
    +       '<label>force group'
    +         '<input id="sh-force-group" list="sys-groups-list" '
    +         'value="' + escapeAttr(forceGroupVal) + '" '
    +         'placeholder="ldy（可选）"></label>'
    +     '</div>'
    +     '<datalist id="sys-users-list">' + usersHtml + '</datalist>'
    +     '<datalist id="sys-groups-list">' + groupsHtml + '</datalist>'
    +     '<div style="color:var(--fg-dimmer);font-size:11.5px;line-height:1.7">'
    +       '· 当客户端的用户对共享目录没权限时，用 force user 让 Samba '
    +       '以该用户身份读写<br>'
    +       '· 例如：Guest 访问 /home/ldy（750 权限）时，填 force user=ldy 即可'
    +     '</div>'
    +   '</div>'
    +   '<div style="color:var(--fg-dimmer);font-size:11.5px;line-height:1.7">'
    +     '· 系统需存在该目录，请先创建并设置权限<br>'
    +     '· 非访客模式需系统用户存在且已用 smbpasswd 设置过密码<br>'
    +     '· 配置将追加到 /etc/samba/smb.conf 的 NetRouter 管理块'
    +   '</div>'
    + '</div>';
}

async function showAddShare(){
  await _loadSystemUsersCache();
  const body = _buildShareForm({name: "", params: {}}, {isEdit: false});
  vmOpenModal("添加共享", body, async () => {
    const name = (document.getElementById("sh-name").value || "").trim();
    const path = (document.getElementById("sh-path").value || "").trim();
    const comment = (document.getElementById("sh-comment").value || "").trim();
    const readonly = document.getElementById("sh-ro").checked;
    const guest = document.getElementById("sh-guest").checked;
    const browseable = document.getElementById("sh-browse").checked;
    const validUsers = (document.getElementById("sh-valid").value || "").trim();
    const forceUser = (document.getElementById("sh-force-user").value || "").trim();
    const forceGroup = (document.getElementById("sh-force-group").value || "").trim();
    if (!name){ toast("请输入共享名", true); return; }
    if (!path || !path.startsWith("/")){ toast("请输入绝对路径", true); return; }
    try {
      const r = await api.post("/api/samba/share/add", {
        name, path, comment, readonly, guest, browseable,
        valid_users: validUsers,
        force_user: forceUser,
        force_group: forceGroup,
        overwrite: true,
      });
      toast(r.message || (r.ok ? "已添加" : "失败"), !r.ok);
      if (r.ok){
        vmCloseModal();
        loadShares();
      }
    } catch(e){ toast(e.message, true); }
  });
}

async function editShare(name){
  try {
    const r = await api.get("/api/samba/status");
    const shares = r.shares || [];
    const sh = shares.find(s => s.name === name);
    if (!sh){ toast("共享不存在", true); return; }
    await _loadSystemUsersCache();
    const body = _buildShareForm(sh, {isEdit: true});
    vmOpenModal("编辑共享 · " + name, body, async () => {
      const path = (document.getElementById("sh-path").value || "").trim();
      const comment = (document.getElementById("sh-comment").value || "").trim();
      const readonly = document.getElementById("sh-ro").checked;
      const guest = document.getElementById("sh-guest").checked;
      const browseable = document.getElementById("sh-browse").checked;
      const validUsers = (document.getElementById("sh-valid").value || "").trim();
      const forceUser = (document.getElementById("sh-force-user").value || "").trim();
      const forceGroup = (document.getElementById("sh-force-group").value || "").trim();
      if (!path || !path.startsWith("/")){ toast("请输入绝对路径", true); return; }
      try {
        const r2 = await api.post("/api/samba/share/add", {
          name, path, comment, readonly, guest, browseable,
          valid_users: validUsers,
          force_user: forceUser,
          force_group: forceGroup,
          overwrite: true,
        });
        toast(r2.message || (r2.ok ? "已更新" : "失败"), !r2.ok);
        if (r2.ok){
          vmCloseModal();
          loadShares();
        }
      } catch(e){ toast(e.message, true); }
    });
  } catch(e){ toast(e.message, true); }
}
async function removeShare(name){
  if (!confirm("删除共享 " + name + " ？")) return;
  try {
    const r = await api.post("/api/samba/share/remove", {name});
    toast(r.message || (r.ok ? "已删除" : "失败"), !r.ok);
    if (r.ok) loadShares();
  } catch(e){ toast(e.message, true); }
}

/* ---------- Samba 全局 Guest 策略 ---------- */
async function loadGuestPolicy(){
  const el = document.getElementById("share-guest-policy");
  if (!el) return;
  el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:11px">加载策略...</div>';
  try {
    const r = await api.get("/api/samba/guest-policy");
    const opts = (r.options || []).map(o =>
      '<option value="' + escapeAttr(o.value) + '"'
      + (o.value === r.policy ? ' selected' : '') + '>'
      + escapeHtml(o.value) + ' — ' + escapeHtml(o.desc) + '</option>'
    ).join('');
    el.innerHTML = ''
      + '<div style="font-size:12px;color:var(--fg-dim);letter-spacing:.08em;'
      +   'text-transform:uppercase;margin-bottom:10px">'
      +   '认证失败策略（map to guest）</div>'
      + '<div class="form-row" style="gap:10px;align-items:flex-end">'
      +   '<label style="flex:1">策略'
      +     '<select id="guest-policy-sel">' + opts + '</select></label>'
      +   '<button class="btn btn-sm" style="flex:0 0 auto" '
      +     'onclick="saveGuestPolicy()">应用</button>'
      + '</div>'
      + '<div style="color:var(--fg-dimmer);font-size:11.5px;margin-top:8px;line-height:1.7">'
      +   '· <b style="color:var(--fg)">Never</b>：认证失败立即拒绝，'
      +     'Windows 会弹窗重新输入用户名密码（<span style="color:var(--ok)">推荐</span>）<br>'
      +   '· <b style="color:var(--warn)">Bad User</b>：用户名不存在 → 降级为 Guest（易被匿名访问）<br>'
      +   '· 修改后立即生效，无需重启 Windows'
      + '</div>';
  } catch(e){
    el.innerHTML = '<div style="color:var(--danger);font-size:12px">'
      + escapeHtml(e.message) + '</div>';
  }
}

async function saveGuestPolicy(){
  const sel = document.getElementById("guest-policy-sel");
  if (!sel) return;
  const policy = sel.value;
  if (!confirm("切换认证失败策略为「" + policy + "」？\n\n"
      + (policy === "Never"
         ? "认证失败会直接拒绝，Windows 将重新弹窗输入用户名密码。"
         : "认证失败可能降级为 Guest，等同匿名访问。")
      + "\n\n继续？")) return;
  try {
    const r = await api.post("/api/samba/guest-policy", {policy});
    toast(r.message || (r.ok ? "已应用" : "失败"), !r.ok);
    if (r.ok){
      // 通知 Windows 清缓存
      setTimeout(() => {
        toast("提示：Windows 端请执行 net use * /delete /y 清除旧凭据", false);
      }, 1500);
      loadShares();
    }
  } catch(e){ toast(e.message, true); }
}

/* ---------- Samba 账户管理 ---------- */
async function loadSambaUsers(){
  const el = document.getElementById("share-users");
  if (!el) return;
  el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">加载中...</div>';
  try {
    const r = await api.get("/api/samba/users");
    if (!r.installed){
      el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">'
        + '请先安装 Samba（见上方服务状态）</div>';
      return;
    }
    renderSambaUsers(r.users || []);
  } catch(e){
    el.innerHTML = '<div style="color:var(--danger)">' + escapeHtml(e.message) + '</div>';
  }
}

function renderSambaUsers(users){
  const el = document.getElementById("share-users");
  if (!users.length){
    el.innerHTML = '<div style="color:var(--fg-dimmer);font-size:12px">'
      + '暂无 Samba 用户。点击「+ 添加用户」创建第一个。</div>';
    return;
  }
  let html = '<table class="tbl"><thead><tr>'
    + '<th>用户名</th><th>状态</th><th>系统账户</th>'
    + '<th>引用共享</th><th>上次改密</th>'
    + '<th style="width:260px"></th></tr></thead><tbody>';
  for (const u of users){
    const sysLabel = u.has_system_account
      ? '<span style="color:var(--ok)">✓</span>'
      : '<span style="color:var(--warn)">✗</span>';
    const sharesLabel = (u.in_shares && u.in_shares.length)
      ? escapeHtml(u.in_shares.join(", "))
      : '<span style="color:var(--fg-dimmer)">—</span>';
    html += '<tr>'
      + '<td style="color:var(--fg);font-weight:600">' + escapeHtml(u.name) + '</td>'
      + '<td>' + (u.enabled
          ? '<span style="color:var(--ok)">启用</span>'
          : '<span style="color:var(--fg-dim)">禁用</span>') + '</td>'
      + '<td>' + sysLabel + '</td>'
      + '<td style="font-size:11px;font-family:ui-monospace,monospace">'
      +   sharesLabel + '</td>'
      + '<td style="font-size:11px;color:var(--fg-dim)">'
      +   escapeHtml(u.last_change || '—') + '</td>'
      + '<td style="text-align:right;white-space:nowrap">'
      + '<button class="btn btn-inverse btn-sm" onclick="sambaUserPasswd(\''
      +   escapeAttr(u.name) + '\')">改密</button> '
      + '<button class="btn btn-inverse btn-sm" onclick="toggleSambaUser(\''
      +   escapeAttr(u.name) + '\',' + (u.enabled ? 'false' : 'true') + ')">'
      +   (u.enabled ? '禁用' : '启用') + '</button> '
      + '<button class="btn btn-danger btn-sm" onclick="removeSambaUser(\''
      +   escapeAttr(u.name) + '\')">删除</button>'
      + '</td></tr>';
  }
  html += '</tbody></table>';
  el.innerHTML = html;
}

function showAddSambaUser(){
  const body = ''
    + '<div class="form-col">'
    +   '<label>用户名'
    +     '<input id="su-name" placeholder="alice" '
    +     'pattern="[a-z_][a-z0-9_\\-]{0,31}" '
    +     'title="小写字母或 _ 开头，可含数字、_、-，1-32 位"></label>'
    +   '<label>密码（≥6 位）'
    +     '<input id="su-pwd" type="password"></label>'
    +   '<label>确认密码'
    +     '<input id="su-pwd2" type="password"></label>'
    +   '<label class="checkbox-row" style="flex-direction:row">'
    +     '<input type="checkbox" id="su-create-sys" checked> '
    +     '系统账户不存在时自动创建（无家目录、不可登录）</label>'
    +   '<div style="color:var(--fg-dimmer);font-size:11.5px;line-height:1.7">'
    +     '· 用户名必须符合 Linux 命名规则：小写字母或 _ 开头<br>'
    +     '· 密码仅用于 SMB 访问，与系统密码独立<br>'
    +     '· 若关闭「自动创建」，请确认系统已存在同名用户'
    +   '</div>'
    + '</div>';
  vmOpenModal("添加 Samba 用户", body, async () => {
    const name = (document.getElementById("su-name").value || "").trim();
    const pwd  = document.getElementById("su-pwd").value || "";
    const pwd2 = document.getElementById("su-pwd2").value || "";
    const createSys = document.getElementById("su-create-sys").checked;
    if (!/^[a-z_][a-z0-9_\-]{0,31}$/.test(name)){
      toast("用户名非法（小写字母或 _ 开头，1-32 位）", true); return;
    }
    if (pwd.length < 6){ toast("密码至少 6 位", true); return; }
    if (pwd !== pwd2){ toast("两次输入的密码不一致", true); return; }
    try {
      const r = await api.post("/api/samba/users/add",
        {name, password: pwd, create_system: createSys});
      toast(r.message || (r.ok ? "已添加" : "失败"), !r.ok);
      if (r.ok){
        vmCloseModal();
        loadSambaUsers();
      }
    } catch(e){ toast(e.message, true); }
  });
}

function sambaUserPasswd(name){
  const body = ''
    + '<div class="form-col">'
    +   '<div style="color:var(--fg-dim);font-size:12px;'
    +      'font-family:ui-monospace,monospace">用户：'
    +      escapeHtml(name) + '</div>'
    +   '<label>新密码（≥6 位）'
    +     '<input id="sp-pwd" type="password"></label>'
    +   '<label>确认新密码'
    +     '<input id="sp-pwd2" type="password"></label>'
    + '</div>';
  vmOpenModal("修改 Samba 密码 · " + name, body, async () => {
    const pwd  = document.getElementById("sp-pwd").value || "";
    const pwd2 = document.getElementById("sp-pwd2").value || "";
    if (pwd.length < 6){ toast("密码至少 6 位", true); return; }
    if (pwd !== pwd2){ toast("两次输入的密码不一致", true); return; }
    try {
      const r = await api.post("/api/samba/users/passwd",
        {name, password: pwd});
      toast(r.message || (r.ok ? "已修改" : "失败"), !r.ok);
      if (r.ok){
        vmCloseModal();
        loadSambaUsers();
      }
    } catch(e){ toast(e.message, true); }
  });
}

async function toggleSambaUser(name, enable){
  const label = enable ? "启用" : "禁用";
  if (!confirm(label + " Samba 用户 " + name + " ？")) return;
  try {
    const r = await api.post("/api/samba/users/toggle",
      {name, enable});
    toast(r.message || (r.ok ? "已" + label : "失败"), !r.ok);
    if (r.ok) loadSambaUsers();
  } catch(e){ toast(e.message, true); }
}

async function removeSambaUser(name){
  if (!confirm("删除 Samba 用户 " + name + " ？\n\n"
      + "Samba 密码会被清除，但系统账户默认保留。")) return;
  const removeSys = confirm(
    "是否同时删除对应的 Linux 系统账户？\n\n"
    + "「确定」= 一并删除系统账户（请确认该账户未被其他服务使用）\n"
    + "「取消」= 仅删除 Samba 账户，保留系统账户");
  try {
    const r = await api.post("/api/samba/users/remove",
      {name, remove_system: removeSys});
    toast(r.message || (r.ok ? "已删除" : "失败"), !r.ok);
    if (r.ok) loadSambaUsers();
  } catch(e){ toast(e.message, true); }
}

/* ==================== boot ==================== */
function boot(){
  loadDashboard();
  connectTrafficWS();
  setInterval(() => {
    if (document.getElementById("view-dashboard").classList.contains("active")){
      loadDashboard();
    }
  }, 5000);
  api.get("/api/router/config").then(r => {
    if (!r.root){
      document.getElementById("root-warn").innerHTML =
        '<div class="warn-box">当前以非 root 运行，修改网络/防火墙/服务会失败。请使用 sudo 重新启动。</div>';
    }
  }).catch(()=>{});
}
window.addEventListener("DOMContentLoaded", async () => {
  if (!Token.get()){ showLogin(); return; }
  try { await api.get("/api/auth/me"); hideLogin(); boot(); }
  catch(_) { showLogin(); }
});
</script>
</body>
</html>
"""

# ============================================================
# 首页
# ============================================================
@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse(INDEX_HTML)

# ============================================================
# 启动
# ============================================================
def main():
    pwd = init_default_password()
    cfg = load_router_cfg()
    fw = load_firewall_cfg()
    peers = load_wg_peers()
    vm_cfg = load_vm_cfg()
    banner = [
        "",
        "  NetRouter  Ubuntu 一体化路由器软件（安全加固版）",
        "  =====================================",
        f"  监听地址 : http://{HOST}:{PORT}",
        f"  配置目录 : {CONF_DIR}",
        f"  Root     : {'是' if is_root() else '否（修改网络需 root）'}",
        "",
        "  安全特性：",
        "    · 所有系统配置文件字段经过严格正则校验，防注入 / RCE",
        "    · 配置文件原子写入（os.replace），防截断损坏",
        "    · token 版本号，改密码后旧会话立即失效",
        "    · 登录失败限速（5 次/分钟/IP）",
        "    · 关闭 /docs /openapi.json /redoc",
        "    · WireGuard 对端列表脱敏，私钥不外泄",
        "    · 审计日志 /etc/netrouter/audit.log",
        "",
        "  路由配置 :",
        f"    WAN      : {cfg.get('wan_if') or '（未配置）'} "
        f"[{cfg.get('wan_mode', 'dhcp')}]",
        f"    LAN 桥接 : {cfg.get('br_name')} = "
        f"{cfg.get('lan_ifs') or '（未配置）'}",
        f"    DHCP     : "
        f"{'启用' if cfg.get('lan_dhcp_enabled', True) else '禁用'}",
    ]
    if cfg.get("wg_enabled"):
        mode = cfg.get("wg_mode", "client")
        banner.append(f"    WireGuard: 已启用 [{mode}] {cfg.get('wg_interface', 'wg0')}")
        if mode == "server":
            banner.append(f"               监听端口 {cfg.get('wg_server_port', '51820')}，"
                          f"对端 {len(peers)} 个")
    else:
        banner.append("    WireGuard: 未启用")
    banner += [
        "",
        "  防火墙   : 强制启用（不可关闭）",
        f"    区域数 : {len(fw.get('zones') or [])}",
        f"    转发数 : {len(fw.get('forwardings') or [])}",
        f"    端口映射数: {len(fw.get('port_forwards') or [])}",
        f"    端口规则数: {len(fw.get('input_rules') or [])}",
        "",
        "  虚拟机   : QEMU/KVM + libvirt",
        f"    存储目录 : {vm_cfg.get('storage_dir')}",
        f"    ISO 目录 : {' / '.join(vm_cfg.get('iso_dirs') or [])}",
        f"    VNC 端口 : {VNC_PORT_MIN}-{VNC_PORT_MAX}（不自动放行 wan）",
        "",
        "  磁盘管理 : 挂载 / 格式化 / fstab 自动挂载",
        f"    fstab 备份 : {FSTAB_BACKUP}",
        "",
        "  文件共享 : Samba SMB / CIFS",
        f"    smb.conf   : {SAMBA_CONF}",
        f"    备份       : {SAMBA_BACKUP}",
        "",
    ]
    if pwd:
        banner += [
            "  首次启动，初始密码如下（请登录后立即修改）：",
            f"      {pwd}",
            "",
            "    自定义：NETROUTER_PASSWORD=xxx sudo python3 route.py",
            "",
        ]
    banner += [
        f"  Netplan   : {NETPLAN_FILE}",
        f"  dnsmasq   : {DNSMASQ_FILE}",
        f"  hostapd   : {HOSTAPD_CONF}",
        f"  nftables  : table inet {NFT_ROUTER_TABLE}（统一规则集）",
        f"  审计日志  : {AUDIT_LOG}",
        "",
        "  功能标签页：",
        "    概览 / 路由器 / 防火墙 / 包管理 / 虚拟机 / 磁盘管理 / 文件共享",
        "",
        "  使用建议：",
        "    1) 浏览器打开上面的地址，用初始密码登录",
        "    2) 进入「包管理」一键安装各功能所需依赖",
        "    3) 进入「路由器」勾选 WAN/LAN，按需配置 WireGuard",
        "    4) 保存后点「一键应用」——自动创建防火墙基础区域",
        "    5) 进入「虚拟机」创建与管理虚拟机",
        "    6) 进入「磁盘管理」挂载 / 格式化 / fstab 自动挂载",
        "    7) 进入「文件共享」配置 Samba 共享",
        "    8) 右上角「修改密码」——所有会话将被强制下线",
        "",
    ]
    print("\n".join(banner))
    if not is_root():
        print("  警告：当前非 root 运行，修改网络/防火墙/包管理/虚拟机/磁盘/共享会失败。")
        print("  建议: sudo python3 route.py\n")
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")

if __name__ == "__main__":
    main()

# === END OF PART 5 ===
