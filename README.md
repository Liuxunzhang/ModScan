# ModScan

Linux 内核模块 DKOM 检测与还原工具。

## 背景

DKOM（Direct Kernel Object Manipulation，直接内核对象篡改）是 rootkit 的常见技术。针对内核模块时，rootkit 会调用：

```c
list_del(&THIS_MODULE->list);
```

将模块从全局 `modules` 链表中摘除。此后 `lsmod` 和 `rmmod` 无法找到该模块，但它仍在内存中运行。

## 检测原理

Linux 内核维护两个独立的数据结构追踪已加载模块：

| 数据结构 | 用途 | DKOM 是否影响 |
|---|---|---|
| `modules` 链表（`struct module.list`） | `lsmod`、`rmmod` 使用 | 是，rootkit 会从此处摘除 |
| `module_kset` kobject 树 | sysfs (`/sys/module/`) 使用 | 通常不影响 |

ModScan 对比这两个数据结构：

- **出现在 kset 中但不在 modules 链表中**：典型 `list_del` 隐藏模块
- **出现在 modules 链表中但不在 kset/sysfs 中**：疑似 `module_kset`/sysfs 视图被篡改

还原时，使用 `list_add()` 将模块重新插入 `modules` 链表头部，之后 `lsmod` 和 `rmmod` 即可正常工作。

## 构建

需要当前内核的头文件和构建工具：

```bash
# Debian/Ubuntu
sudo apt install linux-headers-$(uname -r) build-essential

# RHEL/Fedora
sudo dnf install kernel-devel kernel-headers gcc make

# 构建
make
```

## 使用

```bash
# 加载内核模块
sudo insmod modscan.ko

# 扫描隐藏模块
sudo ./modscan_cli scan
# 或直接读取 proc 文件
sudo cat /proc/modscan

# 还原被隐藏的模块（替换 <modname> 为实际模块名）
sudo ./modscan_cli restore <modname>

# 验证还原结果
lsmod | grep <modname>

# 还原后即可正常卸载
sudo rmmod <modname>

# 卸载 modscan 本身
sudo rmmod modscan
```

## 内核兼容性

| 特性 | 处理方式 |
|---|---|
| `kallsyms_lookup_name` 在 ≥ 5.7 不再导出 | 通过 kprobe 在加载时获取地址 |
| `proc_ops` 在 5.6 引入，旧版本用 `file_operations` | 编译时版本检查 |
| `module_mutex` 为 GPL 导出符号 | 直接声明 extern（模块使用 GPL 协议） |

测试过的内核版本：5.x、6.x

## 文件说明

```
modscan.c       — 内核模块源码
modscan_cli.c   — 用户态 CLI 工具
Makefile        — 构建脚本
```

## 当模块加载被 rootkit 禁止时

rootkit 植入后可能采取以下措施阻止加载检测工具：

### 攻击手段与检测方法

| 攻击手段 | 实现方式 | 检测工具 | 还原路径 |
|---|---|---|---|
| `modules_disabled=1` | 单向开关，写内核变量 | `modscan_scan.sh` `modscan_kcore` | **kexec** 或重启 |
| Hook `finit_module` | 函数首字节改写为 `JMP` | `modscan_kcore` | 预加载 modscan 或 kexec |
| 系统调用表劫持 | `sys_call_table[313]` 改写 | `modscan_kcore` | 同上 |
| LSM hook 插入 | 向 `security_hook_heads` 插入拦截函数 | `modscan_kcore`（部分） | 同上 |
| `sig_enforce=1` | 强制签名验证 | `modscan_scan.sh` | 签署模块或 kexec |
| `module_kset`/sysfs 篡改 | 删除/伪造 `/sys/module` 视图或 kset 链接 | `modscan.ko` `modscan_scan.sh` `modscan_kcore` | **仅告警，不自动修复**；建议 kexec/可信重启 |
| 链表无关隐藏（内存驻留） | 绕过 `modules` 链表，残留 `struct module` 对象 | `modscan_kcore`（内存 carving） | **仅告警，不自动修复**；建议 kexec/可信重启 |

### 检测工具（无需加载模块）

```bash
# 方法1: 纯 bash，最简单
sudo bash modscan_scan.sh

# 方法2: 更深层，通过 /proc/kcore 读取内核内存
sudo ./modscan_kcore

# 一键运行两种检测
make check
```

### 还原路径

**方案 A（最优）：提前加载 modscan.ko**

在 rootkit 有机会禁用模块加载之前加载 modscan：

```bash
# 开机自动加载（加入 /etc/modules 或 systemd unit）
echo "modscan" >> /etc/modules

# 之后即使 modules_disabled=1，/proc/modscan 仍然可用
echo 'restore <hidden_mod>' > /proc/modscan
```

**方案 B：kexec 替换内核**

`kexec` 直接将新内核加载到内存并执行，**不依赖模块加载机制**，rootkit 随旧内核消失：

```bash
# 确认 kexec 未被禁用
cat /proc/sys/kernel/kexec_load_disabled   # 必须为 0

# 加载干净的内核镜像
kexec -l /boot/vmlinuz-$(uname -r) \
      --initrd=/boot/initramfs-$(uname -r).img \
      --reuse-cmdline

# 执行切换（rootkit 消失）
kexec -e
```

**方案 C：内核调试器 kdb**

若内核编译时启用了 `CONFIG_KDB=y`（RHEL/CentOS 系内核通常有）：

```bash
# 触发进入 kdb
echo g > /proc/sysrq-trigger

# 在 kdb 中：
kdb> lsmod                          # 查看所有模块（包括隐藏的）
kdb> md <modules_list_addr>         # 读链表内存
kdb> mm <list.next_addr> <value>    # 直接写指针，重新链接模块
# mm 命令绕过所有软件 hook，直接操作物理内存映射
```

**方案 D：可信介质重启**

最保守但最可靠的方案：从 Live USB/CD 启动，挂载受感染的文件系统进行离线分析和清理。

### 检测能力矩阵

```
                      modscan.ko  modscan_scan.sh  modscan_kcore
DKOM list_del 隐藏        ✓             ✓               ✓
module_kset/sysfs 篡改     ✓(反向对比)    ✓(反向对比)      ✓(三视图交叉验证)
链表无关隐藏(carving)      ✗             ✗               ✓(内存特征扫描)
modules_disabled=1        N/A           ✓               ✓
finit_module 内联 patch   N/A           ✓(需python3)    ✓
系统调用表劫持             N/A           ✓(需python3)    ✓
LSM hook 插入             N/A           ✗               部分
/proc/modules 伪造        N/A           ✗               ✓(kcore对比)
```

## 注意事项

- 需要 root 权限（`CAP_SYS_MODULE`）
- `/proc/modscan` 权限为 0600，只有 root 可读写
- 在启用了 `CONFIG_RANDSTRUCT`（结构体布局随机化）的内核上，`struct module_kobject` 的字段顺序可能与预期不同，但由于我们使用相同内核头文件编译，`container_of` 偏移量是一致的
- 对 `module_kset`/sysfs 篡改仅做检测告警，不做自动修复（避免在未知污染状态下误改链表）
- `modscan_kcore` 的 carving 基于 `struct module` 特征与启发式评分；在裁剪内核/强随机化场景可能出现误报或漏报，建议结合多视图结果一起判断
