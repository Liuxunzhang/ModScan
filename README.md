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

ModScan 对比这两个数据结构：**出现在 kset 中但不在 modules 链表中的模块就是被隐藏的模块**。

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

## 注意事项

- 需要 root 权限（`CAP_SYS_MODULE`）
- `/proc/modscan` 权限为 0600，只有 root 可读写
- 在启用了 `CONFIG_RANDSTRUCT`（结构体布局随机化）的内核上，`struct module_kobject` 的字段顺序可能与预期不同，但由于我们使用相同内核头文件编译，`container_of` 偏移量是一致的
- 本工具仅针对通过 `list_del` 隐藏的模块；同时还修改了 kset 的 rootkit 不在本工具检测范围内
