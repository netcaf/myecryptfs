# 定制 eCryptfs 内部访问控制系统需求设计（v6.0）

---

## 一、总体目标

设计一个仅用于 **定制 eCryptfs 模块内部**的访问控制系统，具备以下特性：

- 基于 **inode（对象中心）** 的访问控制
- 支持规则 **持久化**，重启后规则仍有效
- 支持目录继承
- 高性能，适用于高频 read/write/open 场景
- 支持 **namespace 无关** 的访问决策
- 内核级实现，不依赖外部 LSM
- 对用户展示可读，避免纯数字不可理解的规则
- ACL 决策作为系统原生权限检查后的**最终控制层**

---

## 二、访问决策模型

访问决策由三维组成：

```
Subject (主体)
+
Permission (r/w/x)
+
Content Mode (plaintext / ciphertext / deny)
=
Access Result (最终访问行为)
```

- **权限**：最终权限取 **系统原生权限 ∩ ACL 权限**
- **内容模式**：由 ACL 覆盖（plaintext / ciphertext / deny）
- **deny** 优先级最高，直接阻止访问

> 例如：vim 只读查看密文 → 即便原文件可写，最终访问只读并返回密文

**约束**：`content=ciphertext` 时，write 权限自动无效。即使 ACL 声明 `permission=rw`，最终只有 `r`。这是由密文 Cache 隔离机制在内核层强制保证的，不依赖规则配置是否正确。

---

## 三、规则维度

### 1️⃣ 主体（Subject）

支持任意组合：

- **user**：内核真实 UID (`kuid`)
- **group**：内核真实 GID (`kgid`)
- **process**：可执行文件 inode

**注意**：

- 路径仅用于规则定义和展示
- namespace 与 mount 无关
- 对容器友好

---

### 2️⃣ 文件操作权限

- `r`（read）
- `w`（write）
- `x`（execute）

**冲突处理**：

- ACL **不能提升系统权限**
- 最终权限 = 系统权限 ∩ ACL 权限

---

### 3️⃣ 内容模式（Content Mode）

定义该主体对该文件的**访问结果**，三者互斥，规则中 `content` 字段取其一：

- `plaintext`：允许访问，返回解密后的明文
- `ciphertext`：允许访问，返回原始密文（**强制只读**，见第二章约束）
- `deny`：拒绝访问，直接阻止，不返回任何数据

> ACL 内容模式覆盖系统原始内容模式，deny 强制阻止访问

---

## 四、对象中心模型

- 规则作用于 **被访问对象 inode**
- 不存在全局或 namespace 差异策略
- 决策只依赖 inode + 当前进程 cred

---

## 五、ACL 存储模型

### 1️⃣ 内核部分数据结构

- 每个 inode xattr 存 **ACL ID**，轻量索引
- ACL ID 对应 **规则列表**，列表包含：
  - `priority`（优先级）
  - 主体（user/group/process）
  - 权限 (`r/w/x`)
  - 内容模式 (`plaintext/ciphertext/deny`)
  - 可读路径（用于展示/运维）
  - 可选 hash（增强安全、验证可执行文件）
- 内核访问：
  - 二进制内存结构，高效 pointer 遍历
  - 按 priority 排序，First-match 或 Strict aggregation
  - 支持快速匹配，避免重复规则
- 列表长度上限：**每个 ACL ID 最多 64 条规则**

### 2️⃣ xattr 格式规范

- **xattr key**：`trusted.ecryptfs_acl_id`
- **类型**：`uint16_t`（2字节，大端序）
- **范围**：`0x0001` ~ `0xFFFF`（`0x0000` 保留，表示未分配）
- **分配策略**：单调递增；溢出后从 `0x0001` 起轮询查找未使用的 ID
- **权限要求**：`trusted.*` namespace 需要 `CAP_SYS_ADMIN`
- **最大并发 ACL ID 数**：65535 个

### 3️⃣ 持久化存储

- ACL ID 与规则列表可持久化，重启后恢复
- 格式：
  - JSON 或 protobuf，用于运维可读
  - 内核不直接解析 JSON，启动时加载为内核二进制结构
- 存储方式：
  - 单文件存储所有 ACL ID（中小型部署）
  - 或每 ACL ID 单独文件（大规模/高并发场景）
- 安全与同步：
  - 文件权限严格控制 (`root:root 600`)
  - CRUD 操作通过模块接口，原子更新文件和内核缓存
  - JSON 仅供运维/查看，不直接影响内核匹配
- **一致性保障**：
  - 若 ACL ID 对应规则不存在（文件缺失/损坏）→ 使用默认规则（fallback）并记录审计日志
  - 原子更新中途失败（如断电）→ 下次加载时检测规则文件完整性，降级使用默认规则

---

## 六、规则列表设计

### 1️⃣ 列表结构

- **线性列表 + 优先级字段**
- 可以优化为 **分类索引**（按 user/group/process 分类）
- **列表长度上限：每个 ACL ID 最多 64 条规则**，超出拒绝添加并返回错误

### 2️⃣ 决策模式

| 模式 | 说明 |
|------|------|
| First-match wins + priority | 遍历列表，匹配第一条符合规则立即返回结果 |
| Strict aggregation | 收集所有匹配规则，权限取交集，内容模式取最严格（deny>ciphertext>plaintext） |

- **推荐**：First-match + priority → 简单、可预测、易运维

### 3️⃣ 主体匹配逻辑

主体三个字段（user / group / process）之间为 **AND 关系**：规则匹配当且仅当三个维度**同时满足**。

- `*` 表示该维度不参与过滤，匹配任意值（等同于该维度通配）
- 示例：`process=/usr/bin/vim, user=alice, group=*` 表示：vim 进程 **且** alice 用户 **且** 任意组

### 4️⃣ 重复规则处理

- **完全重复** → 去重
- **部分重复** → 保留，但明确优先级
- 默认规则优先级最低，仅存在一条

---

## 七、继承模型

- 子对象无 ACL → **动态继承**父目录 ACL（每次访问时向上查找，不复制）
- 子对象有 ACL → 使用自身 ACL，忽略父 ACL
- **查找深度**：向上遍历直到 eCryptfs 挂载点根目录为止，不跨越挂载点
- 若直到根目录仍无 ACL → 使用默认规则
- 对新创建的文件和目录同样适用（创建时不自动复制父 ACL）

---

## 八、Namespace 处理

- ACL 基于 **内核真实 UID/GID**
- 不存 user namespace 信息
- 不区分 mount namespace
- 决策只依赖 inode + current->cred

---

## 九、Process 匹配模式

系统支持三种 process 匹配模式：

| 模式 | 匹配依据 | 特性 |
|------|---------|------|
| HASH | 可执行文件 SHA256 | 最严格，防篡改，升级 binary 需更新规则 |
| INODE_AUTO_RESOLVE | dev + inode，自动解析 canonical path | 默认模式，性能高，升级 binary 自动恢复 |
| PATH_ONLY | 路径字符串比较 | 易理解，但受 namespace & mount 影响，仅用于调试或兼容 |

- 规则展示层始终使用可读路径，不显示仅数字 inode

> 注：HASH 模式的 hash 计算时机、INODE_AUTO_RESOLVE 的自动解析触发条件与失败处理，待后续细化。

---

## 十、默认规则（全空规则）

- 三要素全空规则仅存在 **唯一一条**
- 用作 **系统默认策略 fallback**
- 优先级最低，匹配所有未命中的访问请求
- **默认内容模式**：`deny`（安全导向，拒绝所有未明确授权的访问）
- 禁止提升系统权限
- **存储位置**：随 ACL 规则文件一同持久化，作为 ACL ID `0x0000` 的特殊保留条目；每个 eCryptfs 挂载点共享同一份默认规则

---

## 十一、访问决策流程

1. 获取被访问 inode
2. 获取 ACL ID（xattr `trusted.ecryptfs_acl_id`）
3. 若无 ACL → 向上查找父目录，直到挂载点根目录
4. 仍无 ACL → 使用默认规则
5. 获取规则列表
6. 获取当前进程 cred（kuid/kgid）
7. 获取当前进程 executable inode
8. 按匹配模式（HASH / INODE / PATH）匹配规则
   - INODE_AUTO_RESOLVE：若 inode 不匹配，用保存路径重新解析，更新规则缓存后重新匹配
9. 权限计算：`final_permission = system_permission ∩ ACL_permission`
10. 内容模式：ACL 覆盖（`content=ciphertext` 时强制去除 write 权限）
11. First-match 或 aggregation 决策
12. 返回最终访问结果

---

## 十二、持久化要求

- 规则可持久化，重启后仍生效
- ACL ID 与规则表一致
- 不依赖 namespace 或 mount 状态
- 支持自动更新 inode 或 binary
- 启动加载机制、加载失败处理待后续细化

---

## 十三、性能目标

- 高频 open/read/write 场景仍高性能
- 支持内核缓存
- xattr 小而轻量（2字节 ACL ID）
- 列表匹配复杂度可控（最多 64 条线性遍历）

**量化指标（参考）**：

| 指标 | 目标值 | 条件 |
|------|--------|------|
| ACL 决策延迟 | < 1μs（p99） | 热路径，规则数 ≤ 64 |
| 每条规则内存占用 | ≤ 128 字节 | 含主体、权限、内容模式等字段 |
| xattr 大小 | 2 字节 | ACL ID（uint16_t） |
| 最大规则条数/ACL ID | 64 条 | 超出拒绝添加 |

---

## 十四、边界与限制

- 不替代 SELinux
- 不实现全局 LSM
- 不支持 namespace 差异策略
- 不支持多 ACL 叠加
- 不支持复杂父子规则 merge
- PATH_ONLY 模式安全性低，仅用于调试或兼容
- `content=ciphertext` 强制只读，内核层保证，不可通过规则绕过

---

## 十五、审计与运维可读性

- 保存路径用于展示和日志
- ACL 日志显示 human-readable 路径 + dev/ino
- 用户操作/查询界面不直接显示数字 inode

---

## 十六、示例规则（运维可读）

```text
# vim 只读 + 密文访问
priority=100
process=/usr/bin/vim
user=*
group=*
permission=r
content=ciphertext

# grep 可读写明文（alice 且 staff 组）
priority=50
process=/usr/bin/grep
user=alice
group=staff
permission=rw
content=plaintext

# 默认规则（全空，fallback）
priority=0
process=*
user=*
group=*
permission=r
content=deny
```

- First-match wins 按 priority 高到低
- 主体三字段为 AND 关系，`*` 表示该维度通配
- 默认规则仅在前面规则不匹配时生效

---

## 十七、总结设计要点

1. **ACL 列表**：每 inode 对应唯一 ACL ID → 规则列表，上限 64 条
2. **匹配模式**：First-match + priority 或 Strict aggregation
3. **重复规则**：完全重复去重，部分重复保留并明确优先级
4. **默认规则**：仅一条全空规则，content=deny，用作 fallback
5. **权限计算**：最终权限 = 系统权限 ∩ ACL 权限
6. **内容模式**：ACL 覆盖，deny 强制阻止访问，ciphertext 强制只读
7. **继承逻辑**：动态继承，向上查找至挂载点根目录
8. **Process 匹配**：HASH / INODE_AUTO_RESOLVE / PATH_ONLY 可选
9. **主体匹配**：user/group/process 三字段 AND 关系，`*` 为通配

---

## 十八、Page Cache 双模式隔离设计

---

## 18.1 背景与问题来源

标准 eCryptfs 所有通过挂载点的访问均经过解密，Page Cache 仅存储明文数据。为支持第三维度——内容模式（plaintext / ciphertext），系统需要同一文件对不同授权用户呈现不同的数据视图：

- **明文授权用户**：读写解密后的明文（原有行为）
- **密文授权用户**：只读访问原始密文（新增行为）

核心矛盾在于：Linux Page Cache 以 inode 为单位全局共享。同一 inode 只有一个 address_space（缓存位置），所有进程共享同一套缓存页面，无法原生支持同一文件的多视图并发访问。

---

## 18.2 关键概念：address_space

`address_space` 是 Linux 内核中 Page Cache 的管理器，代表一个文件在内存中的缓存位置。其核心组成：

- **i_pages（xarray）**：存储该文件所有缓存页面的索引树
- **a_ops**：定义如何读写页面（readpage / writepage 等）
- **host**：反向指针，指向所属 inode

默认情况下每个 inode 内嵌一个 address_space（`i_data`），`inode->i_mapping` 指向它。打开文件时 VFS 自动设置 `file->f_mapping = inode->i_mapping`。

**关键特性**：`file->f_mapping` 可以被重定向到任意 `address_space` 实例。内核所有读写路径（`generic_file_read_iter` 等）均通过 `file->f_mapping` 操作缓存，而非直接通过 `inode->i_mapping`。这为双 Cache 设计提供了基础。

---

## 18.3 eCryptfs 分层中的 Cache 位置

eCryptfs 是 stackable filesystem，存在两层独立的 address_space：

| 层次 | address_space 归属 | 缓存内容 | 大小 |
|------|-------------------|---------|------|
| Upper（eCryptfs） | `upper inode->i_mapping` | 解密后的明文数据 | 文件逻辑大小 |
| Lower（ext4/xfs） | `lower inode->i_mapping` | 磁盘原始加密数据 | 含 Header 的物理大小 |

原始 eCryptfs 对 address_space 的直接操作极少，主要仅在 inode 创建时设置 `a_ops`，真正的 Cache 管理由 VFS 层（`filemap.c`）完成。eCryptfs 的 `readpage` / `writepage` 只负责加解密逻辑，不直接操作 address_space 结构体本身。

---

## 18.4 双 Cache 设计方案

### 18.4.1 核心思路

为同一 upper inode 创建两个独立的 address_space，通过 `file->f_mapping` 重定向实现不同用户看到不同的数据视图，同时保持 inode 号不变以确保工具兼容性。

结构示意：

```
upper inode（inode 号不变）
  ├── i_mapping  ──→  i_data（明文 address_space）
  │                    ├── i_pages[0] = Page（明文）
  │                    ├── i_pages[1] = Page（明文）
  │                    └── a_ops = ecryptfs_aops_plaintext
  │
  └── ciphertext_mapping（密文 address_space，新增）
                         ├── i_pages[0] = Page（密文）
                         ├── i_pages[1] = Page（密文）
                         └── a_ops = ecryptfs_aops_ciphertext

明文用户：file->f_mapping = inode->i_mapping        （解密读写）
密文用户：file->f_mapping = ciphertext_mapping      （只读密文）
```

### 18.4.2 访问模式约束

| 访问模式 | 读 | 写 | cache 来源 |
|---------|----|----|-----------|
| plaintext（明文授权） | ✅ 解密后明文 | ✅ 加密后写入 | `inode->i_mapping` |
| ciphertext（密文授权） | ✅ 原始密文 | ❌ 拒绝（内核层强制） | `ciphertext_mapping` |
| deny | ❌ 拒绝 | ❌ 拒绝 | — |

密文模式强制只读是简化设计的关键约束，消除了写入路径中所有的 cache 一致性复杂度。

### 18.4.3 数据结构扩展

在 `ecryptfs_inode_info` 中新增字段：

```c
struct ecryptfs_inode_info {
    struct inode        vfs_inode;
    struct inode        *lower_inode;
    struct file         *lower_file;
    struct mutex        lower_file_mutex;

    /* 新增：密文 cache */
    struct address_space  *ciphertext_mapping;   /* NULL = 未初始化 */
    struct mutex           cipher_mapping_mutex; /* 保护初始化竞争 */
};
```

两套 address_space_operations：

```c
/* 明文：原有逻辑不变 */
const struct address_space_operations ecryptfs_aops_plaintext = {
    .readpage    = ecryptfs_readpage,       /* 解密 */
    .writepage   = ecryptfs_writepage,      /* 加密回写 */
    .write_begin = ecryptfs_write_begin,
    .write_end   = ecryptfs_write_end,
};

/* 密文：只读，禁止所有写操作 */
const struct address_space_operations ecryptfs_aops_ciphertext = {
    .readpage    = ecryptfs_readpage_ciphertext,  /* 不解密 */
    /* writepage / write_begin / write_end 均为 NULL，内核层禁止写入 */
};
```

---

## 18.5 Cache 一致性机制

明文用户可写，密文用户只读，两个 cache 之间需要维护一致性。

### 18.5.1 写入时：主动 Invalidate 密文 Cache

在 `write_begin` 时立即使密文 cache 对应页失效，而非等到 `writepage` 回写时。原因：`write_begin` 之后明文 cache 即为最新视图，此刻开始密文 cache 就已过期。

```c
static int ecryptfs_write_begin(..., loff_t pos, ...)
{
    pgoff_t index = pos >> PAGE_SHIFT;

    /* 立即使密文 cache 对应页失效 */
    if (inode_info->ciphertext_mapping)
        invalidate_mapping_pages(
            inode_info->ciphertext_mapping, index, index);

    /* 原有逻辑 */
    return ecryptfs_orig_write_begin(...);
}
```

### 18.5.2 密文读取时：先刷新明文脏页

密文 `readpage` 调用前，强制将明文 cache 中对应位置的脏页回写到 lower file，确保从 lower file 读取到的是最新加密数据。

```c
static int ecryptfs_readpage_ciphertext(struct file *file,
                                        struct page *page)
{
    struct inode *inode = page->mapping->host;
    pgoff_t index = page->index;

    /* 强制刷新明文 cache 对应页的脏数据到 lower file */
    rc = filemap_write_and_wait_range(
             inode->i_mapping,
             (loff_t)index << PAGE_SHIFT,
             ((loff_t)index << PAGE_SHIFT) + PAGE_SIZE - 1);
    if (rc) goto out;

    /* 从 lower file 读取原始密文，不解密 */
    rc = ecryptfs_read_lower_page_segment(
             page, index, 0, PAGE_SIZE, inode);

    if (!rc) SetPageUptodate(page);
out:
    unlock_page(page);
    return rc;
}
```

**关于锁竞争**：`filemap_write_and_wait_range` 操作的是明文 `inode->i_mapping` 中的页面，而当前持有的是密文 `ciphertext_mapping` 中 page[N] 的锁。两个 mapping 的页面是完全独立的内存对象（不同 address_space，不同 page 指针），不存在同一把锁被重复获取的情况，**不会产生死锁**。

### 18.5.3 一致性时序保证

| 时刻 | 事件 | 一致性处理 |
|------|------|-----------|
| T1 | 明文用户写入 page[N] | `write_begin` 立即 invalidate 密文 cache page[N] |
| T2 | 密文用户读取 page[N] | `readpage` 先 flush 明文脏页，再从 lower 读新密文 |
| T3 | 明文脏页异步回写 | `writepage` 加密写入 lower，密文 cache 已在 T1 失效 |
| T4 | 密文用户再次读取 | 从 lower 读取最新密文，cache 命中返回 |

---

## 18.6 密文 Cache 生命周期管理

密文 address_space 在 inode 生命周期内动态创建和销毁，必须在以下节点正确处理。

### 18.6.1 初始化（延迟创建）

`ciphertext_mapping` 在第一次密文模式 open 时才创建（延迟初始化），未被密文访问的文件零额外开销。使用 `cipher_mapping_mutex` 保护并发初始化竞争。

```c
static int ecryptfs_init_ciphertext_mapping(struct inode *inode)
{
    struct ecryptfs_inode_info *inode_info =
        ecryptfs_inode_to_private(inode);
    struct address_space *mapping;

    mapping = kzalloc(sizeof(struct address_space), GFP_KERNEL);
    if (!mapping)
        return -ENOMEM;

    /* 初始化 address_space 内部结构（xarray、锁等） */
    address_space_init_once(mapping);

    /* host 指向同一个 upper inode */
    mapping->host    = inode;
    mapping->a_ops   = &ecryptfs_aops_ciphertext;
    mapping->gfp_mask = GFP_HIGHUSER_MOVABLE;

    inode_info->ciphertext_mapping = mapping;
    return 0;
}
```

### 18.6.2 open 时的处理

```c
static int ecryptfs_open(struct inode *inode, struct file *file)
{
    mode = ecryptfs_acl_get_user_mode(uid, lower_ino);

    if (mode == ECRYPTFS_ACCESS_CIPHERTEXT) {
        /* 拒绝写入模式：内核层强制只读 */
        if (file->f_mode & FMODE_WRITE)
            return -EACCES;

        /* 同时拒绝 O_DIRECT：会绕过 cache 隔离机制 */
        if (file->f_flags & O_DIRECT)
            return -EINVAL;

        /* 延迟初始化 ciphertext_mapping */
        mutex_lock(&inode_info->cipher_mapping_mutex);
        if (!inode_info->ciphertext_mapping)
            rc = ecryptfs_init_ciphertext_mapping(inode);
        mutex_unlock(&inode_info->cipher_mapping_mutex);
        if (rc)
            return rc;

        /* 重定向 file->f_mapping 到密文 cache */
        file->f_mapping = inode_info->ciphertext_mapping;
    }
    return ecryptfs_do_open(inode, file);
}
```

**mmap 写入保障**：密文模式 open 已拒绝 `FMODE_WRITE`，因此后续 `mmap(MAP_SHARED|PROT_WRITE)` 在 VFS 层检查 `file->f_mode` 时会被拒绝，无需在 mmap 路径额外处理。密文用户的只读 mmap（`PROT_READ`）通过 `file->f_mapping` 自动关联到 `ciphertext_mapping`，缺页时调用 `ecryptfs_readpage_ciphertext`，行为正确。

### 18.6.3 truncate 时的处理

明文用户执行 truncate 时，必须同步清理密文 cache，顺序为先密文后明文：

```c
/* 先清理密文 cache，再 truncate 明文 cache */
if (inode_info->ciphertext_mapping)
    truncate_inode_pages(inode_info->ciphertext_mapping, new_length);

truncate_setsize(inode, new_length);   /* 清理明文 cache */
```

### 18.6.4 evict_inode 时的处理（关键）

inode 驱逐时若密文 cache 页面未清理，会导致内核崩溃（页面仍在 LRU 但 inode 已消失）。必须在明文 cache 清理之前完成：

```c
static void ecryptfs_evict_inode(struct inode *inode)
{
    struct ecryptfs_inode_info *inode_info =
        ecryptfs_inode_to_private(inode);

    /* 必须先清理密文 cache 页面，顺序不可颠倒 */
    if (inode_info->ciphertext_mapping)
        truncate_inode_pages_final(inode_info->ciphertext_mapping);

    /* 再清理明文 cache（原有逻辑）*/
    truncate_inode_pages_final(&inode->i_data);
    clear_inode(inode);
}
```

### 18.6.5 destroy_inode 时的处理

```c
static void ecryptfs_destroy_inode(struct inode *inode)
{
    struct ecryptfs_inode_info *inode_info =
        ecryptfs_inode_to_private(inode);

    /* 页面已在 evict_inode 中清理，此处只释放结构体内存 */
    if (inode_info->ciphertext_mapping) {
        kfree(inode_info->ciphertext_mapping);
        inode_info->ciphertext_mapping = NULL;
    }
    /* 原有逻辑 */
    ecryptfs_put_lower_file(inode);
    kmem_cache_free(ecryptfs_inode_info_cache, inode_info);
}
```

---

## 18.7 与其他 Cache 类型的关系

Linux page 通过 `page->mapping` 指针唯一归属于某个 address_space。不同 address_space 是完全独立的命名空间，不存在交叉。

| Cache 类型 | address_space 来源 | 是否与本方案冲突 | 原因 |
|-----------|-------------------|----------------|------|
| Swap Cache | `swapper_spaces[]`（全局独立） | ✅ 不冲突 | 完全不同的 address_space |
| Lower fs Cache | `lower inode->i_mapping` | ✅ 不冲突 | 属于下层 ext4/xfs inode |
| 其他文件 Cache | 各自 `inode->i_mapping` | ✅ 不冲突 | 不同 inode |
| mmap 匿名页 | `anon_vma` 或 NULL | ✅ 不冲突 | mapping 标志位不同 |
| 明文与密文互相 | 同一 inode 两个 mapping | ⚠️ 需主动管理 | 写入时 invalidate 处理 |

Direct I/O（`O_DIRECT`）会绕过 page cache，破坏 cache 隔离机制。密文模式在 open 时拒绝 `O_DIRECT` 标志（返回 `-EINVAL`），从入口处彻底封堵。

---

## 18.8 实现修改点汇总

### 18.8.1 需要修改的现有函数

| 函数 | 文件 | 修改内容 |
|------|------|---------|
| `ecryptfs_open` | file.c | ACL 查询 + 强制只读/O_DIRECT 检查 + 重定向 `file->f_mapping` |
| `ecryptfs_write_begin` | mmap.c | 写入前 invalidate 密文 cache 对应页 |
| `ecryptfs_truncate` | inode.c | 同步清理密文 cache（先密文后明文） |
| `ecryptfs_evict_inode` | super.c | 先清理密文 cache 页面再执行原有逻辑 |
| `ecryptfs_destroy_inode` | super.c | 释放 `ciphertext_mapping` 内存 |
| `ecryptfs_inode_info` | ecryptfs_kernel.h | 新增 `ciphertext_mapping` 和 `cipher_mapping_mutex` 字段 |

### 18.8.2 需要新增的函数

| 函数 | 文件 | 功能 |
|------|------|------|
| `ecryptfs_init_ciphertext_mapping` | inode.c | 延迟初始化密文 address_space，设置 host / a_ops / gfp_mask |
| `ecryptfs_readpage_ciphertext` | mmap.c | 密文读取：先刷明文脏页，再读 lower 不解密 |
| `ecryptfs_aops_ciphertext`（结构体） | mmap.c | 密文模式的 address_space_operations，只含 readpage |

---

## 18.9 性能影响

| 场景 | 性能影响 | 说明 |
|------|---------|------|
| 明文读（无密文访问者） | 零开销 | `ciphertext_mapping` 未初始化，无任何额外操作 |
| 明文写（无密文访问者） | 零开销 | `write_begin` 中 `ciphertext_mapping == NULL` 直接跳过 |
| 明文写（有密文访问者） | 微小开销 | `invalidate_mapping_pages` 一次哈希查找 |
| 密文读（首次） | 一次额外 flush | `filemap_write_and_wait_range` 等待明文脏页回写 |
| 密文读（cache 命中） | 零额外开销 | 直接从 `ciphertext_mapping->i_pages` 返回 |
| 内存占用 | 约 200 字节/文件 | `sizeof(address_space)`，仅被密文访问的文件才分配 |

密文访问是低频的审计/备份场景，首次读取时的 flush 开销可接受。高频路径（明文读写）在无密文访问者时零额外开销。

---

## 18.10 约束与限制

- 密文模式强制只读，open 时携带 `FMODE_WRITE` 将返回 `-EACCES`
- 密文模式拒绝 `O_DIRECT`，open 时携带 `O_DIRECT` 将返回 `-EINVAL`
- 密文 cache 页面永远不产生脏页，内存回收路径安全
- `ciphertext_mapping->host` 指向 upper inode，与 `inode->i_mapping->host` 相同；写路径已在 open 层拦截，不触发 `host->i_mapping` 反查的一致性问题
- mmap 写入由 `FMODE_WRITE` 拒绝在 open 层保障，无需在 mmap 路径额外处理
- 所有修改限定在 eCryptfs 模块内部，不修改 VFS 或其他内核代码

---

## 附：待定项清单

以下问题在当前版本中标记为待定，需后续讨论确认后补充：

| 编号 | 问题 | 影响范围 |
|------|------|---------|
| 问题7 | 继承模型：动态 vs 静态最终确认 | 第七章 |
| 问题9 | INODE_AUTO_RESOLVE 自动解析触发条件与失败处理 | 第九章 |
| 问题10 | HASH 模式：hash 计算时机、内核计算性能、缓存策略 | 第九章 |
| 问题11 | 默认规则存储位置的最终确认 | 第十章 |
| 问题14 | ACL 查询并发处理与锁策略 | 第十一章 |
| 问题15 | 启动加载机制：触发方式、加载失败处理 | 第十二章 |
| 缺失-管理接口 | ioctl/netlink/sysfs 接口形式、命令格式、权限要求 | 新章节 |
| 缺失-热更新 | 运行时 ACL 修改对已打开文件的影响与处理策略 | 新章节 |
| 缺失-错误处理 | 各模块错误码定义、传播路径、用户可见错误信息 | 新章节 |
| 缺失-日志格式 | 审计日志格式、级别、输出位置 | 第十五章 |

---

*v6.0 更新说明：补充 Content Mode 语义说明（问题1/2）、xattr 格式规范（问题3）、Subject AND 匹配逻辑（问题5）、规则上限 64 条（问题6）、动态继承与查找深度（问题8）、默认规则语义修正（问题12）、性能量化指标（问题13）、Cache 章节补充初始化代码/死锁说明/mmap 保障链条/O_DIRECT 拦截（问题17/18/19）。待定项见附录。*