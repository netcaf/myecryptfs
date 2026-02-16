# 定制 eCryptfs 内部访问控制系统需求设计（v4.0）

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

- `plaintext`（明文）  
- `ciphertext`（密文）  
- `deny`（拒绝）  

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
- 列表长度可控，确保高频访问场景性能

### 2️⃣ 持久化存储

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

---

## 六、规则列表设计

### 1️⃣ 列表结构

- **线性列表 + 优先级字段**  
- 可以优化为 **分类索引**（按 user/group/process 分类）  
- 列表长度受限，高性能场景保证快速匹配

### 2️⃣ 决策模式

| 模式 | 说明 |
|------|------|
| First-match wins + priority | 遍历列表，匹配第一条符合规则立即返回结果 |
| Strict aggregation | 收集所有匹配规则，权限取交集，内容模式取最严格（deny>ciphertext>plaintext） |

- **推荐**：First-match + priority → 简单、可预测、易运维

### 3️⃣ 重复规则处理

- **完全重复** → 去重  
- **部分重复** → 保留，但明确优先级  
- 默认规则优先级最低，仅存在一条

---

## 七、继承模型

- 子对象无 ACL → 继承父目录 ACL  
- 子对象有 ACL → 使用自身 ACL，忽略父 ACL  
- 简化逻辑，提高性能
- 对新文件和新目录影响

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

---

## 十、默认规则（全空规则）

- 三要素全空规则仅存在 **唯一一条**  
- 用作 **系统默认策略 fallback**  
- 优先级最低，匹配所有未命中的访问请求  
- 安全性：
  - 默认黑名单（deny / ciphertext / r）  
  - 禁止提升系统权限  

---

## 十一、访问决策流程

1. 获取被访问 inode  
2. 获取 ACL ID（xattr）  
3. 若无 ACL → 查父目录  
4. 获取规则列表  
5. 获取当前进程 cred（kuid/kgid）  
6. 获取当前进程 executable inode  
7. 按匹配模式（HASH / INODE / PATH）匹配规则  
8. 权限计算：`final_permission = system_permission ∩ ACL_permission`  
9. 内容模式：ACL 覆盖  
10. First-match 或 aggregation 决策  
11. 返回最终访问结果  
12. INODE_AUTO_RESOLVE：如 inode 不匹配，可用保存路径解析更新规则

---

## 十二、持久化要求

- 规则可持久化，重启后仍生效  
- ACL ID 与规则表一致  
- 不依赖 namespace 或 mount 状态  
- 支持自动更新 inode 或 binary

---

## 十三、性能目标

- 高频 open/read/write 场景仍高性能  
- 支持内核缓存  
- xattr 小而轻量  
- 列表匹配复杂度可控

---

## 十四、边界与限制

- 不替代 SELinux  
- 不实现全局 LSM  
- 不支持 namespace 差异策略  
- 不支持多 ACL 叠加  
- 不支持复杂父子规则 merge  
- PATH_ONLY 模式安全性低，仅用于调试或兼容

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

# grep 可读写明文
priority=50
process=/usr/bin/grep
user=alice
group=staff
permission=rw
content=plaintext

# 默认规则（全空）
priority=0
process=*
user=*
group=*
permission=r
content=ciphertext
```

- First-match wins 按 priority 高到低  
- 默认规则仅在前面规则不匹配时生效  

---

## 十七、总结设计要点

1. **ACL 列表**：每 inode 对应唯一 ACL ID → 规则列表  
2. **匹配模式**：First-match + priority 或 Strict aggregation  
3. **重复规则**：完全重复去重，部分重复保留并明确优先级  
4. **默认规则**：仅一条全空规则，用作 fallback  
5. **权限计算**：最终权限 = 系统权限 ∩ ACL 权限  
6. **内容模式**：ACL 覆盖，deny 强制阻止访问  
7. **继承逻辑**：子对象无 ACL → 继承父目录 ACL  
8. **Process 匹配**：HASH / INODE_AUTO_RESOLVE / PATH_ONLY 可选  

---

该版本整合了 **权限冲突处理、默认规则、ACL 列表设计、继承、namespace 兼容性、process 匹配模式** 等讨论结果，可作为实现和运维参考。
