# Custom eCryptfs Internal Access Control System — Requirements & Design (v6.0)

---

## 1. Overall Goals

Design an access control system for use **exclusively inside a custom eCryptfs kernel module**, with the following characteristics:

- **Inode-centric (object-centric)** access control
- Rule **persistence** — rules survive reboot
- Directory inheritance support
- High performance, suitable for high-frequency read/write/open workloads
- **Namespace-independent** access decisions
- Kernel-level implementation — no dependency on external LSM frameworks
- Human-readable rule display — avoid cryptic numeric-only representations
- ACL decisions act as the **final enforcement layer** applied after native system permission checks

---

## 2. Access Decision Model

An access decision has three dimensions:

```
Subject
+
Permission (r/w/x)
+
Content Mode (plaintext / ciphertext / deny)
=
Access Result
```

- **Permission**: final permission = **system permission ∩ ACL permission**
- **Content mode**: determined by the ACL rule (plaintext / ciphertext / deny)
- **deny** has the highest precedence and blocks access immediately

> Example: vim with read-only ciphertext access — even if the underlying file is writable, the final access is read-only and returns raw ciphertext.

**Constraint**: When `content=ciphertext`, write permission is automatically voided. Even if the ACL rule declares `permission=rw`, the effective permission is `r` only. This is enforced at the kernel level by the ciphertext cache isolation mechanism, independent of whether the rule is correctly configured.

---

## 3. Rule Dimensions

### 1️⃣ Subject

Any combination of the following is supported:

- **user**: kernel real UID (`kuid`)
- **group**: kernel real GID (`kgid`)
- **process**: executable file inode

**Notes**:

- Paths are used only for rule definition and display purposes
- Independent of namespace and mount context
- Container-friendly

---

### 2️⃣ File Operation Permission

- `r` — read
- `w` — write
- `x` — execute

**Conflict resolution**:

- The ACL **cannot elevate system permissions**
- Final permission = system permission ∩ ACL permission

---

### 3️⃣ Content Mode

Defines the **access outcome** for the given subject on the given file. The three modes are mutually exclusive; the `content` field in a rule takes exactly one value:

- `plaintext` — access allowed, returns decrypted plaintext
- `ciphertext` — access allowed, returns raw ciphertext (**forced read-only**, see §2 constraint)
- `deny` — access refused; no data is returned

> The ACL content mode overrides the system's native content mode. `deny` unconditionally blocks access.

---

## 4. Object-Centric Model

- Rules apply to the **accessed object's inode**
- No global policy or per-namespace policy differentiation
- Decisions depend only on the inode and the calling process's credentials (`current->cred`)

---

## 5. ACL Storage Model

### 1️⃣ Kernel Data Structures

- Each inode's xattr stores an **ACL ID** — a lightweight index
- The ACL ID maps to a **rule list** containing:
  - `priority`
  - Subject (user / group / process)
  - Permission (`r/w/x`)
  - Content mode (`plaintext/ciphertext/deny`)
  - Human-readable path (for display and operational use)
  - Optional hash (for stronger security / executable verification)
- Kernel access:
  - Binary in-memory structures, efficient pointer traversal
  - Sorted by priority; first-match or strict aggregation
  - Fast matching with duplicate-rule suppression
- Rule list cap: **maximum 64 rules per ACL ID**

### 2️⃣ xattr Format Specification

- **xattr key**: `trusted.ecryptfs_acl_id`
- **Type**: `uint16_t` (2 bytes, big-endian)
- **Range**: `0x0001` – `0xFFFF` (`0x0000` reserved, meaning "no ACL assigned")
- **Allocation policy**: monotonically increasing; on overflow, scan from `0x0001` for the first unused ID
- **Permission requirement**: `trusted.*` namespace requires `CAP_SYS_ADMIN`
- **Maximum concurrent ACL IDs**: 65,535

### 3️⃣ Persistent Storage

- ACL IDs and rule lists can be persisted and restored after reboot
- Format:
  - JSON or protobuf for operational readability
  - The kernel does not parse JSON directly; rules are loaded into kernel binary structures at startup
- Storage layout:
  - Single file for all ACL IDs (small/medium deployments)
  - Or one file per ACL ID (large-scale / high-concurrency scenarios)
- Security and synchronization:
  - File permissions strictly controlled (`root:root 600`)
  - CRUD operations go through the module interface with atomic updates to both the file and the kernel cache
  - JSON is for operational/audit use only and does not directly affect kernel matching
- **Consistency guarantees**:
  - If the rule list for an ACL ID is missing or corrupted → apply default rule (fallback) and record an audit log entry
  - If an atomic update is interrupted (e.g., power failure) → on next load, check rule file integrity and downgrade to default rule

---

## 6. Rule List Design

### 1️⃣ List Structure

- **Linear list with a priority field**
- Can be optimized to a **classified index** (organized by user/group/process)
- **Cap: maximum 64 rules per ACL ID**; additions beyond this limit are rejected with an error

### 2️⃣ Decision Modes

| Mode | Description |
|------|-------------|
| First-match wins + priority | Traverse the list; return the result of the first matching rule immediately |
| Strict aggregation | Collect all matching rules; intersect permissions; take the strictest content mode (deny > ciphertext > plaintext) |

- **Recommended**: First-match + priority — simple, predictable, operationally straightforward

### 3️⃣ Subject Matching Logic

The three subject fields (user / group / process) are combined with **AND logic**: a rule matches only when **all three dimensions are simultaneously satisfied**.

- `*` means the dimension is not filtered — matches any value (wildcard for that dimension)
- Example: `process=/usr/bin/vim, user=alice, group=*` means: vim process **AND** user alice **AND** any group

### 4️⃣ Duplicate Rule Handling

- **Exact duplicates** → deduplicated
- **Partial duplicates** → retained, with explicit priority ordering
- The default rule has the lowest priority; only one default rule exists

---

## 7. Inheritance Model

- If a child object has no ACL → **dynamically inherit** the parent directory's ACL (resolved on each access by walking up; not copied)
- If a child object has its own ACL → use that ACL; the parent ACL is ignored
- **Traversal depth**: walk upward until the eCryptfs mount root; do not cross mount boundaries
- If no ACL is found all the way to the root → apply the default rule
- Applies to newly created files and directories as well (parent ACL is not automatically copied at creation time)

---

## 8. Namespace Handling

- ACL decisions are based on **kernel real UID/GID**
- User namespace information is not stored
- Mount namespace differences are not considered
- Decisions depend only on `inode` + `current->cred`

---

## 9. Process Matching Modes

Three process matching modes are supported:

| Mode | Matching Basis | Characteristics |
|------|----------------|-----------------|
| HASH | SHA-256 of executable binary | Strictest; tamper-resistant; rule must be updated when the binary is upgraded |
| INODE_AUTO_RESOLVE | dev + inode number, resolved from canonical path | Default mode; high performance; automatically recovers when binary is upgraded |
| PATH_ONLY | Path string comparison | Easy to understand; affected by namespace and mount context; for debugging or compatibility only |

- The rule display layer always uses human-readable paths; raw inode numbers are not shown to users

> Note: The timing of hash computation in HASH mode, and the auto-resolve trigger conditions and failure handling in INODE_AUTO_RESOLVE mode, are pending further specification.

---

## 10. Default Rule (Catch-All Fallback)

- There is exactly **one** default rule (all subject fields are wildcards)
- Used as the **system-wide fallback policy**
- Has the lowest priority; matches all accesses not caught by any explicit rule
- **Default content mode**: `deny` (security-first; reject all access not explicitly authorized)
- Cannot elevate system permissions
- **Storage**: persisted alongside ACL rule files as a special reserved entry for ACL ID `0x0000`; shared by all eCryptfs mount points

---

## 11. Access Decision Flow

1. Obtain the accessed inode
2. Read the ACL ID from xattr (`trusted.ecryptfs_acl_id`)
3. If no ACL → walk up to parent directories until the eCryptfs mount root
4. If still no ACL → apply the default rule
5. Retrieve the rule list
6. Obtain the calling process's credentials (`kuid` / `kgid`)
7. Obtain the calling process's executable inode
8. Match rules according to the configured process matching mode (HASH / INODE_AUTO_RESOLVE / PATH_ONLY)
   - INODE_AUTO_RESOLVE: if the stored inode does not match, re-resolve using the saved path, update the rule cache, and re-match
9. Permission calculation: `final_permission = system_permission ∩ ACL_permission`
10. Content mode: ACL overrides the native mode; `content=ciphertext` forces removal of write permission
11. Apply first-match or aggregation decision
12. Return the final access result

---

## 12. Persistence Requirements

- Rules can be persisted and remain effective after reboot
- ACL IDs and rule tables are kept consistent
- No dependency on namespace or mount state
- Supports automatic inode or binary re-resolution
- Startup loading mechanism and load-failure handling are pending further specification

---

## 13. Performance Goals

- High performance maintained under high-frequency open/read/write workloads
- Kernel caching supported
- xattr is small and lightweight (2-byte ACL ID)
- Rule matching complexity is bounded (linear scan, maximum 64 rules)

**Quantitative targets (reference)**:

| Metric | Target | Conditions |
|--------|--------|------------|
| ACL decision latency | < 1 µs (p99) | Hot path, rule count ≤ 64 |
| Memory per rule | ≤ 128 bytes | Includes subject, permission, content mode fields |
| xattr size | 2 bytes | ACL ID (`uint16_t`) |
| Max rules per ACL ID | 64 | Additions beyond this are rejected |

---

## 14. Boundaries and Limitations

- Does not replace SELinux
- Does not implement a global LSM
- Does not support per-namespace differentiated policies
- Does not support stacking multiple ACLs on one inode
- Does not support complex parent–child rule merging
- PATH_ONLY mode has lower security; for debugging or compatibility use only
- `content=ciphertext` forces read-only; enforced at the kernel level and cannot be bypassed by rule configuration

---

## 15. Audit and Operational Readability

- Paths are saved for display and logging purposes
- ACL log entries show human-readable paths alongside dev/ino numbers
- User-facing management and query interfaces do not display raw inode numbers

---

## 16. Example Rules (Operational Format)

```text
# vim: read-only access returning ciphertext
priority=100
process=/usr/bin/vim
user=*
group=*
permission=r
content=ciphertext

# grep: read-write plaintext access (alice in staff group)
priority=50
process=/usr/bin/grep
user=alice
group=staff
permission=rw
content=plaintext

# Default rule (catch-all fallback)
priority=0
process=*
user=*
group=*
permission=r
content=deny
```

- First-match wins, evaluated from highest to lowest priority
- Subject fields are ANDed; `*` is a wildcard for that dimension
- The default rule applies only when no preceding rule matches

---

## 17. Design Summary

1. **ACL list**: each inode maps to a unique ACL ID → rule list; capped at 64 rules
2. **Matching mode**: First-match + priority or strict aggregation
3. **Duplicate rules**: exact duplicates are deduplicated; partial duplicates are retained with explicit priority
4. **Default rule**: exactly one catch-all rule; `content=deny`; used as fallback
5. **Permission calculation**: final permission = system permission ∩ ACL permission
6. **Content mode**: ACL overrides native; `deny` unconditionally blocks access; `ciphertext` forces read-only
7. **Inheritance logic**: dynamic inheritance; walk upward to the eCryptfs mount root
8. **Process matching**: HASH / INODE_AUTO_RESOLVE / PATH_ONLY (selectable)
9. **Subject matching**: user/group/process AND logic; `*` is a wildcard

---

## 18. Page Cache Dual-Mode Isolation Design

---

## 18.1 Background and Problem Statement

Standard eCryptfs decrypts all accesses through the mount point; the Page Cache stores only plaintext data. To support the third dimension — content mode (plaintext / ciphertext) — the system must present different data views of the same file to different authorized processes:

- **Plaintext-authorized users**: read and write decrypted plaintext (existing behavior)
- **Ciphertext-authorized users**: read-only access to raw ciphertext (new behavior)

The core challenge is that the Linux Page Cache is globally shared per inode. A single inode has only one `address_space` (cache location) shared by all processes, with no native support for concurrent multi-view access to the same file.

---

## 18.2 Key Concept: address_space

`address_space` is the Linux kernel's Page Cache manager, representing a file's in-memory cache location. Core components:

- **i_pages (xarray)**: index tree of all cached pages for the file
- **a_ops**: defines how pages are read and written (`readpage` / `writepage`, etc.)
- **host**: back-pointer to the owning inode

By default each inode embeds one `address_space` (`i_data`), and `inode->i_mapping` points to it. When a file is opened, the VFS automatically sets `file->f_mapping = inode->i_mapping`.

**Key property**: `file->f_mapping` can be redirected to any `address_space` instance. All kernel read/write paths (`generic_file_read_iter`, etc.) operate through `file->f_mapping`, not directly through `inode->i_mapping`. This is the foundation of the dual-cache design.

---

## 18.3 Cache Locations in the eCryptfs Stack

eCryptfs is a stackable filesystem with two independent `address_space` layers:

| Layer | address_space Owner | Cached Content | Size |
|-------|---------------------|----------------|------|
| Upper (eCryptfs) | `upper inode->i_mapping` | Decrypted plaintext | Logical file size |
| Lower (ext4/xfs) | `lower inode->i_mapping` | Raw encrypted data on disk | Physical size including header |

The original eCryptfs rarely operates directly on `address_space` structures — it primarily sets `a_ops` at inode creation time, while the actual cache management is done by the VFS layer (`filemap.c`). eCryptfs's `readpage` / `writepage` handle only the encryption/decryption logic and do not manipulate the `address_space` structure itself.

---

## 18.4 Dual Cache Design

### 18.4.1 Core Approach

Create two independent `address_space` instances for the same upper inode. By redirecting `file->f_mapping`, different processes see different data views while the inode number remains unchanged, ensuring tool compatibility.

Structure diagram:

```
upper inode (inode number unchanged)
  ├── i_mapping  ──→  i_data (plaintext address_space)
  │                    ├── i_pages[0] = Page (plaintext)
  │                    ├── i_pages[1] = Page (plaintext)
  │                    └── a_ops = ecryptfs_aops_plaintext
  │
  └── ciphertext_mapping (ciphertext address_space, new)
                         ├── i_pages[0] = Page (ciphertext)
                         ├── i_pages[1] = Page (ciphertext)
                         └── a_ops = ecryptfs_aops_ciphertext

Plaintext user:   file->f_mapping = inode->i_mapping      (decrypt on read/write)
Ciphertext user:  file->f_mapping = ciphertext_mapping    (read-only raw ciphertext)
```

### 18.4.2 Access Mode Constraints

| Access Mode | Read | Write | Cache Source |
|-------------|------|-------|--------------|
| plaintext (plaintext-authorized) | ✅ Decrypted plaintext | ✅ Encrypted on write | `inode->i_mapping` |
| ciphertext (ciphertext-authorized) | ✅ Raw ciphertext | ❌ Rejected (kernel-enforced) | `ciphertext_mapping` |
| deny | ❌ Rejected | ❌ Rejected | — |

Forcing ciphertext mode to be read-only is the key design constraint that eliminates all cache-consistency complexity on the write path.

### 18.4.3 Data Structure Extensions

New fields added to `ecryptfs_inode_info`:

```c
struct ecryptfs_inode_info {
    struct inode        vfs_inode;
    struct inode        *lower_inode;
    struct file         *lower_file;
    struct mutex        lower_file_mutex;

    /* New: ciphertext cache */
    struct address_space  *ciphertext_mapping;   /* NULL = not yet initialized */
    struct mutex           cipher_mapping_mutex; /* protects initialization race */
};
```

Two sets of `address_space_operations`:

```c
/* Plaintext: existing logic unchanged */
const struct address_space_operations ecryptfs_aops_plaintext = {
    .readpage    = ecryptfs_readpage,       /* decrypt on read */
    .writepage   = ecryptfs_writepage,      /* encrypt on writeback */
    .write_begin = ecryptfs_write_begin,
    .write_end   = ecryptfs_write_end,
};

/* Ciphertext: read-only; all write operations NULL (kernel-level prohibition) */
const struct address_space_operations ecryptfs_aops_ciphertext = {
    .readpage    = ecryptfs_readpage_ciphertext,  /* no decryption */
    /* writepage / write_begin / write_end are NULL — writes prohibited */
};
```

---

## 18.5 Cache Consistency Mechanism

Plaintext users can write; ciphertext users are read-only. Consistency between the two caches must be maintained.

### 18.5.1 On Write: Proactively Invalidate the Ciphertext Cache

In `write_begin`, immediately invalidate the corresponding ciphertext cache page — do not wait until `writepage` writeback. Reason: after `write_begin`, the plaintext cache becomes the authoritative view, and the ciphertext cache is already stale from that moment.

```c
static int ecryptfs_write_begin(..., loff_t pos, ...)
{
    pgoff_t index = pos >> PAGE_SHIFT;

    /* Immediately invalidate the corresponding ciphertext cache page */
    if (inode_info->ciphertext_mapping)
        invalidate_mapping_pages(
            inode_info->ciphertext_mapping, index, index);

    /* Original logic */
    return ecryptfs_orig_write_begin(...);
}
```

### 18.5.2 On Ciphertext Read: Flush Plaintext Dirty Pages First

Before the ciphertext `readpage` is called, force-flush any dirty pages at the corresponding offset from the plaintext cache to the lower file, ensuring that the latest encrypted data is read from the lower file.

```c
static int ecryptfs_readpage_ciphertext(struct file *file,
                                        struct page *page)
{
    struct inode *inode = page->mapping->host;
    pgoff_t index = page->index;

    /* Force-flush dirty plaintext cache page to lower file */
    rc = filemap_write_and_wait_range(
             inode->i_mapping,
             (loff_t)index << PAGE_SHIFT,
             ((loff_t)index << PAGE_SHIFT) + PAGE_SIZE - 1);
    if (rc) goto out;

    /* Read raw ciphertext from lower file without decryption */
    rc = ecryptfs_read_lower_page_segment(
             page, index, 0, PAGE_SIZE, inode);

    if (!rc) SetPageUptodate(page);
out:
    unlock_page(page);
    return rc;
}
```

**Regarding lock contention**: `filemap_write_and_wait_range` operates on pages in the plaintext `inode->i_mapping`, while the current call holds the lock on page[N] in the ciphertext `ciphertext_mapping`. These two mappings contain completely independent memory objects (different `address_space` instances, different page pointers) — the same lock is never held twice, and **no deadlock can occur**.

### 18.5.3 Consistency Timeline

| Time | Event | Consistency Action |
|------|-------|--------------------|
| T1 | Plaintext user writes page[N] | `write_begin` immediately invalidates ciphertext cache page[N] |
| T2 | Ciphertext user reads page[N] | `readpage` flushes plaintext dirty page, then reads fresh ciphertext from lower |
| T3 | Plaintext dirty page asynchronously written back | `writepage` encrypts and writes to lower; ciphertext cache already invalidated at T1 |
| T4 | Ciphertext user reads again | Reads latest ciphertext from lower; cache hit on subsequent accesses |

---

## 18.6 Ciphertext Cache Lifecycle Management

The ciphertext `address_space` is dynamically created and destroyed within the inode lifecycle. It must be handled correctly at each of the following points.

### 18.6.1 Initialization (Lazy Creation)

`ciphertext_mapping` is created only on the first ciphertext-mode `open` (lazy initialization). Files never accessed in ciphertext mode incur zero additional overhead. `cipher_mapping_mutex` protects against concurrent initialization races.

```c
static int ecryptfs_init_ciphertext_mapping(struct inode *inode)
{
    struct ecryptfs_inode_info *inode_info =
        ecryptfs_inode_to_private(inode);
    struct address_space *mapping;

    mapping = kzalloc(sizeof(struct address_space), GFP_KERNEL);
    if (!mapping)
        return -ENOMEM;

    /* Initialize address_space internal structures (xarray, locks, etc.) */
    address_space_init_once(mapping);

    /* host points to the same upper inode */
    mapping->host    = inode;
    mapping->a_ops   = &ecryptfs_aops_ciphertext;
    mapping->gfp_mask = GFP_HIGHUSER_MOVABLE;

    inode_info->ciphertext_mapping = mapping;
    return 0;
}
```

### 18.6.2 Handling at open Time

```c
static int ecryptfs_open(struct inode *inode, struct file *file)
{
    mode = ecryptfs_acl_get_user_mode(uid, lower_ino);

    if (mode == ECRYPTFS_ACCESS_CIPHERTEXT) {
        /* Reject write mode: kernel-level enforcement of read-only */
        if (file->f_mode & FMODE_WRITE)
            return -EACCES;

        /* Also reject O_DIRECT: would bypass the cache isolation mechanism */
        if (file->f_flags & O_DIRECT)
            return -EINVAL;

        /* Lazy initialize ciphertext_mapping */
        mutex_lock(&inode_info->cipher_mapping_mutex);
        if (!inode_info->ciphertext_mapping)
            rc = ecryptfs_init_ciphertext_mapping(inode);
        mutex_unlock(&inode_info->cipher_mapping_mutex);
        if (rc)
            return rc;

        /* Redirect file->f_mapping to the ciphertext cache */
        file->f_mapping = inode_info->ciphertext_mapping;
    }
    return ecryptfs_do_open(inode, file);
}
```

**mmap write protection**: ciphertext-mode `open` rejects `FMODE_WRITE`, so any subsequent `mmap(MAP_SHARED|PROT_WRITE)` is rejected by the VFS when it checks `file->f_mode` — no additional handling is needed in the mmap path. A read-only mmap (`PROT_READ`) from a ciphertext user is automatically associated with `ciphertext_mapping` via `file->f_mapping`; page faults call `ecryptfs_readpage_ciphertext`, which behaves correctly.

### 18.6.3 Handling at truncate Time

When a plaintext user performs a truncate, the ciphertext cache must be cleaned up synchronously — ciphertext cache first, then plaintext:

```c
/* Clean up ciphertext cache first, then truncate plaintext cache */
if (inode_info->ciphertext_mapping)
    truncate_inode_pages(inode_info->ciphertext_mapping, new_length);

truncate_setsize(inode, new_length);   /* clean up plaintext cache */
```

### 18.6.4 Handling at evict_inode Time (Critical)

If ciphertext cache pages are not cleaned up before the inode is evicted, a kernel crash results (pages still on LRU but inode has been freed). This must be done before the plaintext cache is cleaned up:

```c
static void ecryptfs_evict_inode(struct inode *inode)
{
    struct ecryptfs_inode_info *inode_info =
        ecryptfs_inode_to_private(inode);

    /* Must clean ciphertext cache pages first — order is critical */
    if (inode_info->ciphertext_mapping)
        truncate_inode_pages_final(inode_info->ciphertext_mapping);

    /* Then clean plaintext cache (original logic) */
    truncate_inode_pages_final(&inode->i_data);
    clear_inode(inode);
}
```

### 18.6.5 Handling at destroy_inode Time

```c
static void ecryptfs_destroy_inode(struct inode *inode)
{
    struct ecryptfs_inode_info *inode_info =
        ecryptfs_inode_to_private(inode);

    /* Pages already purged in evict_inode; only free the struct here */
    if (inode_info->ciphertext_mapping) {
        kfree(inode_info->ciphertext_mapping);
        inode_info->ciphertext_mapping = NULL;
    }
    /* Original logic */
    ecryptfs_put_lower_file(inode);
    kmem_cache_free(ecryptfs_inode_info_cache, inode_info);
}
```

---

## 18.7 Relationship to Other Cache Types

A Linux page is uniquely owned by exactly one `address_space` via its `page->mapping` pointer. Different `address_space` instances are fully independent namespaces with no cross-contamination.

| Cache Type | address_space Owner | Conflict with This Design? | Reason |
|------------|---------------------|---------------------------|--------|
| Swap Cache | `swapper_spaces[]` (globally independent) | ✅ No conflict | Completely separate address_space |
| Lower fs Cache | `lower inode->i_mapping` | ✅ No conflict | Belongs to the lower ext4/xfs inode |
| Other file caches | Each file's `inode->i_mapping` | ✅ No conflict | Different inodes |
| mmap anonymous pages | `anon_vma` or NULL | ✅ No conflict | Different mapping flag |
| Plaintext vs. ciphertext (same inode) | Two mappings on one inode | ⚠️ Requires active management | Invalidation on write |

Direct I/O (`O_DIRECT`) bypasses the page cache and would break the cache isolation mechanism. Ciphertext mode rejects the `O_DIRECT` flag at `open` time (returns `-EINVAL`), blocking it completely at the entry point.

---

## 18.8 Implementation Change Summary

### 18.8.1 Existing Functions to Modify

| Function | File | Change |
|----------|------|--------|
| `ecryptfs_open` | file.c | ACL query + forced read-only / O_DIRECT check + redirect `file->f_mapping` |
| `ecryptfs_write_begin` | mmap.c | Invalidate corresponding ciphertext cache page before write |
| `ecryptfs_truncate` | inode.c | Synchronously clean ciphertext cache (ciphertext first, then plaintext) |
| `ecryptfs_evict_inode` | super.c | Clean ciphertext cache pages before executing original logic |
| `ecryptfs_destroy_inode` | super.c | Free `ciphertext_mapping` memory |
| `ecryptfs_inode_info` | ecryptfs_kernel.h | Add `ciphertext_mapping` and `cipher_mapping_mutex` fields |

### 18.8.2 New Functions to Add

| Function | File | Purpose |
|----------|------|---------|
| `ecryptfs_init_ciphertext_mapping` | inode.c | Lazily initialize ciphertext address_space; set host / a_ops / gfp_mask |
| `ecryptfs_readpage_ciphertext` | mmap.c | Ciphertext read: flush plaintext dirty pages, then read from lower without decryption |
| `ecryptfs_aops_ciphertext` (struct) | mmap.c | address_space_operations for ciphertext mode; contains only readpage |

---

## 18.9 Performance Impact

| Scenario | Performance Impact | Notes |
|----------|--------------------|-------|
| Plaintext read (no ciphertext readers) | Zero overhead | `ciphertext_mapping` is NULL; no extra work |
| Plaintext write (no ciphertext readers) | Zero overhead | `write_begin` skips the NULL-check immediately |
| Plaintext write (with ciphertext readers) | Minimal overhead | One `invalidate_mapping_pages` hash lookup |
| Ciphertext read (first access) | One extra flush | `filemap_write_and_wait_range` waits for plaintext dirty writeback |
| Ciphertext read (cache hit) | Zero extra overhead | Served directly from `ciphertext_mapping->i_pages` |
| Memory usage | ~200 bytes / file | `sizeof(address_space)`; allocated only for files with ciphertext access |

Ciphertext access is a low-frequency audit/backup scenario; the flush overhead on the first read is acceptable. The high-frequency path (plaintext read/write with no ciphertext readers) has zero extra overhead.

---

## 18.10 Constraints and Safeguards

- Ciphertext mode is forced read-only; opening with `FMODE_WRITE` returns `-EACCES`
- Ciphertext mode rejects `O_DIRECT`; opening with `O_DIRECT` returns `-EINVAL`
- Ciphertext cache pages never become dirty; memory reclaim paths are safe
- `ciphertext_mapping->host` points to the upper inode, same as `inode->i_mapping->host`; write paths are blocked at the `open` layer, so `host->i_mapping` reverse-lookup consistency issues cannot arise
- mmap write protection is guaranteed at the `open` layer via `FMODE_WRITE` rejection; no extra handling needed in the mmap path
- All changes are confined to the eCryptfs module; no VFS or other kernel code is modified

---

## Appendix: Open Items

The following issues are marked as pending in this version and require further discussion before resolution:

| ID | Issue | Scope |
|----|-------|-------|
| 7 | Inheritance model: final decision between dynamic vs. static | §7 |
| 9 | INODE_AUTO_RESOLVE: auto-resolve trigger conditions and failure handling | §9 |
| 10 | HASH mode: hash computation timing, kernel computation performance, caching strategy | §9 |
| 11 | Default rule storage location: final confirmation | §10 |
| 14 | ACL lookup concurrency handling and locking strategy | §11 |
| 15 | Startup loading mechanism: trigger method and load-failure handling | §12 |
| Missing — Management Interface | ioctl/netlink/sysfs interface form, command format, permission requirements | New section |
| Missing — Hot Update | Impact of runtime ACL modifications on already-open files, and handling strategy | New section |
| Missing — Error Handling | Error code definitions per module, propagation paths, user-visible error messages | New section |
| Missing — Log Format | Audit log format, severity levels, output location | §15 |

---

*v6.0 update notes: added Content Mode semantics (issues 1/2), xattr format specification (issue 3), Subject AND matching logic (issue 5), 64-rule cap (issue 6), dynamic inheritance and traversal depth (issue 8), default rule semantics correction (issue 12), performance quantitative targets (issue 13), cache section additions covering initialization code / deadlock analysis / mmap protection chain / O_DIRECT blocking (issues 17/18/19). Open items listed in appendix.*
