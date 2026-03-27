---
marp: true
theme: gaia
class: lead
paginate: true
backgroundColor: #1a1a2e
color: #eaeaea
style: |
  section {
    font-family: 'Segoe UI', 'Helvetica Neue', sans-serif;
    font-size: 1.1rem;
  }
  section.lead h1 {
    font-size: 2.2rem;
    color: #00d4ff;
  }
  section.lead h3 {
    color: #a0c4ff;
    font-weight: 300;
  }
  h2 {
    color: #00d4ff;
    border-bottom: 2px solid #00d4ff33;
    padding-bottom: 0.2em;
  }
  table {
    font-size: 0.85rem;
    width: 100%;
  }
  th {
    background: #00d4ff22;
    color: #00d4ff;
  }
  code {
    background: #ffffff15;
    color: #ffd166;
    padding: 0.1em 0.4em;
    border-radius: 4px;
  }
  pre code {
    background: transparent;
    color: #a8ff78;
    font-size: 0.8rem;
  }
  pre {
    background: #0d0d1a;
    border-left: 4px solid #00d4ff;
    padding: 1em;
  }
  .columns {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5em;
  }
  footer {
    color: #555577;
    font-size: 0.7rem;
  }
  section.divider {
    background: #0d0d1a;
    justify-content: center;
    align-items: center;
  }
  section.divider h1 {
    color: #00d4ff;
    font-size: 2.5rem;
    border-left: 6px solid #00d4ff;
    padding-left: 0.5em;
  }
---

<!-- _class: lead -->
<!-- _paginate: false -->

# eCryptfs Custom ACL
### Kernel-Level Access Control Implementation

<br>

**Linux 5.15 · Out-of-tree Module · Kernel C**

---
<!-- _class: divider -->

# 01
# Background & Objective

---
<!-- footer: 'eCryptfs Custom ACL — Background' -->

## What is eCryptfs?

eCryptfs is a **stacked cryptographic filesystem** built into the Linux kernel.

- Sits between the VFS layer and a lower filesystem (ext4, etc.)
- Transparently **encrypts files** on write, **decrypts** on read
- Each file carries its own encryption metadata in the header
- Used in Ubuntu home directory encryption, embedded systems, secure storage

<br>

```
User process
     ↓
  VFS layer
     ↓
 eCryptfs  ← intercepts read/write, encrypts/decrypts
     ↓
 Lower FS  (ext4) — stores raw ciphertext
```

---

## The Problem

eCryptfs has **no fine-grained access control** beyond standard POSIX permissions.

<br>

| Limitation | Impact |
|---|---|
| Any permitted process reads **plaintext** | No isolation between processes |
| No per-process content control | Cannot serve ciphertext to one process, plaintext to another |
| No identity-based rules | Cannot restrict by UID, GID, or executable |
| Single permission model | Cannot have read-only ciphertext access |

<br>

> **Need**: A second enforcement layer that runs **after** POSIX checks and controls **who gets what data** — not just whether access is allowed.

---

## Project Objective

Design and implement an **internal ACL system** for a custom eCryptfs module that:

<br>

- Runs **after** standard POSIX/VFS permissions (two-stage model)
- Controls access based on **UID + GID + process executable** (AND logic)
- Decides not just **allow/deny** but also **what data is returned**:
  - `plaintext` — decrypted content
  - `ciphertext` — raw encrypted bytes
  - `deny` — access refused
- Enforced entirely in **kernel space** — no LSM dependency
- Lightweight: 2-byte xattr index, ≤ 64 rules per file

---
<!-- _class: divider -->

# 02
# Design

---
<!-- footer: 'eCryptfs Custom ACL — Design' -->

## Access Decision Model

Every access decision has **three dimensions**:

<br>

```
Subject         →  WHO  is accessing
  uid / gid / process executable (AND logic)

Permission      →  WHAT operations are allowed
  r / w / x  (intersected with system permissions)

Content Mode    →  WHAT DATA is returned
  plaintext | ciphertext | deny
```

<br>

> The content mode is unique to this system — standard ACLs only control allow/deny. Here, two processes can both be **allowed** but receive **different data** from the same file.

---

## Rule Matching Logic

<div class="columns">

<div>

**Subject matching — AND logic**

All specified conditions must match:

| Field | Value | Meaning |
|---|---|---|
| `uid` | number or `*` | User ID |
| `gid` | number or `*` | Group ID |
| `exe` | path or `*` | Executable |

`*` = wildcard (skip this dimension)

</div>

<div>

**Decision — first-match + priority**

```
Rules sorted by priority ↓

  prio=100  uid=1001 exe=head
      ↓ matches? → apply, stop
  prio=50   uid=*    exe=cat
      ↓ matches? → apply, stop
  (no match) → DENY
```

Max **64 rules** per ACL ID.
Higher number = evaluated first.

</div>
</div>

---

## Three-Point Enforcement Architecture

```
Process opens file
        │
        ▼
POINT 1 — ecryptfs_permission()          [inode.c]
  Stage 1: inode_permission(lower)   →   standard POSIX check
  Stage 2: ecryptfs_acl_check()      →   ACL allow / deny gate
        │
        ▼  (allowed)
POINT 2 — ecryptfs_open()               [file.c]
  Query ACL → PLAINTEXT or CIPHERTEXT mode
  Store mode in per-fd:  file_info->content_mode
        │
        ▼
POINT 3 — ecryptfs_read_update_atime()  [file.c]
  PLAINTEXT  → generic_file_read_iter()   page cache + decrypt
  CIPHERTEXT → vfs_iter_read(lower_file)  bypass cache, raw bytes
```

> A single enforcement point is insufficient — content mode selection requires per-fd state, and ciphertext readers must bypass the eCryptfs page cache entirely.

---

## Dual Address Space Design

The same inode must serve **different data** to different processes simultaneously.

<br>

```
                    ┌─────────────────────────────┐
                    │        eCryptfs inode        │
                    │                              │
  head (plaintext)  │   i_mapping  →  page cache   │  ← decrypted pages
                    │   (standard)                 │
                    │                              │
  cat (ciphertext)  │   ciphertext_mapping  →  ?   │  ← raw encrypted pages
                    │   (second address_space)     │
                    └─────────────────────────────┘
                                   │
                              lower inode
                           (ext4 ciphertext)
```

<br>

Two independent page caches per inode — no cross-contamination between plaintext and ciphertext readers.

---

## Storage Model

**File side — xattr on lower inode:**

```bash
trusted.ecryptfs_acl_id = 0x0001   # big-endian uint16, 2 bytes
```

**Kernel side — per-mount hash table:**

```
acl_table (per mount)
  └── bucket[hash(acl_id)]
        └── ecryptfs_acl_entry  (acl_id=1)
              ├── rule[0]  prio=100  uid=*    exe=cat   → ciphertext
              ├── rule[1]  prio=50   uid=1001 exe=head  → plaintext
              └── ...  (max 64 rules)
```

> The xattr stores only a 2-byte index. All rule data lives in kernel memory — fast pointer traversal, no per-access xattr reads after first lookup.

---
<!-- _class: divider -->

# 03
# Implementation

---
<!-- footer: 'eCryptfs Custom ACL — Implementation' -->

## What Was Built

Three implementation phases, all complete:

| Phase | Deliverable | Key Files |
|---|---|---|
| **1** | Data structures, xattr read, hash table, module init | `acl.h`, `acl.c`, `ecryptfs_kernel.h` |
| **2** | Debugfs management interface (`add`/`clear`/`list`), xattr wiring | `acl.c`, `inode.c` |
| **3** | Process matching (dev+ino), ciphertext read path, permission enforcement | `file.c`, `inode.c`, `acl.c` |

<br>

**New files:** `acl.h`, `acl.c`
**Modified files:** `ecryptfs_kernel.h`, `inode.c`, `file.c`, `super.c`, `Makefile`

---

## Key Implementation Decisions

<br>

| Decision | Reason |
|---|---|
| `vfs_iter_read(lower_file)` for ciphertext | `generic_file_read_iter` has a size-bound bug via the eCryptfs page cache |
| Process matching via **dev + inode** (not path) | Path comparison is namespace-dependent; inode number is stable |
| Inode resolved at **rule-insertion time** via `kern_path()` | Avoids path lookup on every file access (hot path) |
| Default when acl_id set but **no rule matches** → DENY | Fail-closed: explicit rules required, no accidental allow |
| Default when **no xattr** → pass-through | Backward compatible with existing unprotected files |

---

## Rule Management — Debugfs Interface

Rules are managed by writing commands to a debugfs control file:

```bash
# Add a rule
echo "add <acl_id> <priority> <uid|*> <gid|*> <exe|*> <perm> <content>" \
  | sudo tee /sys/kernel/debug/ecryptfs_acl/0/control

# Clear all rules for an ACL ID
echo "clear 1" | sudo tee /sys/kernel/debug/ecryptfs_acl/0/control

# View all rules
sudo cat /sys/kernel/debug/ecryptfs_acl/0/rules
```

**Tag a file:**
```bash
setfattr -n trusted.ecryptfs_acl_id -v 0x0001 /data.enc/secret.txt
```

---
<!-- _class: divider -->

# 04
# Testing

---
<!-- footer: 'eCryptfs Custom ACL — Testing' -->

## Test Strategy

**Language:** Python + pytest
**Approach:** Black-box behavioral tests — run real binaries against real mounted files

<br>

Key enabler — user identity switching without `sudo`:
```python
def run(binary, path, uid=0, gid=0):
    def _set_ids():
        os.setgid(gid)   # must be before setuid
        os.setuid(uid)
    return subprocess.run([binary, path],
                          capture_output=True,
                          preexec_fn=_set_ids)
```

`fork + setuid + exec` — the kernel sees the **correct uid and exe path**.
No wrapper process in between.

---

## Test Coverage

| File | Scenario | Tests |
|---|---|---|
| `test_rules.py` | Debugfs: add / clear / list / invalid cmd | 4 |
| `test_basic.py` | Exe-only rules: passthrough / plaintext / ciphertext / deny | 4 |
| `test_uid.py` | UID matching: match→plain, match→cipher, mismatch→deny, wildcard | 4 |
| `test_gid.py` | GID matching: match→plain, match→cipher, mismatch→deny | 3 |
| `test_combined.py` | AND logic: all match, uid fail, exe fail | 4 |
| `test_priority.py` | Priority ordering: cipher wins, plaintext wins | 2 |
| **Total** | | **21 tests** |

<br>

Test users: `root` (uid=0), `pi` (uid=1000), `inspector` (uid=1001)

---

## Test Results

All 21 tests pass. Live log output shows exactly what is being tested:

```
tests/test_uid.py::test_matching_uid_plaintext
  scenario : rule uid=1001 (inspector) + exe=head → plaintext | run as inspector
  rule     : acl_id=2 prio=100  uid=1001 gid=*  exe=head  → plaintext
  command  : inspector (uid=1001 gid=1001)  runs head
  result   : exit=0
PASSED

tests/test_uid.py::test_wrong_uid_denied
  scenario : rule uid=1001 | run as pi (uid=1000) → uid mismatch → expect EACCES
  rule     : acl_id=2 prio=100  uid=1001 gid=*  exe=head  → plaintext
  command  : pi (uid=1000 gid=1000)  runs head
  result   : exit=1
PASSED
```

---
<!-- _class: divider -->

# 05
# Status & Next Steps

---
<!-- footer: 'eCryptfs Custom ACL — Status' -->

## Current Status

<div class="columns">

<div>

**✅ Completed**

- ACL data structures & hash table
- xattr read (`trusted.ecryptfs_acl_id`)
- Debugfs management interface
- UID / GID / exe subject matching
- Three-point kernel enforcement
- Dual address_space (plaintext / ciphertext cache isolation)
- ciphertext read path (`vfs_iter_read`)
- 21 automated tests — all passing

</div>

<div>

**⏳ Remaining**

- **Persistence** (§12)
  Rules lost on `rmmod` — need load/save to disk
- **Directory inheritance** (§7)
  Upward traversal to mount root
- **HASH matching mode** (§9)
  SHA-256 of executable binary
- **Stale inode re-resolve** (§9)
  Auto-recover when binary is upgraded
- **Userspace management tool**
  CLI beyond debugfs

</div>
</div>

---

## Summary

<br>

| What | Detail |
|---|---|
| **Built** | Custom ACL layer inside eCryptfs kernel module |
| **Enforcement** | Three kernel hook points — permission, open, read |
| **Access model** | Subject (uid+gid+exe) × Permission × Content mode |
| **Content control** | Same inode → different data per process (dual address_space) |
| **Validated** | 21 automated tests covering all subject dimensions and outcomes |
| **Codebase** | ~1500 lines added across 6 kernel source files |

<br>

> The core enforcement mechanism is complete and verified. Remaining items (persistence, inheritance) are additive — the foundation is solid.

---
<!-- _class: lead -->
<!-- _paginate: false -->
<!-- footer: '' -->

# Thank You

<br>

**Repository:** `github.com/netcaf/myecryptfs`

**Run tests:**
```bash
sudo pytest tests/ -v
```

**Design document:** `doc/acl_srs.md`
