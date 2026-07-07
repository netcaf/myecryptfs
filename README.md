# eCryptfs ACL — Inode-Centric Access Control with Page-Cache Isolation

A personal research project that extends the Linux **eCryptfs** stacked encrypted
filesystem (based on the Linux 5.15 in-tree module) with a kernel-level access
control subsystem. Beyond classic allow/deny semantics, it introduces a third
access dimension — **content mode** — allowing different processes to see
*different views of the same file*: decrypted plaintext, raw ciphertext, or
nothing at all.

The ciphertext view is backed by a **dual `address_space` page-cache design**:
each inode can carry two independent page caches (plaintext and ciphertext),
and `file->f_mapping` is redirected per-open according to the ACL decision.
See the article [*Two Views of One File*](doc/article_page_cache_isolation.md)
for a deep dive, and the [design document](doc/acl_srs_en.md) for the full
specification, including the cache-consistency protocol and lifecycle handling.

> This is an independent research prototype, developed and tested in an
> isolated VM. It is not affiliated with any employer or commercial product.

---

## Highlights

- **Inode-centric ACL model** — each inode's xattr
  (`trusted.ecryptfs_acl_id`, 2 bytes) indexes an in-kernel rule list
  (max 64 rules, first-match by priority). Subjects are matched with AND
  logic across three dimensions: **user (kuid) · group (kgid) · process
  (executable inode)**, each wildcardable.

- **Three content modes** — `plaintext` (normal decrypted access),
  `ciphertext` (raw encrypted bytes, kernel-enforced read-only — intended
  for backup/audit tooling), and `deny`.

- **Dual page-cache isolation** — a second `address_space` per inode serves
  the ciphertext view. Consistency is maintained by invalidating ciphertext
  pages in `write_begin` and flushing plaintext dirty pages before ciphertext
  reads. Lifecycle is handled across `truncate`, `evict_inode`, and
  `destroy_inode`; `O_DIRECT` and write opens are rejected at `open` time.

- **Directory inheritance via dynamic walk** — an untagged file inherits the
  nearest ancestor's ACL, resolved at access time and cached per-inode.
  The design document contains a detailed trade-off analysis of dynamic walk
  vs. eager propagation ([SRS §7](doc/acl_srs_en.md#7-inheritance-model)).

- **debugfs management interface** — rules are managed at runtime through
  `/sys/kernel/debug/ecryptfs_acl`.

- **White-box pytest suite** — 32 tests exercising the live kernel module
  across UID, GID, process, permission-bit, priority, inheritance, and
  combined-subject dimensions ([tests/](tests/)).

---

## Access decision model

```
Subject (user ∧ group ∧ process)
      + Permission (r/w/x)          final permission = system ∩ ACL
      + Content mode                plaintext | ciphertext (read-only) | deny
      = Access result
```

Example rules (operational format):

```text
# vim: read-only access returning ciphertext
priority=100  process=/usr/bin/vim   user=*      group=*      permission=r   content=ciphertext

# grep: read-write plaintext access for alice in staff
priority=50   process=/usr/bin/grep  user=alice  group=staff  permission=rw  content=plaintext

# default rule (catch-all fallback)
priority=0    process=*              user=*      group=*      permission=r   content=deny
```

## Dual-cache architecture

```
                 upper inode (inode number unchanged)
                   ├── i_mapping ──────► plaintext address_space
                   │                     a_ops: decrypt on read / encrypt on write
                   └── ciphertext_mapping (lazily created)
                                         a_ops: read-only, no decryption

plaintext-authorized open:   file->f_mapping = inode->i_mapping
ciphertext-authorized open:  file->f_mapping = ciphertext_mapping
                             (FMODE_WRITE → -EACCES, O_DIRECT → -EINVAL)
```

---

## Repository layout

| Path | Contents |
|------|----------|
| `acl.c` / `acl.h` | ACL subsystem: rule lists, subject matching, inheritance walk, debugfs interface |
| `file.c`, `inode.c`, `mmap.c`, `super.c`, … | eCryptfs base module with ACL enforcement and dual-cache integration |
| `doc/acl_srs_en.md` | Requirements & design document (SRS v6) |
| `doc/article_page_cache_isolation.md` | Article: *Two Views of One File* — deep dive into the dual page-cache design |
| `tests/` | pytest white-box test suite (runs against the live module) |
| `slides/` | Design-walkthrough presentation (Marp) |

## Building & running

Requires Linux 5.15 kernel headers. **Load the module only in a disposable
VM** — this is experimental kernel code.

```sh
make                      # builds ecryptfs.ko
sudo insmod ecryptfs.ko
./r.sh                    # helper: reload module + mount an eCryptfs test volume
```

Run the test suite (as root, inside the VM, with the module loaded):

```sh
cd tests && sudo pytest -v
```

The suite verifies its target before running: it checks for
`/sys/kernel/debug/ecryptfs_acl` and skips if the stock eCryptfs module is
loaded instead.

## Status & limitations

Research prototype. It deliberately does **not** aim to replace SELinux or
implement a general LSM; per-namespace policies and ACL stacking are out of
scope. Remaining open items (management-interface hardening, hot-update
semantics, audit-log format) are tracked in the
[design document appendix](doc/acl_srs_en.md#appendix-open-items).

## License

GPL-2.0 (see [LICENSE](LICENSE)) — this work is derived from the Linux
kernel's in-tree eCryptfs module; original copyright notices are retained in
the source files.
