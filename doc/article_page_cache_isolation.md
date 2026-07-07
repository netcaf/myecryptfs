# Two Views of One File: Page-Cache Isolation in a Stackable Encrypted Filesystem

*How I extended eCryptfs so that different processes can read the same file as
plaintext or as raw ciphertext — by giving one inode two page caches.*

---

## The problem

eCryptfs is a stackable encrypted filesystem in the Linux kernel: it sits on
top of a lower filesystem (ext4, xfs, …), encrypts data on the way down and
decrypts it on the way up. Every process that opens a file through the mount
point sees decrypted plaintext. That is the whole point — and also the
limitation I wanted to remove.

In the access-control system I built on top of eCryptfs
([ecryptfs_acl](https://github.com/netcaf/ecryptfs_acl)), an ACL rule decides
not only *whether* a subject may access a file, but *what bytes it sees*.
A rule assigns one of three content modes:

- `plaintext` — normal decrypted access,
- `ciphertext` — the raw encrypted bytes, read-only (think backup agents and
  audit tooling that must ship data off the machine without ever seeing it),
- `deny` — nothing at all.

The interesting case is `ciphertext`. It means two processes can hold the
same file open *at the same time* and legitimately read **different bytes**:
an editor sees plaintext, a backup daemon sees ciphertext. Access control can
decide who gets which view — but the page cache decides which bytes a read
actually returns, and Linux gives an inode exactly **one** page cache.

That is the real problem: the Linux page cache is globally shared per inode.
One `struct address_space`, one set of cached pages, shared by every process
that reads the file. There is no native notion of "concurrent multi-view
access" to a single file.

## The pivot point: `file->f_mapping`

`struct address_space` is the kernel's per-file page-cache manager. Three of
its fields matter here:

- `i_pages` — the xarray indexing every cached page of the file,
- `a_ops` — the `address_space_operations` that define how pages are filled
  and written back (`readpage`, `writepage`, `write_begin`, `write_end`),
- `host` — a back-pointer to the owning inode.

By default, each inode embeds one `address_space` (`inode->i_data`) and
`inode->i_mapping` points at it. When a file is opened, the VFS sets
`file->f_mapping = inode->i_mapping`, and from then on the generic I/O paths
(`generic_file_read_iter`, `filemap_fault`, …) operate on **`file->f_mapping`**
— not on `inode->i_mapping` directly.

That indirection is the entire foundation of this design:
`file->f_mapping` is set per-`struct file`, at `open` time, and nothing stops
a filesystem from pointing it somewhere else. Two opens of the same inode can
be wired to two different page caches, while the inode number — what `stat`,
`ls -i`, and every userspace tool sees — stays exactly the same.

## The design: two mappings on one inode

Each eCryptfs inode gets an optional second `address_space`, created lazily on
the first ciphertext-mode open:

```
upper inode (inode number unchanged)
  ├── i_mapping ───────────► i_data          (plaintext address_space)
  │                           a_ops: decrypt on readpage,
  │                                  encrypt on writepage
  │
  └── ciphertext_mapping ──► (lazily created) (ciphertext address_space)
                              a_ops: readpage only — no decryption,
                                     all write ops NULL

plaintext-authorized open:   file->f_mapping = inode->i_mapping
ciphertext-authorized open:  file->f_mapping = inode_info->ciphertext_mapping
```

The private inode info grows two fields:

```c
struct ecryptfs_inode_info {
    /* ... existing fields ... */
    struct address_space  *ciphertext_mapping;   /* NULL = never used */
    struct mutex           cipher_mapping_mutex; /* init race protection */
};
```

and the ciphertext view gets its own operations table, which is mostly
notable for what it does *not* contain:

```c
const struct address_space_operations ecryptfs_aops_ciphertext = {
    .readpage = ecryptfs_readpage_ciphertext,  /* read lower, no decrypt */
    /* writepage / write_begin / write_end: NULL — writes impossible */
};
```

At `open` time, the ACL decision selects the view:

```c
if (mode == ECRYPTFS_ACCESS_CIPHERTEXT) {
    if (file->f_mode & FMODE_WRITE)   /* ciphertext is read-only, period */
        return -EACCES;
    if (file->f_flags & O_DIRECT)     /* O_DIRECT bypasses the page cache */
        return -EINVAL;

    mutex_lock(&inode_info->cipher_mapping_mutex);
    if (!inode_info->ciphertext_mapping)
        rc = ecryptfs_init_ciphertext_mapping(inode);
    mutex_unlock(&inode_info->cipher_mapping_mutex);
    if (rc)
        return rc;

    file->f_mapping = inode_info->ciphertext_mapping;
}
```

### The one decision that makes everything tractable

**Ciphertext mode is read-only, enforced in the kernel, with no exceptions.**
Even if an ACL rule says `permission=rw, content=ciphertext`, the effective
permission is `r`.

This is not a policy nicety — it is the load-bearing simplification of the
whole design. If ciphertext writers existed, I would need bidirectional cache
coherence: a ciphertext write would have to invalidate plaintext pages,
interleave correctly with in-flight plaintext writes, and define what a
"raw write" even means for a file whose header eCryptfs owns. By rejecting
`FMODE_WRITE` at open, the consistency problem collapses to a single
direction: plaintext writes must not let ciphertext readers see stale bytes.

Making one side of a concurrency problem read-only is an old trick, but it is
striking how much machinery it deletes here.

## Keeping the two caches consistent

Plaintext users write; ciphertext readers must never see stale data. Two
hooks are enough.

**1. On write: invalidate the ciphertext page immediately.**
In `write_begin` — not at writeback time — the corresponding ciphertext page
is dropped:

```c
static int ecryptfs_write_begin(..., loff_t pos, ...)
{
    pgoff_t index = pos >> PAGE_SHIFT;

    if (inode_info->ciphertext_mapping)
        invalidate_mapping_pages(inode_info->ciphertext_mapping,
                                 index, index);

    return ecryptfs_orig_write_begin(...);
}
```

Why `write_begin` and not `writepage`? Because the moment `write_begin`
returns, the plaintext cache is the authoritative view of the file, and the
cached ciphertext for that offset is already a lie. Waiting for asynchronous
writeback would leave a window where a ciphertext reader gets bytes that no
longer correspond to any state of the file.

**2. On ciphertext read: flush plaintext dirty pages first.**
The ciphertext `readpage` forces any dirty plaintext page at the same offset
down to the lower file before reading raw bytes from it:

```c
static int ecryptfs_readpage_ciphertext(struct file *file, struct page *page)
{
    struct inode *inode = page->mapping->host;
    pgoff_t index = page->index;

    rc = filemap_write_and_wait_range(inode->i_mapping,
             (loff_t)index << PAGE_SHIFT,
             ((loff_t)index << PAGE_SHIFT) + PAGE_SIZE - 1);
    if (rc)
        goto out;

    rc = ecryptfs_read_lower_page_segment(page, index, 0, PAGE_SIZE, inode);
    if (!rc)
        SetPageUptodate(page);
out:
    unlock_page(page);
    return rc;
}
```

Together the two hooks give this timeline:

| | Event | Consistency action |
|---|-------|--------------------|
| T1 | plaintext write to page N | `write_begin` invalidates ciphertext page N |
| T2 | ciphertext read of page N | flush plaintext dirty page N, then read fresh ciphertext from lower |
| T3 | async writeback of page N | encrypts to lower; ciphertext copy already gone since T1 |
| T4 | ciphertext read again | fresh lower read, then cache hits |

One question worth asking of any "flush the other cache while holding a page
lock" scheme: can it deadlock? Here, no — the flush in
`ecryptfs_readpage_ciphertext` runs while holding the lock on a page in
`ciphertext_mapping`, and operates on pages in `i_mapping`. The two mappings
are disjoint sets of memory objects: different `address_space` instances,
different pages, different locks. The same lock is never taken twice.

## Lifecycle: where the crashes live

A second `address_space` hanging off an inode is invisible to the generic VFS
teardown paths, which only know about `inode->i_data`. Every exit point has
to be taught about it, and the **ordering** matters.

- **`evict_inode`** — the critical one. Ciphertext pages must be purged
  *before* the generic teardown:

  ```c
  static void ecryptfs_evict_inode(struct inode *inode)
  {
      if (inode_info->ciphertext_mapping)
          truncate_inode_pages_final(inode_info->ciphertext_mapping);

      truncate_inode_pages_final(&inode->i_data);
      clear_inode(inode);
  }
  ```

  Skip this and the pages remain on the LRU pointing at a freed inode; the
  next memory-reclaim pass walks into them and the box panics. This is the
  classic failure mode of any "extra cache attached to an inode" design.

- **`truncate`** — shrink the ciphertext cache first, then the plaintext
  cache (`truncate_inode_pages` on the extra mapping, then
  `truncate_setsize`), so no ciphertext page ever refers past EOF.

- **`destroy_inode`** — pages are already gone; just `kfree` the extra
  `address_space`.

And one path needs *no* work at all, which is the quiet payoff of hanging
everything off `f_mapping`: **mmap**. A ciphertext-mode open already rejected
`FMODE_WRITE`, so writable shared mappings die in the VFS's own checks. A
read-only `mmap` inherits `file->f_mapping`, so page faults land in
`ecryptfs_readpage_ciphertext` automatically and behave correctly. No changes
in the fault path.

## What it costs

| Scenario | Overhead |
|----------|----------|
| plaintext I/O, file never opened in ciphertext mode | zero — `ciphertext_mapping` is NULL, one pointer check |
| plaintext write with ciphertext readers | one `invalidate_mapping_pages` lookup |
| first ciphertext read of a page | one range flush of the plaintext cache |
| repeated ciphertext reads | zero — normal page-cache hits |
| memory | ~200 bytes per file, only for files actually opened in ciphertext mode |

Ciphertext access is a low-frequency audit/backup pattern; the hot path —
ordinary plaintext I/O on files nobody audits — pays a single NULL check.

## Takeaways

1. **`file->f_mapping` is an underappreciated indirection point.** "One inode,
   one page cache" is a default, not a law. Because the generic I/O paths
   resolve the cache through the `struct file`, a filesystem can give
   different openers different caches — while userspace-visible identity
   (the inode) stays intact.

2. **Make one side read-only and watch the problem shrink.** The entire
   consistency protocol is two hooks precisely because ciphertext writers
   don't exist. The best concurrency design is often the one that removes a
   writer, not the one with cleverer locking.

3. **The design work is in the teardown.** The happy path (redirect a pointer
   at `open`) took an afternoon. Making `truncate`, `evict_inode`, and
   `destroy_inode` order their cleanup correctly is where a kernel feature
   earns its keep — and where it crashes if you get it wrong.

---

*This article describes the page-cache isolation layer of
[ecryptfs_acl](https://github.com/netcaf/ecryptfs_acl), a personal research
project extending eCryptfs (Linux 5.15) with an inode-centric ACL system —
subject matching on user/group/process, directory inheritance, and the
content-mode mechanism described here. The full requirements & design
document is in the repo:
[doc/acl_srs_en.md](https://github.com/netcaf/ecryptfs_acl/blob/main/doc/acl_srs_en.md).
The white-box pytest suite that validates the module lives in
[tests/](https://github.com/netcaf/ecryptfs_acl/tree/main/tests).*
