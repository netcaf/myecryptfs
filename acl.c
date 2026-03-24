// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * eCryptfs: Linux filesystem encryption layer
 * Internal ACL engine — rule storage, subject matching, cipher cache.
 *
 * Design reference: doc/acl_srs.md (v6.0)
 *
 * Phase 1 status:
 *   - All data structures and lifecycle functions are complete.
 *   - ecryptfs_acl_check() returns pass-through (allow-all / plaintext)
 *     when no ACL table is configured, preserving existing behaviour.
 *   - xattr read, inheritance traversal, and process matching are stubbed;
 *     they will be filled in during Phase 2 and Phase 5.
 */

#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/pagemap.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/mm.h>
#include "ecryptfs_kernel.h"

/* ================================================================== */
/* Helpers                                                              */
/* ================================================================== */

static u32 acl_bucket(u16 acl_id)
{
	return hash_32(acl_id, ECRYPTFS_ACL_HTABLE_BITS);
}

/*
 * acl_table_lookup - find entry by acl_id.
 * Caller must hold tbl->lock for at least reading.
 */
static struct ecryptfs_acl_entry *
acl_table_lookup(struct ecryptfs_acl_table *tbl, u16 acl_id)
{
	struct ecryptfs_acl_entry *entry;

	hlist_for_each_entry(entry,
			     &tbl->buckets[acl_bucket(acl_id)], node) {
		if (entry->acl_id == acl_id)
			return entry;
	}
	return NULL;
}

static void acl_entry_free(struct ecryptfs_acl_entry *entry)
{
	int i;

	for (i = 0; i < entry->nrules; i++)
		kfree(entry->rules[i].proc_path);
	kfree(entry);
}

/* ================================================================== */
/* Table lifecycle                                                      */
/* ================================================================== */

/**
 * ecryptfs_acl_table_alloc - allocate and initialise a per-mount ACL table.
 *
 * Returns pointer on success, NULL on -ENOMEM.
 */
struct ecryptfs_acl_table *ecryptfs_acl_table_alloc(void)
{
	struct ecryptfs_acl_table *tbl;
	int i;

	tbl = kzalloc(sizeof(*tbl), GFP_KERNEL);
	if (!tbl)
		return NULL;

	for (i = 0; i < ECRYPTFS_ACL_HTABLE_SIZE; i++)
		INIT_HLIST_HEAD(&tbl->buckets[i]);

	rwlock_init(&tbl->lock);
	tbl->next_id = 1;	/* 0x0000 is reserved (SRS §5.2) */
	return tbl;
}

/**
 * ecryptfs_acl_table_free - destroy a per-mount ACL table and all its entries.
 *
 * Safe to call with NULL.
 */
void ecryptfs_acl_table_free(struct ecryptfs_acl_table *tbl)
{
	struct ecryptfs_acl_entry *entry;
	struct hlist_node *tmp;
	int i;

	if (!tbl)
		return;

	for (i = 0; i < ECRYPTFS_ACL_HTABLE_SIZE; i++) {
		hlist_for_each_entry_safe(entry, tmp,
					  &tbl->buckets[i], node) {
			hlist_del(&entry->node);
			acl_entry_free(entry);
		}
	}
	kfree(tbl);
}

/* ================================================================== */
/* Subject matching (SRS §6.3)                                         */
/* ================================================================== */

/*
 * subject_matches - test whether the current process satisfies a rule's
 * subject constraints.
 *
 * All specified fields are ANDed: a wildcard field (INVALID_UID,
 * INVALID_GID, proc_ino == 0) is always satisfied.
 *
 * Phase 1: process matching (INODE_AUTO / HASH / PATH_ONLY) is stubbed
 * to always return false when proc_ino != 0 so that only wildcard-process
 * rules can match.  Full implementation arrives in Phase 5.
 */
static bool subject_matches(const struct ecryptfs_acl_rule *rule)
{
	const struct cred *cred = current_cred();

	/* UID check */
	if (uid_valid(rule->uid) && !uid_eq(rule->uid, cred->uid))
		return false;

	/* GID check */
	if (gid_valid(rule->gid) && !gid_eq(rule->gid, cred->gid))
		return false;

	/*
	 * Process check — Phase 5 stub.
	 * proc_ino == 0 is the wildcard; any non-zero value means "must
	 * match a specific executable" which we cannot verify yet.
	 */
	if (rule->proc_ino != 0)
		return false;

	return true;
}

/* ================================================================== */
/* Decision engine (SRS §6.2, §11)                                     */
/* ================================================================== */

/* Default rule: deny everything (SRS §10) */
static const struct ecryptfs_acl_decision acl_default_deny = {
	.perm    = 0,
	.content = ECRYPTFS_CONTENT_DENY,
};

/*
 * acl_evaluate - first-match + priority scan over a rule list.
 *
 * Rules must be pre-sorted by priority descending (highest first).
 * The first rule whose subject matches wins; if none match we fall
 * back to the default-deny sentinel.
 *
 * sys_mask is the VFS-layer MAY_READ | MAY_WRITE | MAY_EXEC bitmask;
 * the final permission is ACL_perm ∩ system_perm (SRS §2).
 */
static void acl_evaluate(const struct ecryptfs_acl_entry *entry,
			 int sys_mask, struct ecryptfs_acl_decision *out)
{
	int i;

	for (i = 0; i < entry->nrules; i++) {
		const struct ecryptfs_acl_rule *rule = &entry->rules[i];

		if (!subject_matches(rule))
			continue;

		/* Intersect with VFS system permission */
		out->perm    = rule->perm & (u8)sys_mask;
		out->content = (enum ecryptfs_content_mode)rule->content;

		/* ciphertext mode forces read-only at kernel level (SRS §2) */
		if (out->content == ECRYPTFS_CONTENT_CIPHERTEXT)
			out->perm &= ECRYPTFS_ACL_PERM_R;

		return;	/* first-match wins */
	}

	*out = acl_default_deny;
}

/* ================================================================== */
/* xattr / inheritance (Phase 2 stubs)                                 */
/* ================================================================== */

/*
 * acl_read_id - read the 2-byte ACL ID from the lower inode's xattr.
 *
 * Phase 2 stub: returns ECRYPTFS_ACL_ID_NONE until xattr I/O is wired.
 * Full implementation needs the lower dentry, which is available in
 * ecryptfs_permission() via the inode's dentry but not directly from
 * the inode pointer alone.
 */
static u16 acl_read_id(struct inode *inode)
{
	/* TODO Phase 2: resolve lower dentry, call ecryptfs_getxattr_lower,
	 * parse 2-byte big-endian ACL ID. */
	(void)inode;
	return ECRYPTFS_ACL_ID_NONE;
}

/* ================================================================== */
/* Core decision API                                                    */
/* ================================================================== */

/**
 * ecryptfs_acl_check - perform the ACL access decision for an inode.
 *
 * @inode: upper eCryptfs inode being accessed
 * @mask:  VFS permission mask (MAY_READ, MAY_WRITE, MAY_EXEC, …)
 * @out:   decision output: final perm bits + content mode
 *
 * Caller inspects out->content for ECRYPTFS_CONTENT_DENY; this
 * function's return value signals only internal errors.
 *
 * Phase 1 behaviour: when no ACL table is present on the mount
 * (sb_info->acl_table == NULL) we return allow-all / plaintext so that
 * existing eCryptfs operation is completely unaffected.
 */
int ecryptfs_acl_check(struct inode *inode, int mask,
		       struct ecryptfs_acl_decision *out)
{
	struct ecryptfs_inode_info *inode_info =
		ecryptfs_inode_to_private(inode);
	struct ecryptfs_sb_info *sb_info =
		ecryptfs_superblock_to_private(inode->i_sb);
	struct ecryptfs_acl_table *tbl = sb_info->acl_table;
	struct ecryptfs_acl_entry *entry;
	u16 acl_id;

	/*
	 * Phase 1 pass-through: no ACL table configured on this mount.
	 * Preserve all existing eCryptfs behaviour unchanged.
	 */
	if (!tbl) {
		out->perm    = ECRYPTFS_ACL_PERM_ALL;
		out->content = ECRYPTFS_CONTENT_PLAINTEXT;
		return 0;
	}

	/* Step 1: resolve ACL ID for this inode (cached or from xattr) */
	acl_id = inode_info->cached_acl_id;
	if (acl_id == ECRYPTFS_ACL_ID_NONE) {
		acl_id = acl_read_id(inode);
		/*
		 * TODO Phase 2: if still NONE, walk up to mount root
		 * for dynamic inheritance (SRS §7).
		 */
		inode_info->cached_acl_id = acl_id;
	}

	/* No ACL anywhere up the tree → default deny (SRS §10) */
	if (acl_id == ECRYPTFS_ACL_ID_NONE) {
		*out = acl_default_deny;
		return 0;
	}

	/* Step 2: look up rule list and evaluate */
	read_lock(&tbl->lock);
	entry = acl_table_lookup(tbl, acl_id);
	if (entry)
		acl_evaluate(entry, mask, out);
	else
		*out = acl_default_deny;	/* missing entry → deny */
	read_unlock(&tbl->lock);

	return 0;
}

/* ================================================================== */
/* Ciphertext address_space — readpage (SRS §18.5.2)                   */
/* ================================================================== */

/*
 * ecryptfs_readpage_ciphertext - fill a cipher-cache page with raw
 * lower-layer data, without decrypting.
 *
 * Before reading from the lower file we force-flush any plaintext dirty
 * pages at the same offset so the lower file holds the latest encrypted
 * data.  The two address_spaces are independent (different page objects),
 * so there is no deadlock between the two page locks. (SRS §18.5.2)
 */
static int ecryptfs_readpage_ciphertext(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	pgoff_t index = page->index;
	int rc;

	/*
	 * Flush plaintext dirty page at the same logical offset to lower
	 * file, ensuring the raw bytes we are about to read are current.
	 */
	rc = filemap_write_and_wait_range(
		inode->i_mapping,
		(loff_t)index << PAGE_SHIFT,
		((loff_t)(index + 1) << PAGE_SHIFT) - 1);
	if (rc)
		goto out;

	/* Read raw ciphertext from lower file — no decryption */
	rc = ecryptfs_read_lower_page_segment(page, index, 0, PAGE_SIZE,
					      inode);
	if (!rc)
		SetPageUptodate(page);

out:
	unlock_page(page);
	return rc;
}

/*
 * ecryptfs_aops_ciphertext - address_space_operations for the cipher cache.
 *
 * Only readpage is populated.  writepage / write_begin / write_end are
 * NULL, which causes the kernel to refuse all write attempts at the
 * page-cache level.  Write access is also blocked at open() time by
 * checking FMODE_WRITE (SRS §18.4.2, §18.6.2).
 */
const struct address_space_operations ecryptfs_aops_ciphertext = {
	.readpage = ecryptfs_readpage_ciphertext,
};

/* ================================================================== */
/* Cipher address_space lifecycle (SRS §18.6)                          */
/* ================================================================== */

/**
 * ecryptfs_acl_init_ciphertext_mapping - lazily create the second
 * address_space used by ciphertext-mode file descriptors.
 *
 * Must be called with inode_info->cipher_mapping_mutex held.
 * The caller must check inode_info->ciphertext_mapping for NULL before
 * calling (double-checked locking pattern). (SRS §18.6.1)
 */
int ecryptfs_acl_init_ciphertext_mapping(struct inode *inode)
{
	struct ecryptfs_inode_info *inode_info =
		ecryptfs_inode_to_private(inode);
	struct address_space *mapping;

	mapping = kzalloc(sizeof(struct address_space), GFP_KERNEL);
	if (!mapping)
		return -ENOMEM;

	address_space_init_once(mapping);
	mapping->host     = inode;
	mapping->a_ops    = &ecryptfs_aops_ciphertext;
	mapping->gfp_mask = GFP_HIGHUSER_MOVABLE;

	inode_info->ciphertext_mapping = mapping;
	return 0;
}

/**
 * ecryptfs_acl_evict_ciphertext_mapping - purge all pages from the cipher
 * cache before the inode is evicted.
 *
 * Must be called BEFORE truncate_inode_pages_final(&inode->i_data).
 * Skips gracefully if ciphertext_mapping was never initialised. (SRS §18.6.4)
 */
void ecryptfs_acl_evict_ciphertext_mapping(struct inode *inode)
{
	struct ecryptfs_inode_info *inode_info =
		ecryptfs_inode_to_private(inode);

	if (inode_info->ciphertext_mapping)
		truncate_inode_pages_final(inode_info->ciphertext_mapping);
}

/**
 * ecryptfs_acl_destroy_ciphertext_mapping - free the cipher address_space.
 *
 * All pages must have been purged by ecryptfs_acl_evict_ciphertext_mapping
 * before this is called.  Called from ecryptfs_destroy_inode(). (SRS §18.6.5)
 */
void ecryptfs_acl_destroy_ciphertext_mapping(struct inode *inode)
{
	struct ecryptfs_inode_info *inode_info =
		ecryptfs_inode_to_private(inode);

	if (inode_info->ciphertext_mapping) {
		kfree(inode_info->ciphertext_mapping);
		inode_info->ciphertext_mapping = NULL;
	}
}

/**
 * ecryptfs_acl_invalidate_cipher_page - evict one page from the cipher
 * cache to maintain consistency when the plaintext side is written.
 *
 * Called from ecryptfs_write_begin() immediately before the plaintext
 * page is dirtied, so cipher-mode readers always re-fetch from lower. (SRS §18.5.1)
 */
void ecryptfs_acl_invalidate_cipher_page(struct inode *inode, pgoff_t index)
{
	struct ecryptfs_inode_info *inode_info =
		ecryptfs_inode_to_private(inode);

	if (inode_info->ciphertext_mapping)
		invalidate_mapping_pages(inode_info->ciphertext_mapping,
					 index, index);
}
