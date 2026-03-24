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
#include <linux/dcache.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <asm/byteorder.h>
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
 * Uses d_find_any_alias() to obtain a dentry for the upper inode,
 * then resolves the lower dentry/inode pair and reads the
 * trusted.ecryptfs_acl_id xattr (2-byte big-endian value).
 *
 * Returns ECRYPTFS_ACL_ID_NONE on any error or if the xattr is absent.
 */
static u16 acl_read_id(struct inode *inode)
{
	struct dentry *upper_dentry;
	struct dentry *lower_dentry;
	struct inode *lower_inode;
	__be16 val;
	ssize_t rc;

	upper_dentry = d_find_any_alias(inode);
	if (!upper_dentry)
		return ECRYPTFS_ACL_ID_NONE;

	lower_dentry = ecryptfs_dentry_to_lower(upper_dentry);
	lower_inode = ecryptfs_inode_to_lower(inode);

	rc = ecryptfs_getxattr_lower(lower_dentry, lower_inode,
				     ECRYPTFS_ACL_XATTR_NAME, &val, 2);
	dput(upper_dentry);

	if (rc != 2)
		return ECRYPTFS_ACL_ID_NONE;

	return be16_to_cpu(val);
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

/* ================================================================== */
/* Cache invalidation                                                   */
/* ================================================================== */

/*
 * acl_invalidate_all_caches - reset cached_acl_id on every ecryptfs
 * inode belonging to @sb, forcing re-read from xattr on next access.
 *
 * Must be called after any rule management write so that changes take
 * effect immediately.  Pattern follows fs/drop_caches.c.
 */
static void acl_invalidate_all_caches(struct super_block *sb)
{
	struct inode *inode;

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		struct ecryptfs_inode_info *ii;

		spin_lock(&inode->i_lock);
		if (inode->i_state & (I_FREEING | I_WILL_FREE | I_NEW)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		spin_unlock(&inode->i_lock);

		ii = ecryptfs_inode_to_private(inode);
		ii->cached_acl_id = ECRYPTFS_ACL_ID_NONE;
	}
	spin_unlock(&sb->s_inode_list_lock);
}

/* ================================================================== */
/* Rule management helpers (used by debugfs control)                    */
/* ================================================================== */

/*
 * acl_entry_create - allocate a new, unlinked ACL entry for @acl_id.
 * The caller is responsible for inserting into the hash table.
 */
static struct ecryptfs_acl_entry *acl_entry_create(u16 acl_id)
{
	struct ecryptfs_acl_entry *entry;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->acl_id = acl_id;
	return entry;
}

/*
 * acl_entry_insert_rule - add a rule to an entry at the correct
 * priority-sorted position.  Rules are sorted descending by priority.
 * Returns 0 on success, negative errno on failure.
 */
static int acl_entry_insert_rule(struct ecryptfs_acl_entry *entry,
				 const struct ecryptfs_acl_rule *rule)
{
	int i, pos;

	if (entry->nrules >= ECRYPTFS_ACL_MAX_RULES)
		return -ENOSPC;

	/* Find insertion point: first position where existing priority < new */
	pos = entry->nrules;
	for (i = 0; i < entry->nrules; i++) {
		if (entry->rules[i].priority < rule->priority) {
			pos = i;
			break;
		}
	}

	/* Shift rules down to make room */
	memmove(&entry->rules[pos + 1], &entry->rules[pos],
		(entry->nrules - pos) * sizeof(entry->rules[0]));

	entry->rules[pos] = *rule;
	entry->nrules++;
	return 0;
}

/* ================================================================== */
/* debugfs: control file (write-only command parsing)                   */
/* ================================================================== */

/*
 * parse_perm - parse permission string ("r", "rw", "rwx", "r-x", etc.)
 * into a bitmask.  Returns negative on invalid characters.
 */
static int parse_perm(const char *s)
{
	u8 perm = 0;

	for (; *s && *s != ' ' && *s != '\n'; s++) {
		switch (*s) {
		case 'r':
			perm |= ECRYPTFS_ACL_PERM_R;
			break;
		case 'w':
			perm |= ECRYPTFS_ACL_PERM_W;
			break;
		case 'x':
			perm |= ECRYPTFS_ACL_PERM_X;
			break;
		case '-':
			break;
		default:
			return -EINVAL;
		}
	}
	return perm;
}

/*
 * Parse content mode string: "plaintext", "ciphertext", "deny".
 * Returns -1 on unrecognised input.
 */
static int parse_content(const char *s)
{
	if (strncmp(s, "plaintext", 9) == 0)
		return ECRYPTFS_CONTENT_PLAINTEXT;
	if (strncmp(s, "ciphertext", 10) == 0)
		return ECRYPTFS_CONTENT_CIPHERTEXT;
	if (strncmp(s, "deny", 4) == 0)
		return ECRYPTFS_CONTENT_DENY;
	return -1;
}

/*
 * acl_cmd_add - handle "add <acl_id> <priority> <uid|*> <gid|*> <proc|*> <perm> <content>"
 */
static int acl_cmd_add(struct ecryptfs_sb_info *sbi, char *args)
{
	struct ecryptfs_acl_table *tbl = sbi->acl_table;
	struct ecryptfs_acl_entry *entry, *new_entry;
	struct ecryptfs_acl_rule rule;
	char uid_str[16], gid_str[16], proc_str[16];
	char perm_str[8], content_str[16];
	u16 acl_id;
	u32 uid_val, gid_val;
	int content_val;
	int rc;

	memset(&rule, 0, sizeof(rule));

	rc = sscanf(args, "%hu %u %15s %15s %15s %7s %15s",
		    &acl_id, &rule.priority,
		    uid_str, gid_str, proc_str, perm_str, content_str);
	if (rc != 7)
		return -EINVAL;

	if (acl_id == ECRYPTFS_ACL_ID_NONE)
		return -EINVAL;

	/* UID */
	if (uid_str[0] == '*') {
		rule.uid = INVALID_UID;
	} else {
		if (kstrtou32(uid_str, 10, &uid_val))
			return -EINVAL;
		rule.uid = make_kuid(&init_user_ns, uid_val);
	}

	/* GID */
	if (gid_str[0] == '*') {
		rule.gid = INVALID_GID;
	} else {
		if (kstrtou32(gid_str, 10, &gid_val))
			return -EINVAL;
		rule.gid = make_kgid(&init_user_ns, gid_val);
	}

	/* Process */
	if (proc_str[0] != '*')
		return -EINVAL;	/* Phase 5: full process matching */
	rule.proc_ino = 0;
	rule.proc_mode = ECRYPTFS_PROC_INODE_AUTO;

	/* Permission */
	rc = parse_perm(perm_str);
	if (rc < 0)
		return -EINVAL;
	rule.perm = (u8)rc;

	/* Content mode */
	content_val = parse_content(content_str);
	if (content_val < 0)
		return -EINVAL;
	rule.content = (u8)content_val;

	/* Pre-allocate outside the lock (struct is ~7 KB) */
	new_entry = acl_entry_create(acl_id);
	if (!new_entry)
		return -ENOMEM;

	/* Insert into table */
	write_lock(&tbl->lock);
	entry = acl_table_lookup(tbl, acl_id);
	if (!entry) {
		entry = new_entry;
		hlist_add_head(&entry->node,
			       &tbl->buckets[acl_bucket(acl_id)]);
		new_entry = NULL;	/* claimed */
	}
	rc = acl_entry_insert_rule(entry, &rule);
	write_unlock(&tbl->lock);

	kfree(new_entry);	/* free if unclaimed */

	if (rc == 0)
		acl_invalidate_all_caches(sbi->upper_sb);

	return rc;
}

/*
 * acl_cmd_del - handle "del <acl_id> <rule_index>"
 */
static int acl_cmd_del(struct ecryptfs_sb_info *sbi, char *args)
{
	struct ecryptfs_acl_table *tbl = sbi->acl_table;
	struct ecryptfs_acl_entry *entry;
	u16 acl_id;
	unsigned int idx;
	int rc;

	rc = sscanf(args, "%hu %u", &acl_id, &idx);
	if (rc != 2)
		return -EINVAL;

	write_lock(&tbl->lock);
	entry = acl_table_lookup(tbl, acl_id);
	if (!entry || (int)idx >= entry->nrules) {
		write_unlock(&tbl->lock);
		return -ENOENT;
	}

	kfree(entry->rules[idx].proc_path);

	/* Shift remaining rules up */
	memmove(&entry->rules[idx], &entry->rules[idx + 1],
		(entry->nrules - idx - 1) * sizeof(entry->rules[0]));
	entry->nrules--;

	/* Clean the vacated slot */
	memset(&entry->rules[entry->nrules], 0, sizeof(entry->rules[0]));

	write_unlock(&tbl->lock);

	acl_invalidate_all_caches(sbi->upper_sb);
	return 0;
}

/*
 * acl_cmd_clear - handle "clear <acl_id>" — remove all rules but keep entry.
 */
static int acl_cmd_clear(struct ecryptfs_sb_info *sbi, char *args)
{
	struct ecryptfs_acl_table *tbl = sbi->acl_table;
	struct ecryptfs_acl_entry *entry;
	u16 acl_id;
	int i;

	if (kstrtou16(args, 10, &acl_id))
		return -EINVAL;

	write_lock(&tbl->lock);
	entry = acl_table_lookup(tbl, acl_id);
	if (!entry) {
		write_unlock(&tbl->lock);
		return -ENOENT;
	}
	for (i = 0; i < entry->nrules; i++)
		kfree(entry->rules[i].proc_path);
	entry->nrules = 0;
	memset(entry->rules, 0, sizeof(entry->rules));
	write_unlock(&tbl->lock);

	acl_invalidate_all_caches(sbi->upper_sb);
	return 0;
}

/*
 * acl_cmd_delete - handle "delete <acl_id>" — remove entry entirely.
 */
static int acl_cmd_delete(struct ecryptfs_sb_info *sbi, char *args)
{
	struct ecryptfs_acl_table *tbl = sbi->acl_table;
	struct ecryptfs_acl_entry *entry;
	u16 acl_id;

	if (kstrtou16(args, 10, &acl_id))
		return -EINVAL;

	write_lock(&tbl->lock);
	entry = acl_table_lookup(tbl, acl_id);
	if (!entry) {
		write_unlock(&tbl->lock);
		return -ENOENT;
	}
	hlist_del(&entry->node);
	write_unlock(&tbl->lock);

	acl_entry_free(entry);
	acl_invalidate_all_caches(sbi->upper_sb);
	return 0;
}

static ssize_t acl_control_write(struct file *file, const char __user *ubuf,
				 size_t count, loff_t *ppos)
{
	struct ecryptfs_sb_info *sbi = file->private_data;
	char *buf, *cmd, *args;
	int rc;

	if (count > 256)
		return -EINVAL;

	buf = memdup_user_nul(ubuf, count);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	/* Strip trailing newline */
	if (count > 0 && buf[count - 1] == '\n')
		buf[count - 1] = '\0';

	/* Split command and arguments */
	cmd = strim(buf);
	args = strchr(cmd, ' ');
	if (args)
		*args++ = '\0';
	else
		args = "";
	args = skip_spaces(args);

	if (strcmp(cmd, "add") == 0)
		rc = acl_cmd_add(sbi, args);
	else if (strcmp(cmd, "del") == 0)
		rc = acl_cmd_del(sbi, args);
	else if (strcmp(cmd, "clear") == 0)
		rc = acl_cmd_clear(sbi, args);
	else if (strcmp(cmd, "delete") == 0)
		rc = acl_cmd_delete(sbi, args);
	else
		rc = -EINVAL;

	kfree(buf);
	return rc ? rc : (ssize_t)count;
}

static const struct file_operations acl_control_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.write	= acl_control_write,
};

/* ================================================================== */
/* debugfs: rules file (read-only seq_file dump)                       */
/* ================================================================== */

static const char * const content_names[] = {
	[ECRYPTFS_CONTENT_PLAINTEXT]  = "plaintext",
	[ECRYPTFS_CONTENT_CIPHERTEXT] = "ciphertext",
	[ECRYPTFS_CONTENT_DENY]       = "deny",
};

static const char *content_name(u8 mode)
{
	if (mode < ARRAY_SIZE(content_names) && content_names[mode])
		return content_names[mode];
	return "?";
}

static void acl_format_perm(char *buf, u8 perm)
{
	buf[0] = (perm & ECRYPTFS_ACL_PERM_R) ? 'r' : '-';
	buf[1] = (perm & ECRYPTFS_ACL_PERM_W) ? 'w' : '-';
	buf[2] = (perm & ECRYPTFS_ACL_PERM_X) ? 'x' : '-';
	buf[3] = '\0';
}

static int acl_rules_show(struct seq_file *m, void *v)
{
	struct ecryptfs_sb_info *sbi = m->private;
	struct ecryptfs_acl_table *tbl = sbi->acl_table;
	struct ecryptfs_acl_entry *entry;
	int bucket, i;

	if (!tbl) {
		seq_puts(m, "(no ACL table)\n");
		return 0;
	}

	read_lock(&tbl->lock);
	for (bucket = 0; bucket < ECRYPTFS_ACL_HTABLE_SIZE; bucket++) {
		hlist_for_each_entry(entry, &tbl->buckets[bucket], node) {
			seq_printf(m, "acl_id=%u (%d rules)\n",
				   entry->acl_id, entry->nrules);
			for (i = 0; i < entry->nrules; i++) {
				const struct ecryptfs_acl_rule *r =
					&entry->rules[i];
				char perm_str[4];

				acl_format_perm(perm_str, r->perm);

				seq_printf(m, "  [%d] prio=%u", i, r->priority);
				if (uid_valid(r->uid))
					seq_printf(m, " uid=%u",
						   from_kuid(&init_user_ns,
							     r->uid));
				else
					seq_puts(m, " uid=*");

				if (gid_valid(r->gid))
					seq_printf(m, " gid=%u",
						   from_kgid(&init_user_ns,
							     r->gid));
				else
					seq_puts(m, " gid=*");

				if (r->proc_ino != 0)
					seq_printf(m, " proc=%s",
						   r->proc_path ? : "?");
				else
					seq_puts(m, " proc=*");

				seq_printf(m, " perm=%s content=%s\n",
					   perm_str, content_name(r->content));
			}
		}
	}
	read_unlock(&tbl->lock);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(acl_rules);

/* ================================================================== */
/* Module-level debugfs + per-mount setup/teardown                     */
/* ================================================================== */

static struct dentry *acl_debugfs_root;
static atomic_t acl_mount_counter = ATOMIC_INIT(0);

/**
 * ecryptfs_acl_global_init - create the top-level debugfs directory.
 *
 * Called once from ecryptfs_init().  debugfs failure is non-fatal:
 * the ACL engine works without debugfs, just without the management
 * interface.
 */
int ecryptfs_acl_global_init(void)
{
	acl_debugfs_root = debugfs_create_dir("ecryptfs_acl", NULL);
	if (IS_ERR(acl_debugfs_root)) {
		pr_warn("ecryptfs: failed to create debugfs root\n");
		acl_debugfs_root = NULL;
	}
	return 0;
}

/**
 * ecryptfs_acl_global_exit - remove the top-level debugfs directory.
 *
 * Called once from ecryptfs_exit().
 */
void ecryptfs_acl_global_exit(void)
{
	debugfs_remove_recursive(acl_debugfs_root);
	acl_debugfs_root = NULL;
}

/**
 * ecryptfs_acl_mount_setup - allocate ACL table and create per-mount
 * debugfs entries.
 *
 * Called from ecryptfs_mount() after the superblock private is set.
 * Non-fatal: if allocation fails, the mount proceeds without ACL
 * (ecryptfs_acl_check returns allow-all/plaintext when acl_table is NULL).
 */
void ecryptfs_acl_mount_setup(struct ecryptfs_sb_info *sbi,
			      struct super_block *sb)
{
	char name[12];

	sbi->upper_sb = sb;

	sbi->acl_table = ecryptfs_acl_table_alloc();
	if (!sbi->acl_table) {
		pr_warn("ecryptfs: failed to allocate ACL table\n");
		return;
	}

	if (!acl_debugfs_root)
		return;

	sbi->acl_mount_idx = atomic_inc_return(&acl_mount_counter) - 1;
	snprintf(name, sizeof(name), "%u", sbi->acl_mount_idx);

	sbi->acl_debugfs_dir = debugfs_create_dir(name, acl_debugfs_root);
	if (IS_ERR_OR_NULL(sbi->acl_debugfs_dir)) {
		sbi->acl_debugfs_dir = NULL;
		return;
	}

	debugfs_create_file("control", 0600, sbi->acl_debugfs_dir, sbi,
			    &acl_control_fops);
	debugfs_create_file("rules", 0400, sbi->acl_debugfs_dir, sbi,
			    &acl_rules_fops);
}

/**
 * ecryptfs_acl_mount_teardown - remove per-mount debugfs entries.
 *
 * Called from ecryptfs_kill_block_super() before the ACL table is freed.
 */
void ecryptfs_acl_mount_teardown(struct ecryptfs_sb_info *sbi)
{
	debugfs_remove_recursive(sbi->acl_debugfs_dir);
	sbi->acl_debugfs_dir = NULL;
}
