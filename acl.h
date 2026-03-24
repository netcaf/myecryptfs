/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * eCryptfs: Linux filesystem encryption layer
 * Internal ACL system — data structures and API.
 *
 * Design reference: doc/acl_srs.md (v6.0)
 */

#ifndef ECRYPTFS_ACL_H
#define ECRYPTFS_ACL_H

#include <linux/types.h>
#include <linux/uidgid.h>
#include <linux/fs.h>
#include <linux/rwlock.h>
#include <linux/hashtable.h>

/* ------------------------------------------------------------------ */
/* Enumerations (SRS §3)                                               */
/* ------------------------------------------------------------------ */

/*
 * ecryptfs_content_mode - per-fd data delivery mode (SRS §3.3).
 *
 * Stored in ecryptfs_file_info.content_mode at open time.
 * PLAINTEXT  : caller sees decrypted data (default eCryptfs behaviour).
 * CIPHERTEXT : caller sees raw encrypted bytes; write is kernel-blocked.
 * DENY       : access refused at the gate; no data returned.
 */
enum ecryptfs_content_mode {
	ECRYPTFS_CONTENT_PLAINTEXT  = 0,
	ECRYPTFS_CONTENT_CIPHERTEXT = 1,
	ECRYPTFS_CONTENT_DENY       = 2,
};

/*
 * ecryptfs_proc_match_mode - how the process subject is matched (SRS §9).
 *
 * INODE_AUTO : match on dev+ino of the executable; if the inode is gone
 *              (binary upgraded), re-resolve via saved path and update cache.
 * HASH       : match on SHA-256 of the executable binary.
 * PATH_ONLY  : plain path-string comparison (debug / compat only).
 */
enum ecryptfs_proc_match_mode {
	ECRYPTFS_PROC_INODE_AUTO = 0,
	ECRYPTFS_PROC_HASH       = 1,
	ECRYPTFS_PROC_PATH_ONLY  = 2,
};

/* ------------------------------------------------------------------ */
/* Constants (SRS §5.2, §6.1, §3.2)                                   */
/* ------------------------------------------------------------------ */

/* xattr key written to the lower inode */
#define ECRYPTFS_ACL_XATTR_NAME		"trusted.ecryptfs_acl_id"

/* Reserved ACL ID: "no ACL assigned" */
#define ECRYPTFS_ACL_ID_NONE		0x0000U

/* Hard ceiling on rules per ACL ID (SRS §6.1) */
#define ECRYPTFS_ACL_MAX_RULES		64

/* Permission-bit flags stored in ecryptfs_acl_rule.perm (SRS §3.2) */
#define ECRYPTFS_ACL_PERM_R		0x01
#define ECRYPTFS_ACL_PERM_W		0x02
#define ECRYPTFS_ACL_PERM_X		0x04
#define ECRYPTFS_ACL_PERM_ALL		(ECRYPTFS_ACL_PERM_R | \
					 ECRYPTFS_ACL_PERM_W | \
					 ECRYPTFS_ACL_PERM_X)

/* SHA-256 digest size for HASH matching mode */
#define ECRYPTFS_ACL_HASH_SIZE		32

/* ------------------------------------------------------------------ */
/* Core data structures                                                 */
/* ------------------------------------------------------------------ */

/*
 * ecryptfs_acl_rule - one access control rule (SRS §5.1, §6).
 *
 * Hot-path matching data is kept compact (≤ 96 bytes before proc_path).
 * proc_path is heap-allocated and used only for audit output / PATH_ONLY
 * matching; it is never dereferenced in the INODE_AUTO or HASH loops.
 *
 * Subject AND semantics (SRS §6.3):
 *   - uid:      INVALID_UID  → wildcard (match any user)
 *   - gid:      INVALID_GID  → wildcard (match any group)
 *   - proc_ino: 0            → wildcard (match any process)
 */
struct ecryptfs_acl_rule {
	u32		priority;	/* higher value = evaluated first     */

	/* Subject — UID / GID (SRS §3.1) */
	kuid_t		uid;		/* INVALID_UID = wildcard             */
	kgid_t		gid;		/* INVALID_GID = wildcard             */

	/* Subject — process (SRS §9) */
	u8		proc_mode;	/* enum ecryptfs_proc_match_mode      */
	dev_t		proc_dev;	/* INODE_AUTO: device of exe inode    */
	unsigned long	proc_ino;	/* INODE_AUTO: inode num; 0 = wildcard*/
	u8		proc_hash[ECRYPTFS_ACL_HASH_SIZE]; /* HASH mode    */

	/* Decision (SRS §3.2, §3.3) */
	u8		perm;		/* ECRYPTFS_ACL_PERM_* bitmask        */
	u8		content;	/* enum ecryptfs_content_mode         */

	/* Display / PATH_ONLY matching — never touched in hot path */
	char		*proc_path;	/* kmalloc'd; NULL if not set         */
};

/*
 * ecryptfs_acl_entry - rule list for one ACL ID (SRS §5.1, §6.1).
 *
 * Rules are kept sorted by priority descending so first-match semantics
 * (SRS §6.2) reduce to a plain linear scan with early exit.
 */
struct ecryptfs_acl_entry {
	struct hlist_node	 node;
	u16			 acl_id;
	int			 nrules;
	struct ecryptfs_acl_rule rules[ECRYPTFS_ACL_MAX_RULES];
};

/*
 * ecryptfs_acl_table - per-mount ACL hash table (SRS §5.3).
 *
 * A pointer to this lives in ecryptfs_sb_info.acl_table; NULL means
 * no ACL has been configured on this mount yet.
 *
 * The rwlock separates fast read-only match paths (many concurrent
 * readers) from infrequent management writes (one writer at a time).
 */
#define ECRYPTFS_ACL_HTABLE_BITS	8
#define ECRYPTFS_ACL_HTABLE_SIZE	(1 << ECRYPTFS_ACL_HTABLE_BITS)

struct ecryptfs_acl_table {
	struct hlist_head	buckets[ECRYPTFS_ACL_HTABLE_SIZE];
	rwlock_t		lock;
	u16			next_id;  /* monotone; wraps with gap-scan    */
};

/* ------------------------------------------------------------------ */
/* ACL decision result                                                  */
/* ------------------------------------------------------------------ */

/*
 * ecryptfs_acl_decision - output of ecryptfs_acl_check().
 *
 * perm:    final allowed permission bits after system∩ACL intersection.
 * content: data delivery mode for this file descriptor.
 */
struct ecryptfs_acl_decision {
	u8			     perm;
	enum ecryptfs_content_mode   content;
};

/* ------------------------------------------------------------------ */
/* Public API — implemented in acl.c                                   */
/* ------------------------------------------------------------------ */

/* Table lifecycle */
struct ecryptfs_acl_table *ecryptfs_acl_table_alloc(void);
void ecryptfs_acl_table_free(struct ecryptfs_acl_table *tbl);

/*
 * ecryptfs_acl_check - main ACL decision entry point.
 *
 * Called from ecryptfs_permission() (allow/deny gate) and
 * ecryptfs_open() (content mode selection).
 *
 * @inode: upper eCryptfs inode being accessed
 * @mask:  VFS-layer requested permission mask (MAY_READ | MAY_WRITE …)
 * @out:   filled with the final allowed perm and content mode
 *
 * Returns 0 on success; negative errno on internal error.
 * A DENY result is signalled via out->content == ECRYPTFS_CONTENT_DENY,
 * not via the return value.
 */
int ecryptfs_acl_check(struct inode *inode, int mask,
		       struct ecryptfs_acl_decision *out);

/*
 * Cipher address_space lifecycle (SRS §18.6).
 *
 * init   : lazily create the second address_space for ciphertext cache.
 *          Must be called with inode_info->cipher_mapping_mutex held.
 * evict  : purge all cipher cache pages — call BEFORE truncate on i_data.
 * destroy: free the address_space struct — call AFTER evict.
 */
int  ecryptfs_acl_init_ciphertext_mapping(struct inode *inode);
void ecryptfs_acl_evict_ciphertext_mapping(struct inode *inode);
void ecryptfs_acl_destroy_ciphertext_mapping(struct inode *inode);

/*
 * ecryptfs_acl_invalidate_cipher_page - drop one page from cipher cache.
 *
 * Called from ecryptfs_write_begin() to maintain cache consistency
 * when the plaintext side is about to be modified (SRS §18.5.1).
 */
void ecryptfs_acl_invalidate_cipher_page(struct inode *inode, pgoff_t index);

/* address_space_operations for the ciphertext cache (SRS §18.4.3) */
extern const struct address_space_operations ecryptfs_aops_ciphertext;

#endif /* ECRYPTFS_ACL_H */
