# Claude Project Guide - eCryptfs ACL Implementation

## Build & Test Commands
- **Build module**: `make`
- **Clean**: `make clean`
- **Check Coding Style**: `/home/pi/kernel_build/linux-5.15.0/scripts/checkpatch.pl --file --no-tree <file>`
- **Load Module**: `sudo insmod ecryptfs.ko` (Execute only in isolated dev VM)
- **Unload Module**: `sudo rmmod ecryptfs`

## Guardrails & Commit Policy
- **No Auto-Commits**: Do not execute `git commit` or `git push` without explicit user confirmation for each specific change.
- **Verification First**: Ensure the code passes checkpatch (if available) and compiles without warnings before suggesting a commit.
- **Staging**: Always show a summary of changes (diff) before asking: "Would you like me to commit these changes?"

## Token Efficiency & Communication
- **Be Concise**: Provide direct answers with minimal prose.
- **Incremental Reads**: Do not re-read large files (e.g., `file.c`, `inode.c`) if they are already in context.
- **Diffs Only**: Propose changes using concise diff formats instead of rewriting entire files.
- **Silent Tool Use**: Execute routine checks (`ls`, `grep`, `tree`) silently; report only relevant findings.
- **No Refactoring**: Do not suggest "code cleanups" of existing eCryptfs code unless strictly necessary for the ACL implementation.

## Code Style Guidelines (Linux Kernel)
- **Language**: Linux Kernel C (C99, no C++ features).
- **Indentation**: Hard tabs (8 characters wide).
- **Naming**: `snake_case` for all functions and variables.
- **Error Handling**: Use `goto out;` patterns for resource cleanup; return negative error codes (e.g., `-ENOMEM`, `-EACCES`).
- **Headers**: Maintain standard eCryptfs header inclusion order.

## Project Context & Logic
- **Objective**: Implement an internal eCryptfs ACL system based on **inode (object-centric)** control.
- **Matching**: Subject matching (user/group/process) uses **AND logic**.
- **Decision Model**: Use **First-match + priority**; list length is capped at **64 rules**.
- **Cache Isolation**: Implement the **dual address_space** design (plaintext vs. ciphertext).
- **Content Mode**: `content=ciphertext` must be **forced read-only** at the kernel level.
- **Xattr**: Use `trusted.ecryptfs_acl_id` (2-byte uint16_t) as the primary index.
- **Inheritance**: Dynamic upward traversal to the eCryptfs mount point.

## Reference Documents
- **Primary Design Doc**: `doc/acl_srs.md`
- **Instruction**: Always prioritize the logic, data structures, and constraints defined in `doc/acl_srs.md` over standard Linux ACL implementations or generic AI knowledge.