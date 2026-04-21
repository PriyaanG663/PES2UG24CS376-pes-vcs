// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = tree->count * 296; 
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf
        
        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
//
// HINTS - Useful functions and concepts for this phase:
//   - index_load      : load the staged files into memory
//   - strchr          : find the first '/' in a path to separate directories from files
//   - strncmp         : compare prefixes to group files belonging to the same subdirectory
//   - Recursion       : you will likely want to create a recursive helper function 
//                       (e.g., `write_tree_level(entries, count, depth)`) to handle nested dirs.
//   - tree_serialize  : convert your populated Tree struct into a binary buffer
//   - object_write    : save that binary buffer to the store as OBJ_TREE
//
// Returns 0 on success, -1 on error.
static int build_tree(const IndexEntry *entries, int count, const char *prefix, ObjectID *id_out) {
    Tree tree;
    tree.count = 0;

    typedef struct {
        char name[256];
        int is_dir;
        ObjectID hash;
        uint32_t mode;
    } PendingEntry;

    PendingEntry pending[MAX_TREE_ENTRIES];
    int pending_count = 0;

    for (int i = 0; i < count; i++) {
        const char *path = entries[i].path;
        size_t prefix_len = strlen(prefix);
        if (strncmp(path, prefix, prefix_len) != 0) continue;
        const char *remaining = path + prefix_len;
        if (*remaining == '\0') continue;
        const char *slash = strchr(remaining, '/');
        if (slash) {
            size_t name_len = slash - remaining;
            char name[256];
            memcpy(name, remaining, name_len);
            name[name_len] = '\0';
            int found = 0;
            for (int j = 0; j < pending_count; j++) {
                if (strcmp(pending[j].name, name) == 0 && pending[j].is_dir) {
                    found = 1;
                    break;
                }
            }
            if (!found && pending_count < MAX_TREE_ENTRIES) {
                strcpy(pending[pending_count].name, name);
                pending[pending_count].is_dir = 1;
                pending[pending_count].mode = MODE_DIR;
                pending_count++;
            }
        } else {
            char name[256];
            strcpy(name, remaining);
            if (pending_count < MAX_TREE_ENTRIES) {
                strcpy(pending[pending_count].name, name);
                pending[pending_count].is_dir = 0;
                pending[pending_count].hash = entries[i].hash;
                pending[pending_count].mode = entries[i].mode;
                pending_count++;
            }
        }
    }

    for (int i = 0; i < pending_count; i++) {
        if (pending[i].is_dir) {
            char sub_prefix[512];
            snprintf(sub_prefix, sizeof(sub_prefix), "%s%s/", prefix, pending[i].name);
            if (build_tree(entries, count, sub_prefix, &pending[i].hash) != 0) return -1;
        }
        if (tree.count < MAX_TREE_ENTRIES) {
            strcpy(tree.entries[tree.count].name, pending[i].name);
            tree.entries[tree.count].hash = pending[i].hash;
            tree.entries[tree.count].mode = pending[i].mode;
            tree.count++;
        }
    }

    void *data;
    size_t len;
    if (tree_serialize(&tree, &data, &len) != 0) return -1;
    int ret = object_write(OBJ_TREE, data, len, id_out);
    free(data);
    return ret;
}

int tree_from_index(ObjectID *id_out) {
    Index index;
    if (index_load(&index) != 0) return -1;
    return build_tree(index.entries, index.count, "", id_out);
}