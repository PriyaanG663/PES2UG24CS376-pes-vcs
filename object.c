// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <errno.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

// Compute SHA-256 hash of data, store in id_out.
// Returns 0 on success, -1 on error.
int compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    if (EVP_DigestUpdate(ctx, data, len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    if (EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);
    return 0;
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    const char *type_strs[] = {"blob", "tree", "commit"};
    const char *type_str = type_strs[type];

    char header[256];
    snprintf(header, sizeof(header), "%s %zu", type_str, len);
    size_t header_len = strlen(header) + 1; // include \0

    size_t full_len = header_len + len;
    void *full_data = malloc(full_len);
    if (!full_data) return -1;

    memcpy(full_data, header, header_len);
    memcpy((char *)full_data + header_len, data, len);

    if (compute_hash(full_data, full_len, id_out) != 0) {
        free(full_data);
        return -1;
    }
    // If object already exists, no need to write (dedupe)
    if (object_exists(id_out)) {
        free(full_data);
        return 0;
    }

    char path[512];
    object_path(id_out, path, sizeof(path));

    char shard_dir[512];
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);
    // Ensure .pes/objects and shard directory exist
    if (mkdir(OBJECTS_DIR, 0755) != 0 && errno != EEXIST) {
        free(full_data);
        return -1;
    }
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    if (mkdir(shard_dir, 0755) != 0 && errno != EEXIST) {
        free(full_data);
        return -1;
    }

    char temp_path[1024];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    int fd = open(temp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd == -1) {
        free(full_data);
        return -1;
    }

    ssize_t wrote = write(fd, full_data, full_len);
    if (wrote != (ssize_t)full_len) {
        close(fd);
        unlink(temp_path);
        free(full_data);
        return -1;
    }

    // Ensure data is flushed to disk
    if (fsync(fd) != 0) {
        close(fd);
        unlink(temp_path);
        free(full_data);
        return -1;
    }

    close(fd);

    // Atomically move into place
    if (rename(temp_path, path) == -1) {
        unlink(temp_path);
        free(full_data);
        return -1;
    }

    // fsync the shard directory to persist the rename
    int dfd = open(shard_dir, O_DIRECTORY | O_RDONLY);
    if (dfd != -1) {
        fsync(dfd);
        close(dfd);
    }

    free(full_data);
    return 0;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    size_t file_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    void *file_data = malloc(file_len);
    if (!file_data) {
        fclose(f);
        return -1;
    }

    if (fread(file_data, 1, file_len, f) != file_len) {
        free(file_data);
        fclose(f);
        return -1;
    }
    fclose(f);

    char *null_pos = memchr(file_data, '\0', file_len);
    if (!null_pos) {
        free(file_data);
        return -1;
    }

    size_t header_len = null_pos - (char *)file_data;
    char header[256];
    memcpy(header, file_data, header_len);
    header[header_len] = '\0';

    char type_str[10];
    size_t size_val;
    if (sscanf(header, "%s %zu", type_str, &size_val) != 2) {
        free(file_data);
        return -1;
    }

    ObjectType type;
    if (strcmp(type_str, "blob") == 0) type = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0) type = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) type = OBJ_COMMIT;
    else {
        free(file_data);
        return -1;
    }

    size_t data_start = header_len + 1;
    if (data_start + size_val != file_len) {
        free(file_data);
        return -1;
    }

    void *data = malloc(size_val);
    if (!data) {
        free(file_data);
        return -1;
    }
    memcpy(data, (char *)file_data + data_start, size_val);

    // Verify hash
    ObjectID computed;
    if (compute_hash(file_data, file_len, &computed) != 0) {
        free(data);
        free(file_data);
        return -1;
    }
    // Ensure the computed hash matches the requested id
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(data);
        free(file_data);
        return -1;
    }

    free(file_data);
    *type_out = type;
    *data_out = data;
    *len_out = size_val;
    return 0;
}
