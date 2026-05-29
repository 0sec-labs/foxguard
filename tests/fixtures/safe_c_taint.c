// Negative fixtures for the C taint engine. Every function either uses
// literal arguments, has its taint killed by sanitization, or avoids
// the dangerous pattern. No c/taint-* rule may fire.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>

// --- Safe format string usage ------------------------------------------------

// Format string is a literal, so even though the data arg is tainted,
// the format string itself is not.
void safe_printf_literal_format() {
    char *input = getenv("USER_INPUT");
    printf("%s\n", input);
}

void safe_fprintf_literal_format() {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    fprintf(stderr, "Got: %s\n", buf);
}

// snprintf is bounds-safe (truncates to its size argument), so a tainted
// format there is not a Critical format-string finding (T15).
void safe_snprintf_untrusted_format() {
    char *fmt = getenv("FMT");
    char buf[64];
    snprintf(buf, sizeof(buf), fmt, "x");
}

// sprintf with a tainted format must not propagate taint into `dest` such
// that a downstream printf with a literal format re-fires (no double-fire).
void safe_sprintf_no_double_fire() {
    char *fmt = getenv("FMT");
    char dest[64];
    sprintf(dest, fmt, "x");
    printf("%s", dest);
}

// --- Safe command execution --------------------------------------------------

// Literal command, no tainted input.
void safe_system_literal() {
    system("ls -la");
}

// exec* command injection is controlled by the pathname (first argument).
// Here the path is a string literal; the tainted data argument that becomes
// argv[1] of the child process is not command injection (T13).
void safe_execv_literal_path() {
    char *arg = getenv("ARG");
    char *argv_child[] = {"cat", arg, NULL};
    execv("/bin/cat", argv_child);
}

void safe_execl_literal_path() {
    char *arg = getenv("ARG");
    execl("/bin/ls", "ls", "-la", arg, NULL);
}

// --- Safe buffer operations --------------------------------------------------

// Using strncpy (bounds-checked) as a sanitizer.
void safe_strncpy_sanitized() {
    char buf[256];
    char dest[64];
    fgets(buf, sizeof(buf), stdin);
    char *safe = strncpy(dest, buf, sizeof(dest) - 1);
    strcpy(dest, safe);
}

// Using strlcpy as a sanitizer.
void safe_strlcpy_sanitized() {
    char buf[256];
    char dest[64];
    fgets(buf, sizeof(buf), stdin);
    strlcpy(dest, buf, sizeof(dest));
}

// memcpy with a constant size is bounded -- not a buffer overflow even if
// the source is tainted (T14).
void safe_memcpy_literal_size() {
    char *src = getenv("DATA");
    char buf[64];
    memcpy(buf, src, 64);
}

// memcpy with a sizeof() size argument is likewise bounded (T14).
void safe_memcpy_sizeof_size() {
    char *src = getenv("DATA");
    char buf[64];
    memcpy(buf, src, sizeof(buf));
}

// --- Safe SQL usage ----------------------------------------------------------

// Literal query, no tainted input.
void safe_sqlite_literal(sqlite3 *db) {
    sqlite3_exec(db, "SELECT 1", NULL, NULL, NULL);
}
