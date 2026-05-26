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

// --- Safe command execution --------------------------------------------------

// Literal command, no tainted input.
void safe_system_literal() {
    system("ls -la");
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

// --- Safe SQL usage ----------------------------------------------------------

// Literal query, no tainted input.
void safe_sqlite_literal(sqlite3 *db) {
    sqlite3_exec(db, "SELECT 1", NULL, NULL, NULL);
}
