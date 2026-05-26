// Positive fixtures for the C taint engine. Each function flows an
// untrusted source into a taint sink. The taint rules must fire
// exactly once per function.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sqlite3.h>

// --- c/taint-format-string ---------------------------------------------------

// 1. getenv -> printf (format string)
void format_string_getenv() {
    char *input = getenv("USER_INPUT");
    printf(input);
}

// 2. fgets -> fprintf (format string)
void format_string_fgets() {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    fprintf(stderr, buf);
}

// --- c/taint-command-injection -----------------------------------------------

// 3. getenv -> system
void cmd_injection_getenv() {
    char *cmd = getenv("CMD");
    system(cmd);
}

// 4. recv -> popen
void cmd_injection_recv(int sockfd) {
    char buf[1024];
    recv(sockfd, buf, sizeof(buf), 0);
    popen(buf, "r");
}

// 5. argv -> execv
int cmd_injection_argv(int argc, char **argv) {
    execv(argv[1], NULL);
    return 0;
}

// 6. fgets -> system via transitive assignment
void cmd_injection_transitive() {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    char *cmd = buf;
    system(cmd);
}

// --- c/taint-buffer-overflow ------------------------------------------------

// 7. fgets -> strcpy
void buffer_overflow_strcpy() {
    char input[256];
    char dest[64];
    fgets(input, sizeof(input), stdin);
    strcpy(dest, input);
}

// 8. recv -> strcat
void buffer_overflow_strcat(int sockfd) {
    char buf[1024];
    char dest[64];
    recv(sockfd, buf, sizeof(buf), 0);
    strcat(dest, buf);
}

// 9. getenv -> memcpy
void buffer_overflow_memcpy() {
    char *input = getenv("DATA");
    char dest[64];
    memcpy(dest, input, strlen(input));
}

// --- c/taint-sql-injection --------------------------------------------------

// 10. getenv -> sqlite3_exec via sprintf
void sql_injection_sqlite(sqlite3 *db) {
    char *input = getenv("QUERY");
    char query[512];
    sprintf(query, "SELECT * FROM users WHERE name = '%s'", input);
    sqlite3_exec(db, query, NULL, NULL, NULL);
}

// 11. fgets -> mysql_query via sprintf
void sql_injection_mysql(void *conn) {
    char buf[256];
    char query[512];
    fgets(buf, sizeof(buf), stdin);
    sprintf(query, "DELETE FROM items WHERE id = %s", buf);
    mysql_query(conn, query);
}
