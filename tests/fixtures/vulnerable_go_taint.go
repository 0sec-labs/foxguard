// Positive fixtures for the Go taint engine. Each handler flows an
// untrusted source into a taint sink. The taint rules must fire
// exactly once per handler; the conservative go/no-* counterparts
// coexist wherever their pattern also matches.
package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os/exec"
)

// ─── go/taint-command-injection ───────────────────────────────────────────

// 1. Gin *Context.Query → exec.Command
func ginQueryToExec(c *gin.Context) {
	name := c.Query("name")
	exec.Command(name)
}

// 2. net/http Request.FormValue → exec.CommandContext
func httpFormValueToExec(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")
	exec.CommandContext(nil, cmd)
}

// 3. Echo Context.QueryParam → exec.Command
func echoQueryParamToExec(c echo.Context) error {
	name := c.QueryParam("name")
	exec.Command(name)
	return nil
}

// 4. Fiber Ctx.Query → exec.Command via fmt.Sprintf wrapping
func fiberQueryToExec(c *fiber.Ctx) error {
	cmd := fmt.Sprintf("echo %s", c.Query("name"))
	exec.Command(cmd)
	return nil
}

// 5. os.Getenv → exec.Command
func envToExec() {
	target := os.Getenv("TARGET")
	exec.Command(target)
}

// ─── go/taint-sql-injection ───────────────────────────────────────────────

// 6. gin Context.Param → db.Query via string concat
func ginParamToDbQuery(c *gin.Context, db *sql.DB) {
	id := c.Param("id")
	db.Query("SELECT * FROM users WHERE id = " + id)
}

// 7. net/http r.URL.Query().Get → tx.Exec via fmt.Sprintf
func httpQueryToTxExec(w http.ResponseWriter, r *http.Request, tx *sql.Tx) {
	name := r.URL.Query().Get("name")
	tx.Exec(fmt.Sprintf("DELETE FROM users WHERE name = '%s'", name))
}

// 8. gin Context.PostForm → db.QueryRow
func ginPostFormToQueryRow(c *gin.Context, db *sql.DB) {
	email := c.PostForm("email")
	db.QueryRow("SELECT id FROM users WHERE email = " + email)
}

// ─── go/taint-ssti ────────────────────────────────────────────────────────

// 12. gin Context.Query → template.Parse
func ginQueryToTemplateParse(c *gin.Context) {
	tmplStr := c.Query("template")
	t := template.New("page")
	t.Parse(tmplStr)
}

// ─── go/taint-xpath-injection ─────────────────────────────────────────────

// 13. net/http r.FormValue → xmlpath.Compile
func httpFormValueToXpathCompile(w http.ResponseWriter, r *http.Request) {
	expr := r.FormValue("xpath")
	xmlpath.Compile(expr)
}

// ─── go/taint-ldap-injection ──────────────────────────────────────────────

// 14. gin Context.Query → ldap.NewSearchRequest
func ginQueryToLdapSearch(c *gin.Context) {
	filter := c.Query("filter")
	ldap.NewSearchRequest("dc=example,dc=com", 2, 0, 0, 0, false, filter, nil, nil)
}

// ─── go/taint-ssrf ────────────────────────────────────────────────────────

// 9. gin Context.Query → http.Get
func ginQueryToHttpGet(c *gin.Context) {
	url := c.Query("url")
	http.Get(url)
}

// 10. net/http r.FormValue → http.NewRequest
func httpFormValueToNewRequest(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("target")
	http.NewRequest("GET", target, nil)
}

// 11. os.Getenv → http.PostForm
func envToHttpPostForm() {
	url := os.Getenv("WEBHOOK_URL")
	http.PostForm(url, nil)
}

// ─── go/taint-log-injection ──────────────────────────────────────────────

// 15. gin Context.Query → log.Printf
func ginQueryToLogPrintf(c *gin.Context) {
	name := c.Query("name")
	log.Printf("user: %s", name)
}

// ─── go/taint-nosql-injection ────────────────────────────────────────────

// 16. gin Context.Query → collection.Find
func ginQueryToMongoFind(c *gin.Context, collection *mongo.Collection) {
	filter := c.Query("filter")
	collection.Find(context.TODO(), filter)
}
