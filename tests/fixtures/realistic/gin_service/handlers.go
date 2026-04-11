// Multi-file Gin fixture (issue #48). Companion to django_shop/ and
// express_api/. handlers.go holds request sources; store.go holds the
// dangerous sinks. The current Go taint engine is intraprocedural +
// same-file interprocedural, so cross-file flows from handlers → store
// do not fire yet. Issue #46 will fix that and this fixture's expected
// counts will need to be updated.
//
// Hand-counted expected findings under the current engine:
//   go/taint-command-injection : 1   (in-file runCmd)
//   go/taint-ssrf              : 1   (in-file proxyFetch)

package gin_service

import (
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

// In-file flow — should fire today.
func runCmd(c *gin.Context) {
	// go/taint-command-injection — source and sink in the same function
	cmd := c.Query("cmd")
	_, _ = exec.Command(cmd).Output()
	c.String(http.StatusOK, "ok")
}

// In-file SSRF — should fire today.
func proxyFetch(c *gin.Context) {
	// go/taint-ssrf
	url := c.Query("url")
	_, _ = http.Get(url)
	c.String(http.StatusOK, "ok")
}

// Cross-file flow — should fire after #46 lands.
func search(c *gin.Context) {
	name := c.Query("name")
	rows := runQuery(name)
	c.JSON(http.StatusOK, rows)
}

// NEAR-MISS — literal, no source
func healthz(c *gin.Context) {
	_, _ = exec.Command("uptime").Output()
	c.String(http.StatusOK, "ok")
}

func Register(r *gin.Engine) {
	r.GET("/run", runCmd)
	r.GET("/fetch", proxyFetch)
	r.GET("/search", search)
	r.GET("/healthz", healthz)
}
