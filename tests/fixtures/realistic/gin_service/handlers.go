// Multi-file Gin fixture (issue #48). Companion to django_shop/ and
// express_api/. handlers.go holds request sources; store.go holds the
// dangerous sinks. Cross-file taint analysis (issue #46) resolves
// same-package function calls, so runQuery(name) in search() flows
// through to db.Query in store.go.
//
// Hand-counted expected findings:
//   go/taint-command-injection : 1   (in-file closure in Register)
//   go/taint-sql-injection     : 1   (cross-file: search → runQuery)
//   go/taint-ssrf              : 1   (in-file proxyFetch)

package gin_service

import (
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

// In-file SSRF — should fire today (named function form).
func proxyFetch(c *gin.Context) {
	// go/taint-ssrf
	url := c.Query("url")
	_, _ = http.Get(url)
	c.String(http.StatusOK, "ok")
}

// Cross-file flow — fires via same-package taint resolution (#46).
func search(c *gin.Context) {
	name := c.Query("name")
	rows := runQuery(name)
	c.JSON(http.StatusOK, rows)
}

func Register(r *gin.Engine) {
	// In-file flow as a closure — should fire today (issue #55).
	// go/taint-command-injection — source and sink in the same closure
	r.GET("/run", func(c *gin.Context) {
		cmd := c.Query("cmd")
		_, _ = exec.Command(cmd).Output()
		c.String(http.StatusOK, "ok")
	})
	r.GET("/fetch", proxyFetch)
	r.GET("/search", search)
	// NEAR-MISS — literal, no source
	r.GET("/healthz", func(c *gin.Context) {
		_, _ = exec.Command("uptime").Output()
		c.String(http.StatusOK, "ok")
	})
}
