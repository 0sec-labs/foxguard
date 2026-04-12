// Test fixture for the Go Semgrep taint YAML bridge.
// Each function should produce exactly one finding: c.Query/c.Param/r.URL → exec.Command().
package main

import (
	"net/http"
	"os/exec"
)

// 1. Gin c.Query → exec.Command
func ginQueryToExec(c *gin.Context) {
	name := c.Query("name")
	exec.Command(name)
}

// 2. Gin c.Param → exec.Command
func ginParamToExec(c *gin.Context) {
	id := c.Param("id")
	exec.Command(id)
}

// 3. net/http r.URL → exec.Command via local
func httpUrlToExec(w http.ResponseWriter, r *http.Request) {
	path := r.URL
	cmd := path
	exec.Command(cmd)
}
