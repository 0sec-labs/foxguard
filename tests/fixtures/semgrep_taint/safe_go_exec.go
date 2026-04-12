// Safe fixture: no taint should flow into exec.Command().
package main

import (
	"os/exec"
)

func safeExec() {
	exec.Command("ls", "-la")
}

func noExec(c *gin.Context) {
	name := c.Query("name")
	println(name)
}
