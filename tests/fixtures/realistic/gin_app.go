// Small realistic Gin service used for end-to-end validation of the
// Go taint engine. Contains three intentional vulnerabilities:
//
//   1. go/taint-command-injection — runCmd handler
//   2. go/taint-sql-injection     — getUser handler
//   3. go/taint-ssrf               — proxyFetch handler
//
// Plus one safe handler (`health`) that must not produce any
// go/taint-* findings.
package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

type Server struct {
	db *sql.DB
}

func NewServer(db *sql.DB) *Server {
	return &Server{db: db}
}

func (s *Server) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Vulnerable: c.Query("cmd") → exec.Command
func (s *Server) runCmd(c *gin.Context) {
	cmd := c.Query("cmd")
	out, err := exec.Command(cmd).Output()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.String(http.StatusOK, string(out))
}

// Vulnerable: c.Param("id") → db.Query via fmt.Sprintf
func (s *Server) getUser(c *gin.Context) {
	id := c.Param("id")
	query := fmt.Sprintf("SELECT name, email FROM users WHERE id = %s", id)
	rows, err := s.db.Query(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// Vulnerable: c.Query("url") → http.Get
func (s *Server) proxyFetch(c *gin.Context) {
	url := c.Query("url")
	resp, err := http.Get(url)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	c.JSON(http.StatusOK, gin.H{"status": resp.Status})
}

func main() {
	db, _ := sql.Open("sqlite3", ":memory:")
	s := NewServer(db)

	r := gin.Default()
	r.GET("/health", s.health)
	r.GET("/run", s.runCmd)
	r.GET("/users/:id", s.getUser)
	r.GET("/fetch", s.proxyFetch)
	r.Run(":8080")
}
