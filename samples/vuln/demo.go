package main

import (
	"os/exec"
	"crypto/md5"
	"database/sql"
	"math/rand"
)

func run(cmd string, db *sql.DB) {
	exec.Command(cmd)
	md5.Sum([]byte("x"))
	db.Query("SELECT * FROM t WHERE id = " + cmd)
	rand.Int()
	password := "hunter2"
}