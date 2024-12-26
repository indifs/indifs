# indiFS

[![Go Report Card](https://goreportcard.com/badge/github.com/indifs/indifs)](https://goreportcard.com/report/github.com/indifs/indifs)
[![GoDoc](https://godoc.org/github.com/indifs/indifs?status.svg)](https://godoc.org/github.com/indifs/indifs)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](

Individual Distributed Peer-to-Peer Filesystem for the Decentralized Web

## Overview 

IndiFS is a virtual file system designed for decentralized web applications. It provides a peer-to-peer distributed filesystem with features such as file versioning, merkle proofs, and efficient file part handling.

## Features

- **Distributed File System**: Store and retrieve files across a decentralized network.
- **File Versioning**: Keep track of file versions and changes.
- **Merkle Proofs**: Verify file integrity using merkle proofs.
- **Efficient File Handling**: Handle large files by splitting them into parts.

## Installation

To install the project dependencies, run:

```sh
go get github.com/indifs/indifs
```

## Usage   
```go
package main

import (
	"github.com/indifs/indifs"
	"github.com/indifs/indifs/crypto"
	"github.com/indifs/indifs/database/memdb"
	"log"
	"os"
	"time"
)

func main() {
	prv := crypto.NewPrivateKeyFromSeed("Alice-secret")
	pub := prv.PublicKey()
	src := os.DirFS(os.Getenv("HOME") + "/Alice-Files/")
	ifs, _ := indifs.OpenFS(pub, memdb.New())
	ts := time.Now()

	commit, err := indifs.MakeCommit(ifs, prv, src, ts)
	if err != nil {
		log.Panic(err)
	}
	if err = ifs.Commit(commit); err != nil {
		log.Panic(err)
	}
	return
}

```