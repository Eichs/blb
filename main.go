package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/pierrec/lz4/v4"
)

func main() {
	fh, err := os.Open("./repacked.blk")
	if err != nil {
		log.Fatal(err)
	}
	defer fh.Close()

	b, err := ParseBlb3(fh)
	if err != nil {
		log.Fatal(err)
	}

	if err := b.ExtractAllToDir("out_unpack"); err != nil {
		log.Fatal(err)
	}

}
