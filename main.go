package main

import (
	"log"
	"os"
)

func main() {
	fh, err := os.Open("./20527480.blk")
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
