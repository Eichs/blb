package main

import (
	"crypto/rand"
	"os"
)

func RandomHeaderKey16() []byte {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}
func main() {
	fh, err := os.Open("./20527480.blk")
	if err != nil {
		panic(err)
	}

	b, err := ParseBlb3(fh)
	cabs, err := b.ExtractAllToBytes()
	if err != nil {
		panic(err)
	}

	for name, data := range cabs {
		newData, err := PatchCABBytes(name, data, ConfigPatch{
			ChannelName: "hello mihoyo",
			DispatchURL: "https://dispatchosglobal.yuanshen.com/query_region_list",
			KeyID:       5,
		})
		if err != nil {
			panic(err)
		}
		cabs[name] = newData
	}
	headerKey := RandomHeaderKey16()
	err = RepackCABsFromBytes(
		cabs,
		"repacked.blk",
		headerKey,
		17,
		CompressionLz4,
	)
	if err != nil {
		panic(err)
	}
}
