package main

import (
	"crypto/rand"
	"fmt"
	"log"
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
	ParseBlkFileInfo("./repacked.blk", false)

}

func ParseBlkFileInfo(filename string, isExtract bool) {
	fh, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer fh.Close()

	b, err := ParseBlb3(fh)
	if err != nil {
		log.Fatal(err)
	}
	if isExtract {
		if err := b.ExtractAllToDir("out_unpack"); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("---- Blb3 Header ----\n")
	fmt.Printf("HeaderSize            = %d (0x%X)\n", b.Header.HeaderSize, b.Header.HeaderSize)
	fmt.Printf("LastUncompressedSize  = %d (0x%X)\n", b.Header.LastUncompressedSize, b.Header.LastUncompressedSize)
	fmt.Printf("BlobOffset            = %d (0x%X)\n", b.Header.BlobOffset, uint32(b.Header.BlobOffset))
	fmt.Printf("BlobSize              = %d (0x%X)\n", b.Header.BlobSize, b.Header.BlobSize)
	fmt.Printf("CompressionType       = %d\n", b.Header.CompressionType)
	fmt.Printf("BlockPow              = %d\n", b.Header.BlockPow)
	fmt.Printf("BlockSize             = %d (0x%X)\n", b.Header.BlockSize, b.Header.BlockSize)
	fmt.Printf("BlocksInfoCount       = %d\n", b.Header.BlocksInfoCount)
	fmt.Printf("NodesCount            = %d\n", b.Header.NodesCount)
	fmt.Printf("BlocksInfoOffsetAbs   = %d (0x%X)\n", b.Header.BlocksInfoOffsetAbs, b.Header.BlocksInfoOffsetAbs)
	fmt.Printf("NodesInfoOffsetAbs    = %d (0x%X)\n", b.Header.NodesInfoOffsetAbs, b.Header.NodesInfoOffsetAbs)
	fmt.Printf("FlagInfoOffsetAbs     = %d (0x%X)\n", b.Header.FlagInfoOffsetAbs, b.Header.FlagInfoOffsetAbs)
	fmt.Printf("----------------------\n")

}

// RepackBlkFile xxx.blk CNRELWin https://sdk.yuanshen.org.cn/query_region_list 5
func RepackBlkFile(filename, channelName, dispatchURL string, keyID int) {
	fh, err := os.Open(filename)
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
			ChannelName: channelName,
			DispatchURL: dispatchURL,
			KeyID:       keyID,
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
