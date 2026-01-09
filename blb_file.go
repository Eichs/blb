package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pierrec/lz4/v4"
)

type CompressionType byte

const (
	CompressionNone  CompressionType = 0
	CompressionOodle CompressionType = 1
	CompressionLzma  CompressionType = 2
	CompressionLz4   CompressionType = 3
	CompressionLz4HC CompressionType = 4
)

type Blb3File struct {
	Offset int64

	HeaderKey   []byte // 16 bytes header used as key material
	HeaderBytes []byte
	Blocks      []StorageBlock
	Nodes       []Node

	// 解出来的 blocks 全部拼起来的“解压后块流”
	BlocksStream []byte
}
type StorageBlockFlags uint32

type StorageBlock struct {
	CompressedSize   uint32
	UncompressedSize uint32
	Flags            StorageBlockFlags
}

type Node struct {
	Offset int32
	Size   int32
	Flags  uint32
	Path   string
}
type binReader struct {
	rs    io.ReadSeeker
	order binary.ByteOrder
}

func newBinReader(rs io.ReadSeeker) *binReader {
	return &binReader{rs: rs, order: binary.LittleEndian}
}

func (br *binReader) Pos() int64 {
	p, _ := br.rs.Seek(0, io.SeekCurrent)
	return p
}
func (br *binReader) Seek(pos int64) error {
	_, err := br.rs.Seek(pos, io.SeekStart)
	return err
}
func (br *binReader) Skip(n int64) error {
	_, err := br.rs.Seek(n, io.SeekCurrent)
	return err
}
func (br *binReader) Align(align int64) error {
	if align <= 1 {
		return nil
	}
	p := br.Pos()
	m := p % align
	if m == 0 {
		return nil
	}
	_, err := br.rs.Seek(align-m, io.SeekCurrent)
	return err
}
func (br *binReader) ReadU8() (byte, error) {
	var b [1]byte
	_, err := io.ReadFull(br.rs, b[:])
	return b[0], err
}
func (br *binReader) ReadU32() (uint32, error) {
	var b [4]byte
	_, err := io.ReadFull(br.rs, b[:])
	return br.order.Uint32(b[:]), err
}
func (br *binReader) ReadI32() (int32, error) {
	u, err := br.ReadU32()
	return int32(u), err
}
func (br *binReader) ReadI64() (int64, error) {
	var b [8]byte
	_, err := io.ReadFull(br.rs, b[:])
	return int64(br.order.Uint64(b[:])), err
}
func (br *binReader) ReadBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(br.rs, buf)
	return buf, err
}

// ReadStringToNull(固定长度) —— C# reader.ReadStringToNull(4)
func (br *binReader) ReadStringToNullFixed(n int) (string, error) {
	b, err := br.ReadBytes(n)
	if err != nil {
		return "", err
	}
	// 截断到 0
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			return string(b[:i]), nil
		}
	}
	return string(b), nil
}

// ReadStringToNull(不定长) —— C# reader.ReadStringToNull()
func (br *binReader) ReadStringToNull() (string, error) {
	var out []byte
	var one [1]byte
	for {
		if _, err := io.ReadFull(br.rs, one[:]); err != nil {
			return "", err
		}
		if one[0] == 0 {
			return string(out), nil
		}
		out = append(out, one[0])
	}
}

// ParseBlb3 ：
// 1) 读签名 "Blb\x03"
// 2) 读 size（compressedBlocksInfoSize）
// 3) 跳过 4 bytes（和你 C# reader.ReadUInt32() 一样）
// 4) 读 HeaderKey（16 bytes）
// 5) 读 headerBytes(size)，Decrypt(HeaderKey, headerBytes)
// 6) 解析 blocks/nodes/path
// 7) 读取每个 block：None/LZ4/LZ4HC -> 需要 Decrypt(HeaderKey, blockData) 后写入 blocksStream
func ParseBlb3(rs io.ReadSeeker) (*Blb3File, error) {
	br := newBinReader(rs)
	f := &Blb3File{Offset: br.Pos()}

	sig, err := br.ReadStringToNullFixed(4)
	if err != nil {
		return nil, err
	}
	if sig != "Blb\x03" {
		return nil, fmt.Errorf("not a Blb3 file, sig=%q", sig)
	}

	size, err := br.ReadU32()
	if err != nil {
		return nil, err
	}

	// skip 4 bytes (C# reader.ReadUInt32();)
	if _, err := br.ReadU32(); err != nil {
		return nil, err
	}

	HeaderKey, err := br.ReadBytes(16)
	if err != nil {
		return nil, err
	}
	f.HeaderKey = HeaderKey

	headerBytes, err := br.ReadBytes(int(size))
	if err != nil {
		return nil, err
	}
	f.HeaderBytes = headerBytes

	// 关键：解密 blocksInfo+directory 的 headerBytes
	Decrypt(f.HeaderKey, f.HeaderBytes)

	blocks, nodes, err := parseBlocksInfoAndDirectory(f.HeaderBytes)
	if err != nil {
		return nil, err
	}
	f.Blocks = blocks
	f.Nodes = nodes

	// 读取 blocks + 解压/解密拼出 BlocksStream
	blocksStream, err := readBlocksAndBuildStream(br, f.HeaderKey, f.Blocks)
	if err != nil {
		return nil, err
	}
	f.BlocksStream = blocksStream

	return f, nil
}

// -------------------- 解析 headerBytes（对应 ReadBlocksInfoAndDirectory） --------------------

func parseBlocksInfoAndDirectory(headerBytes []byte) ([]StorageBlock, []Node, error) {
	br := newBinReader(bytes.NewReader(headerBytes))

	_, err := br.ReadU32() // m_Header.size
	if err != nil {
		return nil, nil, err
	}
	lastUncompressedSizeU32, err := br.ReadU32()
	if err != nil {
		return nil, nil, err
	}

	if err := br.Skip(4); err != nil { // reader.Position += 4
		return nil, nil, err
	}

	if _, err := br.ReadI32(); err != nil { // blobOffset
		return nil, nil, err
	}
	if _, err := br.ReadU32(); err != nil { // blobSize
		return nil, nil, err
	}

	compByte, err := br.ReadU8()
	if err != nil {
		return nil, nil, err
	}
	compressionType := CompressionType(compByte)

	b, err := br.ReadU8()
	if err != nil {
		return nil, nil, err
	}
	uncompressedSize := uint32(1) << b

	if err := br.Align(4); err != nil { // reader.AlignStream()
		return nil, nil, err
	}

	blocksInfoCount, err := br.ReadI32()
	if err != nil {
		return nil, nil, err
	}
	nodesCount, err := br.ReadI32()
	if err != nil {
		return nil, nil, err
	}

	//basePos 必须是 “读 Int64 之前”的位置
	base := br.Pos()
	rel, err := br.ReadI64()
	if err != nil {
		return nil, nil, err
	}
	blocksInfoOffset := base + rel

	base = br.Pos()
	rel, err = br.ReadI64()
	if err != nil {
		return nil, nil, err
	}
	nodesInfoOffset := base + rel

	base = br.Pos()
	rel, err = br.ReadI64()
	if err != nil {
		return nil, nil, err
	}
	flagInfoOffset := base + rel

	// blocks
	if err := br.Seek(blocksInfoOffset); err != nil {
		return nil, nil, err
	}
	blocks := make([]StorageBlock, 0, blocksInfoCount)
	for i := int32(0); i < blocksInfoCount; i++ {
		csz, err := br.ReadU32()
		if err != nil {
			return nil, nil, err
		}
		usz := uncompressedSize
		if i == blocksInfoCount-1 {
			usz = lastUncompressedSizeU32
		}
		blocks = append(blocks, StorageBlock{
			CompressedSize:   csz,
			UncompressedSize: usz,
			Flags:            StorageBlockFlags(compressionType),
		})
	}

	for i := len(blocks) - 1; i > 0; i-- {
		blocks[i].CompressedSize -= blocks[i-1].CompressedSize
		if blocks[i].CompressedSize == blocks[i].UncompressedSize {
			blocks[i].Flags = StorageBlockFlags(CompressionNone)
		} else {
			blocks[i].Flags = StorageBlockFlags(compressionType)
		}
	}

	// nodes
	if err := br.Seek(nodesInfoOffset); err != nil {
		return nil, nil, err
	}
	nodes := make([]Node, 0, nodesCount)

	for i := int32(0); i < nodesCount; i++ {
		off, err := br.ReadI32()
		if err != nil {
			return nil, nil, err
		}
		sz, err := br.ReadI32()
		if err != nil {
			return nil, nil, err
		}

		// flag
		pos := br.Pos()
		if err := br.Seek(flagInfoOffset); err != nil {
			return nil, nil, err
		}
		flag0, err := br.ReadU32()
		if err != nil {
			return nil, nil, err
		}
		flag := flag0
		if i >= 0x20 {
			flag1, err := br.ReadU32()
			if err != nil {
				return nil, nil, err
			}
			flag = flag1
		}
		nodeFlags := uint32(flag&(1<<uint32(i))) * 4

		if err := br.Seek(pos); err != nil {
			return nil, nil, err
		}

		//pathOffset = (posBeforeReadI64) + rel
		base = br.Pos()
		rel, err = br.ReadI64()
		if err != nil {
			return nil, nil, err
		}
		pathOffset := base + rel

		pos2 := br.Pos()
		if err := br.Seek(pathOffset); err != nil {
			return nil, nil, err
		}
		p, err := br.ReadStringToNull()
		if err != nil {
			return nil, nil, err
		}
		if err := br.Seek(pos2); err != nil {
			return nil, nil, err
		}

		nodes = append(nodes, Node{
			Offset: off,
			Size:   sz,
			Flags:  nodeFlags,
			Path:   p,
		})
	}

	return blocks, nodes, nil
}

// -------------------- 读取 blocks + 解密 + LZ4/LZ4HC 解压 --------------------

func readBlocksAndBuildStream(br *binReader, HeaderKey []byte, blocks []StorageBlock) ([]byte, error) {
	// 预估总解压后大小
	var total int
	for _, b := range blocks {
		total += int(b.UncompressedSize)
	}
	out := make([]byte, 0, total)

	for _, blk := range blocks {
		ct := CompressionType(blk.Flags) //  flags & mask；这里 flags 就是 type（和原逻辑一致）
		switch ct {
		case CompressionNone:
			// 读 uncompressedSize bytes，Decrypt(HeaderKey, buffer)，直接 append
			n := int(blk.UncompressedSize)
			buf, err := br.ReadBytes(n)
			if err != nil {
				return nil, err
			}
			Decrypt(HeaderKey, buf)
			out = append(out, buf...)

		case CompressionLz4, CompressionLz4HC:
			// 读 compressedSize bytes -> Decrypt -> LZ4 解压成 uncompressedSize
			csz := int(blk.CompressedSize)
			usz := int(blk.UncompressedSize)

			comp, err := br.ReadBytes(csz)
			if err != nil {
				return nil, err
			}
			Decrypt(HeaderKey, comp)

			dec := make([]byte, usz)
			// 这里用 lz4.UncompressBlock（适用于 block 格式，和 C# 的 LZ4.Instance.Decompress 对应）
			n, err := lz4.UncompressBlock(comp, dec)
			if err != nil {
				return nil, fmt.Errorf("lz4 decompress failed: %w", err)
			}
			if n != usz {
				return nil, fmt.Errorf("lz4 decompressed size mismatch: got=%d expected=%d", n, usz)
			}
			out = append(out, dec...)

		default:
			return nil, fmt.Errorf("unsupported compression type: %d (only None/LZ4/LZ4HC are implemented)", ct)
		}
	}
	return out, nil
}

// -------------------- 抽取文件（对应 ReadFiles） --------------------

func (f *Blb3File) ExtractAllToDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, n := range f.Nodes {
		if n.Size < 0 {
			return fmt.Errorf("invalid node size %d for %s", n.Size, n.Path)
		}
		start := int(n.Offset)
		end := start + int(n.Size)
		if start < 0 || end > len(f.BlocksStream) {
			return fmt.Errorf("node out of range: %s offset=%d size=%d stream=%d",
				n.Path, n.Offset, n.Size, len(f.BlocksStream))
		}

		name := filepath.Base(n.Path)
		outPath := filepath.Join(dir, name)
		if err := os.WriteFile(outPath, f.BlocksStream[start:end], 0o644); err != nil {
			return err
		}
	}
	return nil
}
