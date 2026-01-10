package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

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

// -------------------- 新增：仅解析 blb headerBytes 的头部字段 --------------------

type Blb3HeaderBytes struct {
	HeaderSize           uint32 // C# m_Header.size
	LastUncompressedSize uint32

	BlobOffset int32
	BlobSize   uint32

	CompressionType CompressionType
	BlockPow        byte
	BlockSize       uint32 // 1 << BlockPow

	BlocksInfoCount int32
	NodesCount      int32

	BlocksInfoOffsetAbs int64 // 相对 headerBytes 起始的“绝对偏移”
	NodesInfoOffsetAbs  int64
	FlagInfoOffsetAbs   int64
}

// -------------------- 文件结构 --------------------

type Blb3File struct {
	Offset int64

	HeaderKey   []byte // 16 bytes header used as key material
	HeaderBytes []byte // 解密后内容
	Header      *Blb3HeaderBytes

	Blocks []StorageBlock
	Nodes  []Node

	BlocksStream []byte // 解出来的 blocks 全部拼起来的“解压后块流”
}

// -------------------- Reader --------------------

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
		// 可选：防止坏数据导致无限长
		if len(out) > 1<<20 {
			return "", fmt.Errorf("string too long (no null terminator?)")
		}
	}
}

// -------------------- ParseBlb3（完整：包含解析 headerBytes 字段） --------------------

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
	if _, err := br.ReadU32(); err != nil { //对应5
		return nil, err
	}

	headerKey, err := br.ReadBytes(16)
	if err != nil {
		return nil, err
	}
	f.HeaderKey = headerKey

	headerBytes, err := br.ReadBytes(int(size))
	if err != nil {
		return nil, err
	}
	f.HeaderBytes = headerBytes

	// 关键：解密 headerBytes
	Decrypt(f.HeaderKey, f.HeaderBytes)

	// 完整解析 headerBytes：header字段 + blocks + nodes
	hdr, blocks, nodes, err := parseHeaderBytesAll(f.HeaderBytes)
	if err != nil {
		return nil, err
	}
	f.Header = hdr
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

// -------------------- 解析 headerBytes（对应 C# ReadBlocksInfoAndDirectory） --------------------

func parseHeaderBytesAll(headerBytes []byte) (*Blb3HeaderBytes, []StorageBlock, []Node, error) {
	br := newBinReader(bytes.NewReader(headerBytes))

	h := &Blb3HeaderBytes{}
	var err error

	// m_Header.size
	if h.HeaderSize, err = br.ReadU32(); err != nil {
		return nil, nil, nil, err
	}
	// lastUncompressedSize
	if h.LastUncompressedSize, err = br.ReadU32(); err != nil {
		return nil, nil, nil, err
	}

	// reader.Position += 4;
	if err := br.Skip(4); err != nil {
		return nil, nil, nil, err
	}

	// blobOffset / blobSize
	if h.BlobOffset, err = br.ReadI32(); err != nil {
		return nil, nil, nil, err
	}
	if h.BlobSize, err = br.ReadU32(); err != nil {
		return nil, nil, nil, err
	}

	// compressionType
	compByte, err := br.ReadU8()
	if err != nil {
		return nil, nil, nil, err
	}
	h.CompressionType = CompressionType(compByte)

	// blockPow / blockSize
	b, err := br.ReadU8()
	if err != nil {
		return nil, nil, nil, err
	}
	h.BlockPow = b
	h.BlockSize = uint32(1) << h.BlockPow

	// AlignStream()
	if err := br.Align(4); err != nil {
		return nil, nil, nil, err
	}

	// counts
	if h.BlocksInfoCount, err = br.ReadI32(); err != nil {
		return nil, nil, nil, err
	}
	if h.NodesCount, err = br.ReadI32(); err != nil {
		return nil, nil, nil, err
	}

	// offsets：basePos 必须是 “读 Int64 之前”的位置（和 C# 完全一致）
	base := br.Pos()
	rel, err := br.ReadI64()
	if err != nil {
		return nil, nil, nil, err
	}
	h.BlocksInfoOffsetAbs = base + rel

	base = br.Pos()
	rel, err = br.ReadI64()
	if err != nil {
		return nil, nil, nil, err
	}
	h.NodesInfoOffsetAbs = base + rel

	base = br.Pos()
	rel, err = br.ReadI64()
	if err != nil {
		return nil, nil, nil, err
	}
	h.FlagInfoOffsetAbs = base + rel

	// ---------------- blocks ----------------
	if err := br.Seek(h.BlocksInfoOffsetAbs); err != nil {
		return nil, nil, nil, err
	}
	blocks := make([]StorageBlock, 0, h.BlocksInfoCount)
	for i := int32(0); i < h.BlocksInfoCount; i++ {
		csz, err := br.ReadU32()
		if err != nil {
			return nil, nil, nil, err
		}
		usz := h.BlockSize
		if i == h.BlocksInfoCount-1 {
			usz = h.LastUncompressedSize
		}
		blocks = append(blocks, StorageBlock{
			CompressedSize:   csz,
			UncompressedSize: usz,
			Flags:            StorageBlockFlags(h.CompressionType),
		})
	}

	// C#：for (i=count-1; i>0; i--) { blocks[i].compressedSize -= blocks[i-1].compressedSize; flags=... }
	for i := len(blocks) - 1; i > 0; i-- {
		blocks[i].CompressedSize -= blocks[i-1].CompressedSize
		if blocks[i].CompressedSize == blocks[i].UncompressedSize {
			blocks[i].Flags = StorageBlockFlags(CompressionNone)
		} else {
			blocks[i].Flags = StorageBlockFlags(h.CompressionType)
		}
	}

	// ---------------- nodes ----------------
	if err := br.Seek(h.NodesInfoOffsetAbs); err != nil {
		return nil, nil, nil, err
	}
	nodes := make([]Node, 0, h.NodesCount)

	for i := int32(0); i < h.NodesCount; i++ {
		off, err := br.ReadI32()
		if err != nil {
			return nil, nil, nil, err
		}
		sz, err := br.ReadI32()
		if err != nil {
			return nil, nil, nil, err
		}

		// flag：保存当前位置 -> 跳到 flagInfoOffset -> 读 flag -> 回来
		pos := br.Pos()
		if err := br.Seek(h.FlagInfoOffsetAbs); err != nil {
			return nil, nil, nil, err
		}
		flag0, err := br.ReadU32()
		if err != nil {
			return nil, nil, nil, err
		}
		flag := flag0
		if i >= 0x20 {
			flag1, err := br.ReadU32()
			if err != nil {
				return nil, nil, nil, err
			}
			flag = flag1
		}

		// C# 的 (1<<i) 在 i>=32 时会按低 5 位 mask
		bit := uint32(1) << (uint32(i) & 31)
		nodeFlags := uint32(flag&bit) * 4

		if err := br.Seek(pos); err != nil {
			return nil, nil, nil, err
		}

		// pathOffset = (posBeforeReadI64) + rel
		base = br.Pos()
		rel, err = br.ReadI64()
		if err != nil {
			return nil, nil, nil, err
		}
		pathOffset := base + rel

		pos2 := br.Pos()
		if err := br.Seek(pathOffset); err != nil {
			return nil, nil, nil, err
		}
		p, err := br.ReadStringToNull()
		if err != nil {
			return nil, nil, nil, err
		}
		if err := br.Seek(pos2); err != nil {
			return nil, nil, nil, err
		}

		nodes = append(nodes, Node{
			Offset: off,
			Size:   sz,
			Flags:  nodeFlags,
			Path:   p,
		})
	}

	return h, blocks, nodes, nil
}

// -------------------- 读取 blocks + 解密 + LZ4/LZ4HC 解压 --------------------

func readBlocksAndBuildStream(br *binReader, headerKey []byte, blocks []StorageBlock) ([]byte, error) {
	// 预估总解压后大小
	var total int
	for _, b := range blocks {
		total += int(b.UncompressedSize)
	}

	var buf bytes.Buffer
	if total > 0 {
		buf.Grow(total)
	}

	for _, blk := range blocks {
		ct := CompressionType(blk.Flags) // 这里 flags 就是 type
		switch ct {
		case CompressionNone:
			n := int(blk.UncompressedSize)
			raw, err := br.ReadBytes(n)
			if err != nil {
				return nil, err
			}
			Decrypt(headerKey, raw)
			_, _ = buf.Write(raw)

		case CompressionLz4, CompressionLz4HC:
			csz := int(blk.CompressedSize)
			usz := int(blk.UncompressedSize)

			comp, err := br.ReadBytes(csz)
			if err != nil {
				return nil, err
			}
			Decrypt(headerKey, comp)

			dec := make([]byte, usz)
			n, err := lz4.UncompressBlock(comp, dec)
			if err != nil {
				return nil, fmt.Errorf("lz4 decompress failed: %w", err)
			}

			// 更兼容：允许 n < usz（有些实现返回实际写入长度）
			if n != usz {
				if n < 0 || n > usz {
					return nil, fmt.Errorf("lz4 decompressed size invalid: got=%d expected<=%d", n, usz)
				}
				dec = dec[:n]
			}
			_, _ = buf.Write(dec)

		default:
			return nil, fmt.Errorf("unsupported compression type: %d (only None/LZ4/LZ4HC are implemented)", ct)
		}
	}

	return buf.Bytes(), nil
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
func (f *Blb3File) ExtractAllToBytes() (map[string][]byte, error) {
	out := make(map[string][]byte, len(f.Nodes))

	for _, n := range f.Nodes {
		if n.Size < 0 {
			return nil, fmt.Errorf("invalid node size %d for %s", n.Size, n.Path)
		}
		start := int(n.Offset)
		end := start + int(n.Size)
		if start < 0 || end > len(f.BlocksStream) {
			return nil, fmt.Errorf(
				"node out of range: %s offset=%d size=%d stream=%d",
				n.Path, n.Offset, n.Size, len(f.BlocksStream),
			)
		}

		name := filepath.Base(n.Path)
		out[name] = append([]byte(nil), f.BlocksStream[start:end]...)
	}
	return out, nil
}

//打包流程
//u32 HeaderSize                  // 0x4BD
//u32 LastUncompressedSize         // 0x1548
//u32 (skip4 bytes)               // C# Position +=4
//i32 BlobOffset                  // 0
//u32 BlobSize                    // 0
//u8  CompressionType             // 3 = LZ4
//u8  BlockPow                    // 17
//align4
//i32 BlocksInfoCount             // 1
//i32 NodesCount                  // 1
//
//i64 relBlocksInfoOffset   // 计算方式：ABS = (posBeforeReadI64) + rel
//i64 relNodesInfoOffset
//i64 relFlagInfoOffset
//
//// blocksInfo table @ blocksInfoOffsetAbs:
//repeat BlocksInfoCount:
//    u32 cumulativeCompressedSize  // 注意：C# 读的是“累计值”，后面会做差得到每块大小
//
//// nodes table @ nodesInfoOffsetAbs:
//repeat NodesCount:
//    i32 offset
//    i32 size
//    i64 relPathOffset             // ABS = (posBeforeReadI64) + rel
//// path strings @ pathOffsetAbs:
//    "xxx\0"
//
//// flags area @ flagInfoOffsetAbs:
//u32 flagWord0
//u32 flagWord1 (只有 i>=0x20 才会去读第二个)
//node.flags = (flagWord & (1<<(i&31))) * 4

func RepackCABsFromDir(unpackDir, outPath string, headerKey []byte, blockPow byte, comp CompressionType) error {
	if len(headerKey) != 16 {
		return fmt.Errorf("headerKey must be 16 bytes, got=%d", len(headerKey))
	}

	cabPaths, cabNames, err := findAllCABsSorted(unpackDir)
	if err != nil {
		return err
	}
	if len(cabPaths) == 0 {
		return fmt.Errorf("no CAB-* file found in %s", unpackDir)
	}

	// 读取所有 CAB，构建 BlocksStream + Nodes
	var blocksStream bytes.Buffer
	nodes := make([]Node, 0, len(cabPaths))

	var offset int64 = 0
	for i := 0; i < len(cabPaths); i++ {
		data, err := os.ReadFile(cabPaths[i])
		if err != nil {
			return err
		}
		if len(data) == 0 {
			return fmt.Errorf("CAB file is empty: %s", cabPaths[i])
		}

		nodes = append(nodes, Node{
			Offset: int32(offset),
			Size:   int32(len(data)),
			Flags:  0,           // 这里不用直接写，解析时 flags 来自 flagWords
			Path:   cabNames[i], // 只要文件名
		})

		_, _ = blocksStream.Write(data)
		offset += int64(len(data))
	}

	// 先写 blocks（压缩/加密）
	blockSize := 1 << blockPow
	blocksPayload, blocksMeta, lastUnc, err := buildBlocksPayload(blocksStream.Bytes(), headerKey, blockSize, comp)
	if err != nil {
		return err
	}

	// 构建 headerBytes 明文 多node
	hdrPlain, err := buildHeaderBytes(blockPow, comp, uint32(lastUnc), blocksMeta, nodes)
	if err != nil {
		return err
	}

	// headerBytes 加密
	hdrEnc := append([]byte(nil), hdrPlain...)
	Encrypt(headerKey, hdrEnc)

	// 写出最终 blb
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// 文件头
	if _, err := f.Write([]byte{'B', 'l', 'b', 0x03}); err != nil {
		return err
	}
	if err := writeU32LE(f, uint32(len(hdrEnc))); err != nil {
		return err
	}
	// C# reader.ReadUInt32();//5
	if err := writeU32LE(f, 5); err != nil {
		return err
	}
	if _, err := f.Write(headerKey); err != nil {
		return err
	}
	if _, err := f.Write(hdrEnc); err != nil {
		return err
	}

	// blocks 区域（已加密）
	if _, err := f.Write(blocksPayload); err != nil {
		return err
	}

	return nil
}
func RepackCABsFromBytes(cabs map[string][]byte, outPath string, headerKey []byte, blockPow byte, comp CompressionType) error {

	if len(headerKey) != 16 {
		return fmt.Errorf("headerKey must be 16 bytes")
	}
	if len(cabs) == 0 {
		return fmt.Errorf("no CAB data")
	}

	// 排序，保证和原版一致
	names := make([]string, 0, len(cabs))
	for name := range cabs {
		names = append(names, name)
	}
	sort.Strings(names)

	var blocksStream bytes.Buffer
	nodes := make([]Node, 0, len(names))
	var offset int64

	for _, name := range names {
		data := cabs[name]
		if len(data) == 0 {
			return fmt.Errorf("CAB empty: %s", name)
		}

		nodes = append(nodes, Node{
			Offset: int32(offset),
			Size:   int32(len(data)),
			Flags:  0,
			Path:   name,
		})

		blocksStream.Write(data)
		offset += int64(len(data))
	}

	// blocks
	blockSize := 1 << blockPow
	blocksPayload, blocksMeta, lastUnc, err :=
		buildBlocksPayload(blocksStream.Bytes(), headerKey, blockSize, comp)
	if err != nil {
		return err
	}

	// header
	hdrPlain, err := buildHeaderBytes(
		blockPow,
		comp,
		uint32(lastUnc),
		blocksMeta,
		nodes,
	)
	if err != nil {
		return err
	}

	hdrEnc := append([]byte(nil), hdrPlain...)
	Encrypt(headerKey, hdrEnc)

	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// blb header
	f.Write([]byte{'B', 'l', 'b', 0x03})
	writeU32LE(f, uint32(len(hdrEnc)))
	writeU32LE(f, 5)
	f.Write(headerKey)
	f.Write(hdrEnc)
	f.Write(blocksPayload)

	return nil
}

// -------------------- blocks: 压缩/选择 None/加密/拼接 --------------------

func buildBlocksPayload(blocksStream []byte, headerKey []byte, blockSize int, comp CompressionType) (payload []byte, blocks []StorageBlock, lastUnc int, err error) {
	if blockSize <= 0 {
		return nil, nil, 0, fmt.Errorf("invalid blockSize: %d", blockSize)
	}
	total := len(blocksStream)
	if total == 0 {
		return nil, nil, 0, errors.New("blocksStream empty")
	}

	nBlocks := (total + blockSize - 1) / blockSize
	blocks = make([]StorageBlock, 0, nBlocks)

	var out bytes.Buffer

	for bi := 0; bi < nBlocks; bi++ {
		start := bi * blockSize
		end := start + blockSize
		if end > total {
			end = total
		}
		uncomp := blocksStream[start:end]
		usz := len(uncomp)
		if bi == nBlocks-1 {
			lastUnc = usz
		}

		var blkType CompressionType
		var toWrite []byte

		switch comp {
		case CompressionLz4, CompressionLz4HC:
			// 尝试压缩
			maxDst := lz4.CompressBlockBound(usz)
			dst := make([]byte, maxDst)
			n, cErr := lz4.CompressBlock(uncomp, dst, nil)
			if cErr != nil {
				return nil, nil, 0, fmt.Errorf("lz4 compress block %d failed: %w", bi, cErr)
			}
			if n > 0 && n < usz {
				// 压缩有效
				blkType = comp
				toWrite = dst[:n]
			} else {
				// 压不动：写 raw，并标 None（与 C# 解包的判断一致）
				blkType = CompressionNone
				toWrite = append([]byte(nil), uncomp...)
			}

		case CompressionNone:
			blkType = CompressionNone
			toWrite = append([]byte(nil), uncomp...)

		default:
			return nil, nil, 0, fmt.Errorf("unsupported compression type for repack: %d (only None/LZ4/LZ4HC)", comp)
		}

		Encrypt(headerKey, toWrite)

		_, _ = out.Write(toWrite)

		blocks = append(blocks, StorageBlock{
			CompressedSize:   uint32(len(toWrite)),
			UncompressedSize: uint32(usz),
			Flags:            StorageBlockFlags(blkType),
		})
	}

	return out.Bytes(), blocks, lastUnc, nil
}

func buildHeaderBytes(blockPow byte, comp CompressionType, lastUnc uint32, blocks []StorageBlock, nodes []Node) ([]byte, error) {
	if len(nodes) < 1 {
		return nil, fmt.Errorf("no nodes")
	}
	if len(blocks) < 1 {
		return nil, fmt.Errorf("no blocks")
	}

	// 写 headerBytes（明文）
	var buf bytes.Buffer

	// 1) HeaderSize 占位（最后回填）
	headerSizePos := buf.Len()
	_ = writeU32ToBuf(&buf, 0)

	// 2) LastUncompressedSize
	_ = writeU32ToBuf(&buf, lastUnc)

	// 3) skip4 bytes（C# Position +=4）
	_ = writeU32ToBuf(&buf, 0)

	// 4) blobOffset/blobSize（样本为 0）
	_ = writeI32ToBuf(&buf, 0)
	_ = writeU32ToBuf(&buf, 0)

	// 5) compressionType / blockPow
	_ = buf.WriteByte(byte(comp))
	_ = buf.WriteByte(byte(blockPow))

	// 6) align4
	for (buf.Len() & 3) != 0 {
		_ = buf.WriteByte(0)
	}

	// 7) counts
	_ = writeI32ToBuf(&buf, int32(len(blocks)))
	_ = writeI32ToBuf(&buf, int32(len(nodes)))

	// 8) 三个 relOffset 占位（按“写 int64 前 pos”规则回填）
	blocksRelPos := buf.Len()
	_ = writeI64ToBuf(&buf, 0)

	nodesRelPos := buf.Len()
	_ = writeI64ToBuf(&buf, 0)

	flagsRelPos := buf.Len()
	_ = writeI64ToBuf(&buf, 0)

	// 9) blocksInfo：记录 abs + 写累计 compressedSize
	blocksInfoAbs := int64(buf.Len())
	var cum uint32
	for i := 0; i < len(blocks); i++ {
		cum += blocks[i].CompressedSize
		_ = writeU32ToBuf(&buf, cum)
	}

	// 10) nodesInfo：记录 abs + 写 nodes 表（offset/size + relPathOffset 占位）
	nodesInfoAbs := int64(buf.Len())
	nodePathRelPos := make([]int, len(nodes))

	for i := 0; i < len(nodes); i++ {
		_ = writeI32ToBuf(&buf, nodes[i].Offset)
		_ = writeI32ToBuf(&buf, nodes[i].Size)
		nodePathRelPos[i] = buf.Len()
		_ = writeI64ToBuf(&buf, 0) // placeholder
	}

	// 11) flags：记录 abs + 写足够的 flagWords
	flagsAbs := int64(buf.Len())

	// 每 32 个 node 一个 word
	wordCount := (len(nodes) + 31) / 32
	flagWords := make([]uint32, wordCount)

	// 自动：把所有 node 的 bit 都置 1（和你单文件 node0=1 同逻辑）
	for i := 0; i < len(nodes); i++ {
		w := i / 32
		bit := uint32(1) << uint32(i&31)
		flagWords[w] |= bit
	}

	for _, w := range flagWords {
		_ = writeU32ToBuf(&buf, w)
	}

	// 12) string table：逐个写 path (只用文件名) + '\0'，并回填 relPathOffset
	raw := buf.Bytes()

	for i := 0; i < len(nodes); i++ {
		pathAbs := int64(buf.Len())
		// 只要文件名
		name := filepath.Base(nodes[i].Path)
		_, _ = buf.WriteString(name)
		_ = buf.WriteByte(0)

		// rel = pathAbs - posBeforeWriteI64
		posBefore := int64(nodePathRelPos[i])
		rel := pathAbs - posBefore
		patchI64LE(raw, nodePathRelPos[i], rel)
	}

	// ⚠️ buf.Bytes() 可能因为增长而换底层数组，所以重新拿 raw
	raw = buf.Bytes()

	// 13) 回填 3 个 rel offsets（同规则：targetAbs - posBeforeWriteI64）
	patchI64LE(raw, blocksRelPos, blocksInfoAbs-int64(blocksRelPos))
	patchI64LE(raw, nodesRelPos, nodesInfoAbs-int64(nodesRelPos))
	patchI64LE(raw, flagsRelPos, flagsAbs-int64(flagsRelPos))

	// 14) 回填 HeaderSize = len(headerBytes)
	patchU32LE(raw, headerSizePos, uint32(len(raw)))

	return raw, nil
}
func findAllCABsSorted(dir string) (paths []string, names []string, err error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}

	type item struct {
		name string
		path string
	}
	var items []item

	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasPrefix(n, "CAB-") {
			items = append(items, item{
				name: n,
				path: filepath.Join(dir, n),
			})
		}
	}

	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })

	for _, it := range items {
		names = append(names, it.name)
		paths = append(paths, it.path)
	}
	return paths, names, nil
}

func writeU32LE(w io.Writer, v uint32) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	_, err := w.Write(b[:])
	return err
}

func writeU32ToBuf(buf *bytes.Buffer, v uint32) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	_, err := buf.Write(b[:])
	return err
}

func writeI32ToBuf(buf *bytes.Buffer, v int32) error {
	return writeU32ToBuf(buf, uint32(v))
}

func writeI64ToBuf(buf *bytes.Buffer, v int64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(v))
	_, err := buf.Write(b[:])
	return err
}

func patchU32LE(b []byte, pos int, v uint32) {
	binary.LittleEndian.PutUint32(b[pos:pos+4], v)
}

func patchI64LE(b []byte, pos int, v int64) {
	binary.LittleEndian.PutUint64(b[pos:pos+8], uint64(v))
}
