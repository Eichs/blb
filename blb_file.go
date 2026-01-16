package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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
	startOff := br.Pos()
	f := &Blb3File{Offset: startOff}

	// ---------- 0) 文件总长 ----------
	endPos, _ := rs.Seek(0, io.SeekEnd)
	_, _ = rs.Seek(startOff, io.SeekStart)
	fileSize := endPos - startOff

	// ---------- 1) sig ----------
	sig, err := br.ReadStringToNullFixed(4)
	if err != nil {
		return nil, err
	}
	if sig != "Blb\x03" {
		return nil, fmt.Errorf("not a Blb3 file, sig=%q", sig)
	}

	// ---------- 2) blocksInfoSize ----------
	sizeU32, err := br.ReadU32()
	if err != nil {
		return nil, err
	}
	size := int64(sizeU32)

	// ---------- 3) outerFlag (skip) ----------
	outerFlag, err := br.ReadU32()
	if err != nil {
		return nil, err
	}

	// ---------- 4) headerKey ----------
	headerKey, err := br.ReadBytes(16)
	if err != nil {
		return nil, err
	}
	f.HeaderKey = headerKey

	// ---------- 5) size 合法性检查 ----------
	// 至少要能容纳固定头 (56 bytes 起步)；也别大于文件剩余
	cur := br.Pos()
	remain := (startOff + fileSize) - cur
	if size < 56 {
		return nil, fmt.Errorf("blocksInfoSize too small: %d (<56). outerFlag=0x%X key=%s",
			size, outerFlag, hex.EncodeToString(headerKey))
	}
	if size > remain {
		return nil, fmt.Errorf("blocksInfoSize too large: %d, remain=%d (fileSize=%d). outerFlag=0x%X",
			size, remain, fileSize, outerFlag)
	}

	// ---------- 6) 读 headerBytes(密文) ----------
	headerBytesEnc, err := br.ReadBytes(int(size))
	if err != nil {
		return nil, err
	}
	f.HeaderBytes = headerBytesEnc

	// 额外：打印密文前 64 字节（不泄露就不管了，反正你自己用）
	{
		n := 64
		if len(headerBytesEnc) < n {
			n = len(headerBytesEnc)
		}
		fmt.Printf("[BLB3] fileSize=%d start=0x%X blocksInfoSize=%d outerFlag=0x%08X\n",
			fileSize, startOff, size, outerFlag)
		fmt.Printf("[BLB3] headerKey=%s\n", hex.EncodeToString(headerKey))
		fmt.Printf("[BLB3] headerEnc[0:%d]=% X\n", n, headerBytesEnc[:n])
	}

	// ---------- 7) 解密 headerBytes ----------
	headerBytesDec := append([]byte(nil), headerBytesEnc...) // 不要原地改 f.HeaderBytes，方便对比
	Decrypt(headerKey, headerBytesDec)

	{
		n := 64
		if len(headerBytesDec) < n {
			n = len(headerBytesDec)
		}
		fmt.Printf("[BLB3] headerDec[0:%d]=% X\n", n, headerBytesDec[:n])

		// 直接把关键字段按小端读出来（不依赖 parseHeaderBytesAll）
		// 0x00 u32 headerSize
		// 0x04 u32 lastUnc
		// 0x08 u32 innerReserved
		// 0x0C i32 blobOffset
		// 0x10 u32 blobSize
		// 0x14 u8 comp
		// 0x15 u8 blockPow
		// 0x18 i32 blocksCount
		// 0x1C i32 nodesCount
		if len(headerBytesDec) >= 0x20 {
			hSz := leU32(headerBytesDec[0x00:0x04])
			lastUnc := leU32(headerBytesDec[0x04:0x08])
			innerRes := leU32(headerBytesDec[0x08:0x0C])
			blobOff := leI32(headerBytesDec[0x0C:0x10])
			blobSz := leU32(headerBytesDec[0x10:0x14])
			comp := headerBytesDec[0x14]
			blockPow := headerBytesDec[0x15]
			blocksCount := leI32(headerBytesDec[0x18:0x1C])
			nodesCount := leI32(headerBytesDec[0x1C:0x20])

			fmt.Printf("[BLB3] decFields headerSizeU32=%d(0x%X) lastUnc=%d(0x%X) innerReserved=0x%X blobOff=%d blobSz=%d comp=%d blockPow=%d blocksCount=%d nodesCount=%d\n",
				hSz, hSz, lastUnc, lastUnc, innerRes, blobOff, blobSz, comp, blockPow, blocksCount, nodesCount)
		}
	}

	// ---------- 8) 用解密后的 bytes 去 parseHeaderBytesAll ----------
	hdr, blocks, nodes, perr := parseHeaderBytesAll(headerBytesDec)
	if perr != nil {
		// 失败时把解密后的 headerBytes 写出来，方便你 hex diff
		_ = os.WriteFile("header_dec_dump.bin", headerBytesDec, 0o644)
		_ = os.WriteFile("header_enc_dump.bin", headerBytesEnc, 0o644)

		// 再给你多一层提示：通常 blocksCount/nodesCount 乱 => size/范围不对 或 Encrypt/Decrypt 不可逆
		return nil, fmt.Errorf("parseHeaderBytesAll failed: %w (wrote header_enc_dump.bin & header_dec_dump.bin)", perr)
	}

	f.Header = hdr
	f.Blocks = blocks
	f.Nodes = nodes

	// ---------- 9) 读取 blocks + 解压/解密拼出 BlocksStream ----------
	blocksStream, err := readBlocksAndBuildStream(br, headerKey, blocks)
	if err != nil {
		return nil, err
	}
	f.BlocksStream = blocksStream

	// ---------- 10) 一些 sanity check ----------
	// blocksInfoSize 应等于 hdr bytes 实际长度（你的样本是 1916）
	if int64(len(headerBytesEnc)) != size {
		fmt.Printf("[WARN] headerBytesEnc len(%d) != size(%d)\n", len(headerBytesEnc), size)
	}
	// 如果你认为 headerSizeU32 语义是 “blb fileSize”，你也可以在这里对照输出：
	// fmt.Printf("[BLB3] hdr.HeaderSize=%d fileSize=%d\n", hdr.HeaderSize, fileSize)

	return f, nil
}

// ---- 小端工具（不依赖 encoding/binary，避免额外 import） ----
func leU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
func leI32(b []byte) int32 { return int32(leU32(b)) }

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

	// reader.Position += 4; 其实是一个 u32 保留字段（innerReservedU32）
	posBefore := br.Pos()
	innerRes, err := br.ReadU32()
	if err != nil {
		return nil, nil, nil, err
	}
	fmt.Printf("[BLB3] innerReservedU32 @0x%X = 0x%08X (%d)\n", posBefore, innerRes, innerRes)

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
			maxDst := lz4.CompressBlockBound(usz)
			dst := make([]byte, maxDst)

			var n int
			var cErr error

			if comp == CompressionLz4HC {
				// HC level=12 (你跟 C# 一致)
				n, cErr = lz4.CompressBlockHC(uncomp, dst, 12, nil, nil)
			} else {
				// 普通 LZ4
				n, cErr = lz4.CompressBlock(uncomp, dst, nil)
			}

			if cErr != nil {
				return nil, nil, 0, fmt.Errorf("lz4 compress block %d failed: %w", bi, cErr)
			}

			if n > 0 && n < usz {
				blkType = comp
				toWrite = dst[:n]
			} else {
				// 压不动：写 raw，并标 None（和 C# 解包判断一致）
				blkType = CompressionNone
				toWrite = append([]byte(nil), uncomp...)
			}

		case CompressionNone:
			blkType = CompressionNone
			toWrite = append([]byte(nil), uncomp...)

		default:
			return nil, nil, 0, fmt.Errorf("unsupported compression type for repack: %d (only None/LZ4/LZ4HC)", comp)
		}

		// 只影响前 128 字节（你的 Encrypt 实现就是这样）
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

func isCABMain(name string) bool {
	// 原版：主 CAB 文件 flags=0x4，.resS flags=0
	// 你现在 dump 里就是这样
	return strings.HasPrefix(name, "CAB-") && !strings.HasSuffix(name, ".resS")
}

func patchHeaderSizeAsFileTotal(hdrPlain []byte, blocksPayloadLen int) {
	// HeaderSizeU32 = blb 文件总长度
	// 4("Blb\x03")+4(blocksInfoSize)+4(outerFlag)+16(headerKey)+len(headerBytes)+blocksPayloadLen
	total := 4 + 4 + 4 + 16 + len(hdrPlain) + blocksPayloadLen
	patchU32LE(hdrPlain, 0, uint32(total))
}

// -------------------- repack from dir --------------------

func RepackCABsFromDir(unpackDir, outPath string, headerKey []byte, blockPow byte, comp CompressionType) error {
	if len(headerKey) != 16 {
		return fmt.Errorf("headerKey must be 16 bytes, got=%d", len(headerKey))
	}

	// 硬编 key
	headerKey, _ = hex.DecodeString("36790E79C7BFD31AE36B5209EDD1EC1C")

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

		// ✅ 修复：flags 规则
		var flags uint32 = 0
		if isCABMain(cabNames[i]) {
			flags = 4
		}

		nodes = append(nodes, Node{
			Offset: int32(offset),
			Size:   int32(len(data)),
			Flags:  flags,
			Path:   cabNames[i], // 只要文件名
		})

		_, _ = blocksStream.Write(data)
		offset += int64(len(data))
	}

	// blocks（压缩/加密）
	blockSize := 1 << blockPow
	blocksPayload, blocksMeta, lastUnc, err := buildBlocksPayload(blocksStream.Bytes(), headerKey, blockSize, comp)
	if err != nil {
		return err
	}

	// headerBytes 明文
	hdrPlain, err := buildHeaderBytes(blockPow, comp, uint32(lastUnc), blocksMeta, nodes)
	if err != nil {
		return err
	}

	// ✅ 关键：回填 HeaderSizeU32 = blb 总长度（在加密之前！）
	patchHeaderSizeAsFileTotal(hdrPlain, len(blocksPayload))

	// headerBytes 加密（只影响前 128）
	hdrEnc := append([]byte(nil), hdrPlain...)
	Encrypt(headerKey, hdrEnc)

	// 写出 blb
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write([]byte{'B', 'l', 'b', 0x03}); err != nil {
		return err
	}
	if err := writeU32LE(f, uint32(len(hdrEnc))); err != nil {
		return err
	}
	// outerFlag（你样本是 5）
	if err := writeU32LE(f, 5); err != nil {
		return err
	}
	if _, err := f.Write(headerKey); err != nil {
		return err
	}
	if _, err := f.Write(hdrEnc); err != nil {
		return err
	}
	if _, err := f.Write(blocksPayload); err != nil {
		return err
	}
	return nil
}

// -------------------- repack from bytes --------------------

func RepackCABsFromBytes(cabs map[string][]byte, outPath string, headerKey []byte, blockPow byte, comp CompressionType) error {
	if len(headerKey) != 16 {
		return fmt.Errorf("headerKey must be 16 bytes")
	}
	if len(cabs) == 0 {
		return fmt.Errorf("no CAB data")
	}

	// 排序保证稳定
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

		// ✅ 修复：flags 规则
		var flags uint32 = 0
		if isCABMain(name) {
			flags = 4
		}

		nodes = append(nodes, Node{
			Offset: int32(offset),
			Size:   int32(len(data)),
			Flags:  flags,
			Path:   name,
		})

		blocksStream.Write(data)
		offset += int64(len(data))
	}

	// blocks
	blockSize := 1 << blockPow
	blocksPayload, blocksMeta, lastUnc, err := buildBlocksPayload(blocksStream.Bytes(), headerKey, blockSize, comp)
	if err != nil {
		return err
	}

	// header
	hdrPlain, err := buildHeaderBytes(blockPow, comp, uint32(lastUnc), blocksMeta, nodes)
	if err != nil {
		return err
	}

	// ✅ 关键：回填 HeaderSizeU32 = blb 总长度（在加密之前！）
	patchHeaderSizeAsFileTotal(hdrPlain, len(blocksPayload))

	hdrEnc := append([]byte(nil), hdrPlain...)
	Encrypt(headerKey, hdrEnc)

	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	f.Write([]byte{'B', 'l', 'b', 0x03})
	writeU32LE(f, uint32(len(hdrEnc)))
	writeU32LE(f, 5)
	f.Write(headerKey)
	f.Write(hdrEnc)
	f.Write(blocksPayload)
	return nil
}

// -------------------- headerBytes builder (不写 HeaderSize) --------------------

func buildHeaderBytes(blockPow byte, comp CompressionType, lastUnc uint32, blocks []StorageBlock, nodes []Node) ([]byte, error) {
	if len(nodes) < 1 {
		return nil, fmt.Errorf("no nodes")
	}
	if len(blocks) < 1 {
		return nil, fmt.Errorf("no blocks")
	}

	var buf bytes.Buffer

	// 1) HeaderSize 占位（外层回填为 blb 总长度）
	_ = writeU32ToBuf(&buf, 0)

	// 2) LastUncompressedSize
	_ = writeU32ToBuf(&buf, lastUnc)

	// 3) innerReserved/skip4（样本是 0）
	_ = writeU32ToBuf(&buf, 0)

	// 4) blobOffset/blobSize（样本是 0）
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

	// 8) relOffset 占位（abs = posBeforeReadI64 + rel）
	blocksRelPos := buf.Len()
	_ = writeI64ToBuf(&buf, 0)
	nodesRelPos := buf.Len()
	_ = writeI64ToBuf(&buf, 0)
	flagsRelPos := buf.Len()
	_ = writeI64ToBuf(&buf, 0)

	// 9) blocksInfo：累计 compressedSize
	blocksInfoAbs := int64(buf.Len())
	var cum uint32
	for i := 0; i < len(blocks); i++ {
		cum += blocks[i].CompressedSize
		_ = writeU32ToBuf(&buf, cum)
	}

	// 10) nodesInfo：offset/size + relPathOffset
	nodesInfoAbs := int64(buf.Len())
	nodePathRelPos := make([]int, len(nodes))
	for i := 0; i < len(nodes); i++ {
		_ = writeI32ToBuf(&buf, nodes[i].Offset)
		_ = writeI32ToBuf(&buf, nodes[i].Size)
		nodePathRelPos[i] = buf.Len()
		_ = writeI64ToBuf(&buf, 0)
	}

	// 11) string table：路径 + \0
	pathAbsList := make([]int64, len(nodes))
	for i := 0; i < len(nodes); i++ {
		pathAbsList[i] = int64(buf.Len())
		_, _ = buf.WriteString(nodes[i].Path)
		_ = buf.WriteByte(0)
	}

	// 12) align4 before flags（保持样本 flagsAbs=0x778 这种对齐）
	for (buf.Len() & 3) != 0 {
		_ = buf.WriteByte(0)
	}

	// 13) flags bitmap（放最后）
	flagsAbs := int64(buf.Len())
	wordCount := (len(nodes) + 31) / 32
	flagWords := make([]uint32, wordCount)
	for i := 0; i < len(nodes); i++ {
		if nodes[i].Flags != 0 {
			w := i / 32
			bit := uint32(1) << uint32(i&31)
			flagWords[w] |= bit
		}
	}
	for _, w := range flagWords {
		_ = writeU32ToBuf(&buf, w)
	}

	raw := buf.Bytes()

	// patch node relPathOffset：rel = pathAbs - fieldPos
	for i := 0; i < len(nodes); i++ {
		posBefore := int64(nodePathRelPos[i]) // 字段起始 pos（和你 parse 的 base 一致）
		rel := pathAbsList[i] - posBefore
		patchI64LE(raw, nodePathRelPos[i], rel)
	}

	// patch 3 relOffset（base=字段起始 pos）
	patchI64LE(raw, blocksRelPos, blocksInfoAbs-int64(blocksRelPos))
	patchI64LE(raw, nodesRelPos, nodesInfoAbs-int64(nodesRelPos))
	patchI64LE(raw, flagsRelPos, flagsAbs-int64(flagsRelPos))

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
