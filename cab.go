package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type Endian int

const (
	BigEndian Endian = iota
	LittleEndian
)

type Reader struct {
	b      []byte
	pos    int64
	endian Endian
}

func NewReader(b []byte) *Reader {
	return &Reader{b: b, pos: 0, endian: BigEndian} // Unity SerializedFile: header 常用 BE 起步
}

func (r *Reader) Pos() int64         { return r.pos }
func (r *Reader) SetPos(p int64)     { r.pos = p }
func (r *Reader) SetEndian(e Endian) { r.endian = e }
func (r *Reader) Remaining() int64   { return int64(len(r.b)) - r.pos }
func (r *Reader) Bytes(n int) ([]byte, error) {
	if n < 0 || r.pos+int64(n) > int64(len(r.b)) {
		return nil, io.ErrUnexpectedEOF
	}
	out := r.b[r.pos : r.pos+int64(n)]
	r.pos += int64(n)
	return out, nil
}
func (r *Reader) U8() (byte, error) {
	b, err := r.Bytes(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}
func (r *Reader) Bool() (bool, error) {
	v, err := r.U8()
	if err != nil {
		return false, err
	}
	return v != 0, nil
}
func (r *Reader) U16() (uint16, error) {
	b, err := r.Bytes(2)
	if err != nil {
		return 0, err
	}
	if r.endian == LittleEndian {
		return binary.LittleEndian.Uint16(b), nil
	}
	return binary.BigEndian.Uint16(b), nil
}
func (r *Reader) I16() (int16, error) {
	v, err := r.U16()
	return int16(v), err
}
func (r *Reader) U32() (uint32, error) {
	b, err := r.Bytes(4)
	if err != nil {
		return 0, err
	}
	if r.endian == LittleEndian {
		return binary.LittleEndian.Uint32(b), nil
	}
	return binary.BigEndian.Uint32(b), nil
}
func (r *Reader) I32() (int32, error) {
	v, err := r.U32()
	return int32(v), err
}
func (r *Reader) U64() (uint64, error) {
	b, err := r.Bytes(8)
	if err != nil {
		return 0, err
	}
	if r.endian == LittleEndian {
		return binary.LittleEndian.Uint64(b), nil
	}
	return binary.BigEndian.Uint64(b), nil
}
func (r *Reader) I64() (int64, error) {
	v, err := r.U64()
	return int64(v), err
}
func (r *Reader) Align(n int64) {
	if n <= 1 {
		return
	}
	m := r.pos % n
	if m != 0 {
		r.pos += (n - m)
	}
}
func (r *Reader) StringToNull() (string, error) {
	start := r.pos
	for {
		if r.pos >= int64(len(r.b)) {
			return "", io.ErrUnexpectedEOF
		}
		if r.b[r.pos] == 0 {
			s := string(r.b[start:r.pos])
			r.pos++
			return s, nil
		}
		r.pos++
	}
}
func (r *Reader) BytesToNull() ([]byte, error) {
	start := r.pos
	for {
		if r.pos >= int64(len(r.b)) {
			return nil, io.ErrUnexpectedEOF
		}
		if r.b[r.pos] == 0 {
			out := bytes.Clone(r.b[start:r.pos])
			r.pos++
			return out, nil
		}
		r.pos++
	}
}

// ---------------------------
// SerializedFile structures
// ---------------------------

type SerializedFileHeader struct {
	MetadataSize uint32
	FileSize32   uint32
	Version      uint32
	DataOffset32 uint32

	// if Version >= 9:
	Endianess byte
	Reserved  [3]byte

	// if Version >= LargeFilesSupport:
	MetadataSize2 uint32
	FileSize64    int64
	DataOffset64  int64
	Unknown64     int64
}

type ObjectInfo struct {
	PathID    int64
	ByteStart int64
	ByteSize  uint32
	TypeID    int32
	ClassID   int32
}

type LocalSerializedObjectIdentifier struct {
	LocalSerializedFileIndex int32
	LocalIdentifierInFile    int64
}

type FileIdentifier struct {
	GUID     [16]byte
	Type     int32
	PathName string
	FileName string
}

type TypeTreeNode struct {
	Version       uint16
	Level         byte
	TypeFlags     byte
	TypeStrOffset uint32
	NameStrOffset uint32
	ByteSize      int32
	Index         int32
	MetaFlag      int32
	RefTypeHash   uint64 // if Version >= TypeTreeNodeWithTypeFlags
	TypeName      string
	Name          string
}

type TypeTree struct {
	Nodes        []TypeTreeNode
	StringBuffer []byte
}

type SerializedType struct {
	ClassID         int32
	IsStrippedType  bool
	ScriptTypeIndex int16
	ScriptID        []byte
	OldTypeHash     []byte
	TypeTree        *TypeTree

	// ref-type extras:
	KlassName string
	NameSpace string
	AsmName   string

	// non-ref type deps:
	TypeDependencies []int32
}

type SerializedFile struct {
	Header         SerializedFileHeader
	UnityVersion   string
	TargetPlatform int32
	EnableTypeTree bool

	BigIDEnabled int32

	Types     []SerializedType
	Objects   []ObjectInfo
	ScriptIDs []LocalSerializedObjectIdentifier
	Externals []FileIdentifier
	RefTypes  []SerializedType

	UserInformation string
}

// ---------------------------
// Version constants (按你 C# 的枚举习惯给最小用到的阈值)
// 说明：你工程里如果已经有 SerializedFileFormatVersion 枚举，直接替换这些阈值即可。
// 这里按 Unity 常见：7/8/9/14/22 等分界；你这个文件 Version=17。
// ---------------------------

const (
	Ver_Unknown_5  = 5
	Ver_Unknown_6  = 6
	Ver_Unknown_7  = 7
	Ver_Unknown_8  = 8
	Ver_Unknown_9  = 9
	Ver_Unknown_10 = 10
	Ver_Unknown_12 = 12
	Ver_Unknown_14 = 14

	Ver_HasTypeTreeHashes         = 13 // 近似，够用
	Ver_HasScriptTypeIndex        = 11 // 近似
	Ver_RefactorTypeData          = 16 // 近似
	Ver_RefactoredClassId         = 15 // 近似
	Ver_StoresTypeDependencies    = 16 // 近似
	Ver_SupportsRefObject         = 20 // 近似
	Ver_LargeFilesSupport         = 22 // 近似
	Ver_TypeTreeNodeWithTypeFlags = 19 // 近似
)

// CommonString buffer map：你可替换为你项目里的 CommonString.StringBuffer
var CommonString = map[uint32]string{}

// ---------------------------
// Parse entry
// ---------------------------

func ParseSerializedFile(data []byte) (*SerializedFile, error) {
	r := NewReader(data)
	sf := &SerializedFile{}

	// ---- ReadHeader (按你 C#：先读 u32/u32/u32/u32；此时 reader 默认为 BigEndian) ----
	var err error
	sf.Header.MetadataSize, err = r.U32()
	if err != nil {
		return nil, err
	}
	sf.Header.FileSize32, err = r.U32()
	if err != nil {
		return nil, err
	}
	sf.Header.Version, err = r.U32()
	if err != nil {
		return nil, err
	}
	sf.Header.DataOffset32, err = r.U32()
	if err != nil {
		return nil, err
	}

	// Version >= 9: endian byte + reserved[3]
	if sf.Header.Version >= Ver_Unknown_9 {
		sf.Header.Endianess, err = r.U8()
		if err != nil {
			return nil, err
		}
		b, err := r.Bytes(3)
		if err != nil {
			return nil, err
		}
		copy(sf.Header.Reserved[:], b)
	} else {
		// 旧版本：跳到文件末尾 metadata 前取 endian byte
		// reader.Position = fileSize - metadataSize
		pos := int64(sf.Header.FileSize32) - int64(sf.Header.MetadataSize)
		r.SetPos(pos)
		sf.Header.Endianess, err = r.U8()
		if err != nil {
			return nil, err
		}
	}

	// LargeFilesSupport
	if sf.Header.Version >= Ver_LargeFilesSupport {
		sf.Header.MetadataSize2, err = r.U32()
		if err != nil {
			return nil, err
		}
		sf.Header.FileSize64, err = r.I64()
		if err != nil {
			return nil, err
		}
		sf.Header.DataOffset64, err = r.I64()
		if err != nil {
			return nil, err
		}
		sf.Header.Unknown64, err = r.I64()
		if err != nil {
			return nil, err
		}
	}

	// ---- Switch endianness for metadata reading (你的 C#: endianess==0 -> Little) ----
	if sf.Header.Endianess == 0 {
		r.SetEndian(LittleEndian)
	}

	// ---- ReadMetadata ----
	if sf.Header.Version >= Ver_Unknown_7 {
		sf.UnityVersion, err = r.StringToNull()
		if err != nil {
			return nil, err
		}
	}
	if sf.Header.Version >= Ver_Unknown_8 {
		v, err := r.I32()
		if err != nil {
			return nil, err
		}
		sf.TargetPlatform = v
	}
	if sf.Header.Version >= Ver_HasTypeTreeHashes {
		sf.EnableTypeTree, err = r.Bool()
		if err != nil {
			return nil, err
		}
	} else {
		sf.EnableTypeTree = true
	}

	// ---- Types ----
	typeCount, err := r.I32()
	if err != nil {
		return nil, err
	}
	sf.Types = make([]SerializedType, 0, typeCount)
	for i := 0; i < int(typeCount); i++ {
		t, err := readSerializedType(r, sf.Header.Version, sf.EnableTypeTree, false)
		if err != nil {
			return nil, fmt.Errorf("read type[%d]: %w", i, err)
		}
		sf.Types = append(sf.Types, t)
	}

	// bigIDEnabled
	if sf.Header.Version >= Ver_Unknown_7 && sf.Header.Version < Ver_Unknown_14 {
		sf.BigIDEnabled, err = r.I32()
		if err != nil {
			return nil, err
		}
	}

	// ---- Objects ----
	objCount, err := r.I32()
	if err != nil {
		return nil, err
	}
	sf.Objects = make([]ObjectInfo, 0, objCount)
	for i := 0; i < int(objCount); i++ {
		oi := ObjectInfo{}

		// PathID 规则按你 C#
		if sf.BigIDEnabled != 0 {
			oi.PathID, err = r.I64()
		} else if sf.Header.Version < Ver_Unknown_14 {
			v, e := r.I32()
			err = e
			oi.PathID = int64(v)
		} else {
			r.Align(4)
			oi.PathID, err = r.I64()
		}
		if err != nil {
			return nil, err
		}

		// byteStart
		if sf.Header.Version >= Ver_LargeFilesSupport {
			oi.ByteStart, err = r.I64()
		} else {
			v, e := r.U32()
			err = e
			oi.ByteStart = int64(v)
		}
		if err != nil {
			return nil, err
		}

		// DataOffset
		dataOffset := int64(sf.Header.DataOffset32)
		if sf.Header.Version >= Ver_LargeFilesSupport {
			dataOffset = sf.Header.DataOffset64
		}
		oi.ByteStart += dataOffset

		// byteSize/typeID
		oi.ByteSize, err = r.U32()
		if err != nil {
			return nil, err
		}
		oi.TypeID, err = r.I32()
		if err != nil {
			return nil, err
		}

		// classID 规则（这里给最常见的 refactored 逻辑，够你后面接 type table）
		if sf.Header.Version < Ver_RefactoredClassId {
			// classID = ReadUInt16
			cid16, e := r.U16()
			if e != nil {
				return nil, e
			}
			oi.ClassID = int32(cid16)
		} else {
			// type = types[typeID], classID=type.classID
			if oi.TypeID >= 0 && int(oi.TypeID) < len(sf.Types) {
				oi.ClassID = sf.Types[oi.TypeID].ClassID
			}
		}

		// has script type index / stripped byte 等字段：你如果要完全一致可继续补
		// 为了“能解析出对象表”，这里先不强制吃掉那些字段（否则需要精确枚举值）
		// 如果你希望我“严格按你工程的 SerializedFileFormatVersion 枚举”，把枚举贴我就能一行不差复刻。

		sf.Objects = append(sf.Objects, oi)
	}

	// ---- ScriptTypes（Version >= HasScriptTypeIndex）----
	if sf.Header.Version >= Ver_HasScriptTypeIndex {
		scriptCount, err := r.I32()
		if err != nil {
			return nil, err
		}
		sf.ScriptIDs = make([]LocalSerializedObjectIdentifier, 0, scriptCount)
		for i := 0; i < int(scriptCount); i++ {
			s := LocalSerializedObjectIdentifier{}
			s.LocalSerializedFileIndex, err = r.I32()
			if err != nil {
				return nil, err
			}
			if sf.Header.Version < Ver_Unknown_14 {
				v, e := r.I32()
				if e != nil {
					return nil, e
				}
				s.LocalIdentifierInFile = int64(v)
			} else {
				r.Align(4)
				s.LocalIdentifierInFile, err = r.I64()
				if err != nil {
					return nil, err
				}
			}
			sf.ScriptIDs = append(sf.ScriptIDs, s)
		}
	}

	// ---- Externals ----
	extCount, err := r.I32()
	if err != nil {
		return nil, err
	}
	sf.Externals = make([]FileIdentifier, 0, extCount)
	for i := 0; i < int(extCount); i++ {
		fi := FileIdentifier{}

		if sf.Header.Version >= Ver_Unknown_6 {
			_, err := r.StringToNull() // tempEmpty
			if err != nil {
				return nil, err
			}
		}
		if sf.Header.Version >= Ver_Unknown_5 {
			gb, err := r.Bytes(16)
			if err != nil {
				return nil, err
			}
			copy(fi.GUID[:], gb)
			fi.Type, err = r.I32()
			if err != nil {
				return nil, err
			}
		}
		fi.PathName, err = r.StringToNull()
		if err != nil {
			return nil, err
		}
		fi.FileName = baseName(fi.PathName)
		sf.Externals = append(sf.Externals, fi)
	}

	// ---- RefTypes (SupportsRefObject) ----
	if sf.Header.Version >= Ver_SupportsRefObject {
		refCount, err := r.I32()
		if err != nil {
			return nil, err
		}
		sf.RefTypes = make([]SerializedType, 0, refCount)
		for i := 0; i < int(refCount); i++ {
			t, err := readSerializedType(r, sf.Header.Version, sf.EnableTypeTree, true)
			if err != nil {
				return nil, fmt.Errorf("read reftype[%d]: %w", i, err)
			}
			sf.RefTypes = append(sf.RefTypes, t)
		}
	}

	if sf.Header.Version >= Ver_Unknown_5 {
		sf.UserInformation, err = r.StringToNull()
		if err != nil {
			return nil, err
		}
	}

	return sf, nil
}

func readSerializedType(r *Reader, ver uint32, enableTypeTree bool, isRefType bool) (SerializedType, error) {
	var t SerializedType
	var err error

	t.ClassID, err = r.I32()
	if err != nil {
		return t, err
	}

	if ver >= Ver_RefactoredClassId {
		b, err := r.Bool()
		if err != nil {
			return t, err
		}
		t.IsStrippedType = b
	}
	if ver >= Ver_RefactorTypeData {
		v, err := r.I16()
		if err != nil {
			return t, err
		}
		t.ScriptTypeIndex = v
	}

	if ver >= Ver_HasTypeTreeHashes {
		// 这里按你 C# 的条件读 ScriptID / OldTypeHash（保持结构，但不做 classID<0 等细节强绑定）
		// ScriptID（可能存在）
		// 简化：如果 isRefType && scriptTypeIndex>=0 -> read 16
		if isRefType && t.ScriptTypeIndex >= 0 {
			t.ScriptID, err = r.Bytes(16)
			if err != nil {
				return t, err
			}
		}
		// OldTypeHash 总是读 16（按你 C#）
		t.OldTypeHash, err = r.Bytes(16)
		if err != nil {
			return t, err
		}
	}

	if enableTypeTree {
		tt := &TypeTree{}
		// Blob 读：ver>=12 或 ver==10
		if ver >= Ver_Unknown_12 || ver == Ver_Unknown_10 {
			if err := typeTreeBlobRead(r, ver, tt); err != nil {
				return t, err
			}
		} else {
			return t, fmt.Errorf("non-blob typetree (older versions) not implemented in this snippet")
		}

		// stores deps
		if ver >= Ver_StoresTypeDependencies {
			if isRefType {
				t.KlassName, err = r.StringToNull()
				if err != nil {
					return t, err
				}
				t.NameSpace, err = r.StringToNull()
				if err != nil {
					return t, err
				}
				t.AsmName, err = r.StringToNull()
				if err != nil {
					return t, err
				}
			} else {
				// int32 array
				n, err := r.I32()
				if err != nil {
					return t, err
				}
				if n < 0 || n > 1_000_000 {
					return t, fmt.Errorf("bad type dependency count: %d", n)
				}
				arr := make([]int32, n)
				for i := 0; i < int(n); i++ {
					v, err := r.I32()
					if err != nil {
						return t, err
					}
					arr[i] = v
				}
				t.TypeDependencies = arr
			}
		}

		t.TypeTree = tt
	}

	return t, nil
}

func typeTreeBlobRead(r *Reader, ver uint32, tt *TypeTree) error {
	nodeCount, err := r.I32()
	if err != nil {
		return err
	}
	strBufSize, err := r.I32()
	if err != nil {
		return err
	}
	if nodeCount < 0 || nodeCount > 5_000_000 {
		return fmt.Errorf("bad nodeCount: %d", nodeCount)
	}
	if strBufSize < 0 || strBufSize > 1_000_000_000 {
		return fmt.Errorf("bad stringBufferSize: %d", strBufSize)
	}

	tt.Nodes = make([]TypeTreeNode, nodeCount)
	for i := 0; i < int(nodeCount); i++ {
		var n TypeTreeNode
		n.Version, err = readU16LE(r)
		if err != nil {
			return err
		}
		n.Level, err = r.U8()
		if err != nil {
			return err
		}
		n.TypeFlags, err = r.U8()
		if err != nil {
			return err
		}
		n.TypeStrOffset, err = readU32LE(r)
		if err != nil {
			return err
		}
		n.NameStrOffset, err = readU32LE(r)
		if err != nil {
			return err
		}
		n.ByteSize, err = readI32LE(r)
		if err != nil {
			return err
		}
		n.Index, err = readI32LE(r)
		if err != nil {
			return err
		}
		n.MetaFlag, err = readI32LE(r)
		if err != nil {
			return err
		}
		if ver >= Ver_TypeTreeNodeWithTypeFlags {
			n.RefTypeHash, err = readU64LE(r)
			if err != nil {
				return err
			}
		}
		tt.Nodes[i] = n
	}

	tt.StringBuffer, err = r.Bytes(int(strBufSize))
	if err != nil {
		return err
	}

	// 解析字符串：value 的最高位表示 CommonString 表还是 offset
	for i := 0; i < int(nodeCount); i++ {
		tt.Nodes[i].TypeName = resolveTypeTreeString(tt.StringBuffer, tt.Nodes[i].TypeStrOffset)
		tt.Nodes[i].Name = resolveTypeTreeString(tt.StringBuffer, tt.Nodes[i].NameStrOffset)
	}
	return nil
}

func resolveTypeTreeString(buf []byte, value uint32) string {
	// 你 C#：isOffset = (value & 0x80000000) == 0
	if (value & 0x80000000) == 0 {
		off := int(value)
		if off < 0 || off >= len(buf) {
			return fmt.Sprintf("bad_off_%d", off)
		}
		// read null-terminated from buf[off:]
		end := off
		for end < len(buf) && buf[end] != 0 {
			end++
		}
		return string(buf[off:end])
	}
	key := value & 0x7FFFFFFF
	if s, ok := CommonString[key]; ok {
		return s
	}
	return fmt.Sprintf("%d", key)
}

func baseName(p string) string {
	// 不引入 path/filepath，简单实现
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}

// 注意：TypeTreeBlob 在 Unity 里一般固定用 LE，所以这里强制 LE 读
func readU16LE(r *Reader) (uint16, error) {
	b, err := r.Bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}
func readU32LE(r *Reader) (uint32, error) {
	b, err := r.Bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}
func readI32LE(r *Reader) (int32, error) {
	v, err := readU32LE(r)
	return int32(v), err
}
func readU64LE(r *Reader) (uint64, error) {
	b, err := r.Bytes(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

type ConfigPatch struct {
	ChannelName string
	DispatchURL string
	KeyID       int
}

func patchJSON(js []byte, p ConfigPatch) ([]byte, error) {
	var obj map[string]any
	if err := json.Unmarshal(js, &obj); err != nil {
		return nil, err
	}

	if p.ChannelName != "" {
		obj["ChannelName"] = p.ChannelName
	}
	if p.KeyID != 0 {
		rsa, ok := obj["RSAParam"].(map[string]any)
		if !ok {
			rsa = map[string]any{}
			obj["RSAParam"] = rsa
		}
		rsa["keyId"] = p.KeyID
	}
	if p.DispatchURL != "" {
		if dc, ok := obj["DispatchConfigs"].([]any); ok && len(dc) > 0 {
			if d0, ok := dc[0].(map[string]any); ok {
				if urls, ok := d0["DispatchUrls"].([]any); ok && len(urls) > 0 {
					urls[0] = p.DispatchURL
					d0["DispatchUrls"] = urls
				} else {
					d0["DispatchUrls"] = []any{p.DispatchURL}
				}
			}
		}
	}

	// 紧凑格式，尽量减少长度变化
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------------------
// Object get/replace/repack
// ---------------------------

func getObjectRaw(file []byte, oi ObjectInfo) ([]byte, error) {
	start := oi.ByteStart
	end := oi.ByteStart + int64(oi.ByteSize)
	if start < 0 || end < start || end > int64(len(file)) {
		return nil, fmt.Errorf("object out of range: pathID=%d start=%d size=%d file=%d",
			oi.PathID, start, oi.ByteSize, len(file))
	}
	return bytes.Clone(file[start:end]), nil
}

func repackReplaceObject(file []byte, sf *SerializedFile, target *ObjectInfo, newObjRaw []byte) ([]byte, error) {
	oldSize := int64(target.ByteSize)
	newSize := int64(len(newObjRaw))
	delta := newSize - oldSize
	start := target.ByteStart
	end := start + oldSize

	if delta == 0 {
		out := bytes.Clone(file)
		copy(out[start:start+newSize], newObjRaw)
		// header filesize unchanged
		return out, nil
	}

	newFileLen := int64(len(file)) + delta
	if newFileLen <= 0 {
		return nil, fmt.Errorf("bad new file length: %d", newFileLen)
	}

	out := make([]byte, newFileLen)
	copy(out[:start], file[:start])
	copy(out[start:start+newSize], newObjRaw)
	copy(out[start+newSize:], file[end:])

	// update header m_FileSize (BigEndian u32 at offset 4)
	binary.BigEndian.PutUint32(out[4:8], uint32(newFileLen))

	// update in-memory objects (byteSize + shift following)
	target.ByteSize = uint32(newSize)
	for i := range sf.Objects {
		oi := &sf.Objects[i]
		if oi.PathID == target.PathID {
			continue
		}
		if oi.ByteStart >= end {
			oi.ByteStart += delta
		}
	}
	return out, nil
}
func patchObjectTableV17(file []byte, sf *SerializedFile) error {
	r := NewReader(file)

	_, err := r.U32() // metadataSize
	if err != nil {
		return err
	}
	_, err = r.U32() // fileSize
	if err != nil {
		return err
	}
	ver, err := r.U32()
	if err != nil {
		return err
	}
	dataOffset32, err := r.U32()
	if err != nil {
		return err
	}
	if ver < Ver_Unknown_9 {
		return errors.New("unexpected version < 9")
	}

	endianByte, err := r.U8()
	if err != nil {
		return err
	}
	_, err = r.Bytes(3)
	if err != nil {
		return err
	}
	if endianByte == 0 {
		r.SetEndian(LittleEndian)
	}

	if ver >= Ver_Unknown_7 {
		if _, err := r.StringToNull(); err != nil {
			return err
		}
	}
	if ver >= Ver_Unknown_8 {
		if _, err := r.I32(); err != nil {
			return err
		}
	}
	if ver >= Ver_HasTypeTreeHashes {
		if _, err := r.Bool(); err != nil {
			return err
		}
	}

	// skip types minimal (same as parse)
	typeCount, err := r.I32()
	if err != nil {
		return err
	}
	for i := 0; i < int(typeCount); i++ {
		if _, err := r.I32(); err != nil { // classID
			return err
		}
		if ver >= Ver_RefactoredClassId {
			if _, err := r.Bool(); err != nil {
				return err
			}
		}
		if ver >= Ver_RefactorTypeData {
			if _, err := r.I16(); err != nil {
				return err
			}
		}
		if ver >= Ver_HasTypeTreeHashes {
			if _, err := r.Bytes(16); err != nil {
				return err
			}
		}
	}

	objCount, err := r.I32()
	if err != nil {
		return err
	}
	if int(objCount) != len(sf.Objects) {
		return fmt.Errorf("object count mismatch: table=%d parsed=%d", objCount, len(sf.Objects))
	}

	dataOffset := int64(dataOffset32)

	for i := 0; i < int(objCount); i++ {
		// ver>=14 align + pathID
		if ver >= Ver_Unknown_14 {
			r.Align(4)
			if _, err := r.I64(); err != nil {
				return err
			}
		} else {
			if _, err := r.I32(); err != nil {
				return err
			}
		}

		// byteStart relative u32: patch at current pos
		rel := uint32(int64(sf.Objects[i].ByteStart) - dataOffset)
		if r.pos+4 > int64(len(file)) {
			return io.ErrUnexpectedEOF
		}
		binary.LittleEndian.PutUint32(file[r.pos:r.pos+4], rel)
		if _, err := r.U32(); err != nil {
			return err
		}

		// byteSize u32: patch
		if r.pos+4 > int64(len(file)) {
			return io.ErrUnexpectedEOF
		}
		binary.LittleEndian.PutUint32(file[r.pos:r.pos+4], sf.Objects[i].ByteSize)
		if _, err := r.U32(); err != nil {
			return err
		}

		// typeID int32: keep
		if _, err := r.I32(); err != nil {
			return err
		}

		// ver>=15: object table usually DOES NOT have extra u16 classID (it’s refactored by typeID)
		// If your other CABs have extra fields here, tell me，我按真实布局补齐。
	}

	return nil
}
func parseObject3JSON(raw []byte) ([]byte, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("object too small")
	}

	data := raw[4:]

	// 从后往前找 JSON 结束的 '}'
	end := -1
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == '}' {
			end = i + 1
			break
		}
	}
	if end < 0 {
		return nil, fmt.Errorf("no JSON object end '}' found")
	}

	js := data[:end]

	// sanity check
	var tmp any
	if err := json.Unmarshal(js, &tmp); err != nil {
		return nil, err
	}

	return bytes.Clone(js), nil
}

func buildObject3Raw(newJSON []byte) []byte {
	// payload = json + '\0'
	payloadLen := len(newJSON) + 1

	// object raw = u32(dataSize) + payload
	totalSize := 4 + payloadLen

	out := make([]byte, totalSize)

	// dataSize = ByteSize - 4
	binary.LittleEndian.PutUint32(out[0:4], uint32(payloadLen))

	// copy json
	copy(out[4:], newJSON)

	// null-terminator
	out[4+len(newJSON)] = 0

	return out
}
func PatchCABBytes(cabName string, cabData []byte, patch ConfigPatch) ([]byte, error) {

	sf, err := ParseSerializedFile(cabData)
	if err != nil {
		return nil, fmt.Errorf("[%s] parse failed: %w", cabName, err)
	}

	// 锁定 objectID = 3
	var target *ObjectInfo
	for i := range sf.Objects {
		if sf.Objects[i].PathID == 3 {
			target = &sf.Objects[i]
			break
		}
	}
	if target == nil {
		return cabData, nil
	}

	oldRaw, err := getObjectRaw(cabData, *target)
	if err != nil {
		return nil, err
	}

	oldJSON, err := parseObject3JSON(oldRaw)
	if err != nil {
		return nil, err
	}

	newJSON, err := patchJSON(oldJSON, patch)
	if err != nil {
		return nil, err
	}

	newRaw := buildObject3Raw(newJSON)

	patched, err := repackReplaceObject(cabData, sf, target, newRaw)
	if err != nil {
		return nil, err
	}

	if err := patchObjectTableV17(patched, sf); err != nil {
		return nil, err
	}

	return patched, nil
}
