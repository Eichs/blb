package main

import (
	"fmt"
)

// Decrypt 按 C#：
// buffer = buffer[..Math.Min(128, buffer.Length)]
// 1) 首 16 字节 XOR header
// 2) BlbAES.Encrypt(buffer[0:16].ToArray(), header) 覆盖回 buffer[0:16]
// 3) len>16 -> RC4(buffer)（只改 0x10 之后）
// 4) Descramble(buffer[0:16])
func Decrypt(header []byte, buffer []byte) {
	if len(header) != 0x10 {
		panic(fmt.Sprintf("invalid header size: %d != 16", len(header)))
	}
	if len(buffer) == 0 {
		return
	}

	n := len(buffer)
	if n > 128 {
		n = 128
	}
	buf := buffer[:n]

	// Initial XOR step (only first 16 bytes used)
	for i := 0; i < 16 && i < len(buf); i++ {
		buf[i] ^= header[i]
	}

	// Modified AES implementation: calling Encrypt() is intentional.
	// C# does: BlbAES.Encrypt(buffer.Slice(0,16).ToArray(), header).CopyTo(buffer);
	if len(buf) >= 16 {
		in := make([]byte, 16)
		copy(in, buf[:16])
		out := BlbAESEncrypt(in, header) // returns 16 bytes
		copy(buf[:16], out)
	}

	// RC4 only modifies bytes after first 16, but uses early bytes to seed
	if len(buf) > 16 {

		RC4Decrypt(buf)
	}

	// Descramble first 16 bytes
	if len(buf) >= 16 {
		Descramble(buf[:16])
	} else {
		Descramble(buf)
	}
}
func Encrypt(header []byte, buffer []byte) {
	if len(header) != 0x10 {
		panic(fmt.Sprintf("invalid header size: %d != 16", len(header)))
	}
	if len(buffer) == 0 {
		return
	}

	n := len(buffer)
	if n > 128 {
		n = 128
	}
	buf := buffer[:n]

	if len(buf) >= 16 {
		Scramble(buf[:16]) // 用你确认过的“只对16字节”
	} else {
		panic(fmt.Sprintf("buffer too short for Encrypt: %d (<16)", len(buf)))
	}

	if len(buf) > 16 {
		RC4Encrypt(buf)
	}

	if len(buf) >= 16 {
		in := make([]byte, 16)
		copy(in, buf[:16])
		out := BlbAESDecrypt(in, header)
		copy(buf[:16], out)
	}

	for i := 0; i < 16 && i < len(buf); i++ {
		buf[i] ^= header[i]
	}
}
