package main

import "sync"

func gf256Inv(a byte) byte {
	// 0 没有逆；非 0：a^(−1) = exp(255 - log(a))
	if a == 0 {
		return 0
	}
	la := int(GF256Log[a]) // 0..254
	return GF256Exp[(0xFF-la)%0xFF]
}

// -------------------- SBox 逆表（按 row=0..3 各 256） --------------------

var (
	invSBoxOnce sync.Once
	invSBox     [4][256]byte
)

func buildInvSBox() {
	for row := 0; row < 4; row++ {
		base := row * 0x100
		for t := 0; t < 256; t++ {
			v := Blb3SBox[base+t]
			invSBox[row][v] = byte(t)
		}
	}
}

// -------------------- 逆过程：Scramble --------------------

// Scramble 是 Descramble 的逆：把 descramble 过的数据“还原回去”
// 注意：要保证 (1) 每轮的 k%len 不发生碰撞（典型就是 len==16），(2) SBox 每行可逆，(3) mul != 0
func Scramble(buf []byte) {
	if len(buf) == 0 {
		return
	}
	invSBoxOnce.Do(buildInvSBox)

	// 预计算 8 个 mul 的逆元（idx = j%8）
	var invMul [8]byte
	for i := 0; i < 8; i++ {
		invMul[i] = gf256Inv(Blb3Mul[i])
	}

	prev := make([]byte, len(buf))

	// Descramble 是 i=0..2（用 shiftRow block 2,1,0）
	// 逆过程要倒序 i=2..0
	for i := 2; i >= 0; i-- {
		// 从当前 buf（相当于 forward 的 vector）反推上一轮输入 prev
		for j := 0; j < len(buf); j++ {
			k := int(Blb3ShiftRow[(2-i)*0x10+j]) // 与 forward 完全一致
			idx := j % 8
			row := j % 4

			// s = SBox[row*256 + gf256Mul(mul, x)]
			s := buf[j] ^ Blb3Key[idx]

			// t = gf256Mul(mul, x)
			t := invSBox[row][s]

			// x = invMul * t
			// 若 invMul[idx]==0（mul==0）则不可逆；这里会得到 0（你也可以选择 panic/return）
			x := gf256Mul(invMul[idx], t)

			prev[k%len(buf)] = x
		}

		copy(buf, prev)
	}
}
