package chibihash

// load64le 从字节切片中以小端序加载一个uint64值
func load64le(p []byte) uint64 {
	return uint64(p[0]) |
		uint64(p[1])<<8 |
		uint64(p[2])<<16 |
		uint64(p[3])<<24 |
		uint64(p[4])<<32 |
		uint64(p[5])<<40 |
		uint64(p[6])<<48 |
		uint64(p[7])<<56
}

// Hash64 计算输入数据的64位哈希值
// key: 输入数据
// seed: 哈希种子
func Hash64(key []byte, seed uint64) uint64 {
	k := key
	l := len(key)

	const (
		P1 = uint64(0x2B7E151628AED2A5)
		P2 = uint64(0x9E3793492EEDC3F7)
		P3 = uint64(0x3243F6A8885A308D)
	)

	h := [4]uint64{P1, P2, P3, seed}

	// 主循环: 每次处理32字节
	for l >= 32 {
		for i := 0; i < 4; i++ {
			lane := load64le(k[i*8:])
			h[i] ^= lane
			h[i] *= P1
			h[(i+1)&3] ^= ((lane << 40) | (lane >> 24))
		}
		l -= 32
		k = k[32:]
	}

	// 处理长度信息
	h[0] += (uint64(len(key)) << 32) | (uint64(len(key)) >> 32)

	// 处理剩余的单个字节
	if l&1 != 0 {
		h[0] ^= uint64(k[0])
		l--
		k = k[1:]
	}

	// 处理第一个哈希槽
	h[0] *= P2
	h[0] ^= h[0] >> 31

	// 处理剩余的完整8字节块
	for i := 1; l >= 8; i++ {
		h[i] ^= load64le(k)
		h[i] *= P2
		h[i] ^= h[i] >> 31
		l -= 8
		k = k[8:]
	}

	// 处理剩余的2字节块
	for i := 0; l > 0; i++ {
		if l >= 2 {
			h[i] ^= uint64(k[0]) | uint64(k[1])<<8
		} else {
			h[i] ^= uint64(k[0])
		}
		h[i] *= P3
		h[i] ^= h[i] >> 31
		l -= 2
		k = k[2:]
	}

	// 最终混合
	x := seed
	x ^= h[0] * ((h[2] >> 32) | 1)
	x ^= h[1] * ((h[3] >> 32) | 1)
	x ^= h[2] * ((h[0] >> 32) | 1)
	x ^= h[3] * ((h[1] >> 32) | 1)

	// moremur mixing
	x ^= x >> 27
	x *= 0x3C79AC492BA7B653
	x ^= x >> 33
	x *= 0x1C69B3F74AC4AE35
	x ^= x >> 27

	return x
}
