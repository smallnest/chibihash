package chibihash

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzHash64 针对Hash64函数的模糊测试
func FuzzHash64(f *testing.F) {
	// 添加种子语料
	seeds := [][]byte{
		{},                             // 空输入
		{0x42},                         // 单字节
		{0x42, 0x43},                   // 两字节
		bytes.Repeat([]byte{0xFF}, 8),  // 8字节全1
		bytes.Repeat([]byte{0x00}, 32), // 32字节全0
		[]byte("Hello, World!"),        // 常见字符串
		[]byte("The quick brown fox jumps over the lazy dog"), // 包含所有字母的句子
	}

	for _, seed := range seeds {
		f.Add(seed, uint64(0x12345678)) // 添加初始种子用例
	}

	f.Fuzz(func(t *testing.T, data []byte, seed uint64) {
		// 基本属性测试
		hash1 := Hash64(data, seed)
		hash2 := Hash64(data, seed)

		// 属性1: 一致性检查 - 相同输入应产生相同输出
		if hash1 != hash2 {
			t.Errorf("Hash inconsistency: same input produced different hashes: %x != %x", hash1, hash2)
		}

		// 属性2: 非零检查 - 确保输出不为零（除非输入非常特殊）
		if hash1 == 0 && len(data) > 0 {
			t.Errorf("Hash produced zero for non-empty input of length %d", len(data))
		}

		// 属性3: 种子敏感性检查
		differentSeed := seed ^ 0xFFFFFFFFFFFFFFFF
		hashWithDifferentSeed := Hash64(data, differentSeed)
		if hash1 == hashWithDifferentSeed {
			t.Errorf("Hash is not sensitive to seed change")
		}

		// 属性4: 数据敏感性检查（如果数据长度足够）
		if len(data) > 0 {
			modifiedData := make([]byte, len(data))
			copy(modifiedData, data)
			// 修改最后一个字节
			modifiedData[len(data)-1] ^= 0xFF
			modifiedHash := Hash64(modifiedData, seed)

			if hash1 == modifiedHash {
				t.Errorf("Hash is not sensitive to data change")
			}
		}

		// 属性5: 长度扩展检查
		if len(data) > 0 {
			extendedData := make([]byte, len(data)+1)
			copy(extendedData, data)
			extendedHash := Hash64(extendedData, seed)

			if hash1 == extendedHash {
				t.Errorf("Hash is not sensitive to length extension")
			}
		}

		// 属性6: 对齐敏感性检查
		if len(data) >= 9 {
			// 测试不同的对齐偏移
			for offset := 1; offset < 8; offset++ {
				slice1 := data[:len(data)-offset]
				slice2 := data[offset:]

				hash3 := Hash64(slice1, seed)
				hash4 := Hash64(slice2, seed)

				if hash3 == hash4 && !bytes.Equal(slice1, slice2) {
					t.Errorf("Hash produced same output for different slices at offset %d", offset)
				}
			}
		}

		// 属性7: 雪崩效应检查（使用汉明距离）
		if len(data) >= 8 {
			modifiedData := make([]byte, len(data))
			copy(modifiedData, data)
			// 修改一个位
			modifiedData[len(data)/2] ^= 1

			hash5 := Hash64(modifiedData, seed)
			hammingDistance := calcHammingDistance(hash1, hash5)

			// 一个位的改变应该影响大约一半的输出位
			const minExpectedChangedBits = 20 // 期望至少20位发生改变
			if hammingDistance < minExpectedChangedBits {
				t.Errorf("Poor avalanche effect: only %d bits changed (expected >= %d)",
					hammingDistance, minExpectedChangedBits)
			}
		}

		// 属性8: 分块一致性检查
		if len(data) > 32 {
			// 测试分块处理的一致性
			block1 := Hash64(data[:16], seed)
			block2 := Hash64(data[16:], seed)
			fullHash := Hash64(data, seed)

			if block1 == block2 && len(data[:16]) == len(data[16:]) {
				t.Error("Equal hashes for different blocks of same size")
			}
			if block1 == fullHash || block2 == fullHash {
				t.Error("Partial hash equals full hash")
			}
		}
	})
}

// 计算两个uint64值之间的汉明距离（不同位的数量）
func calcHammingDistance(a, b uint64) int {
	xor := a ^ b
	distance := 0

	// 计算置位数
	for xor != 0 {
		distance += int(xor & 1)
		xor >>= 1
	}

	return distance
}

// FuzzLoad64le 针对load64le函数的模糊测试
func FuzzLoad64le(f *testing.F) {
	// 添加一些初始测试用例
	seeds := [][]byte{
		{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != 8 {
			return // load64le需要精确的8字节输入
		}

		// 使用load64le加载值
		result := load64le(data)

		// 使用标准库的binary.LittleEndian.Uint64进行对比
		expected := binary.LittleEndian.Uint64(data)

		if result != expected {
			t.Errorf("load64le produced incorrect result: got %x, want %x", result, expected)
		}

		// 验证字节序
		var reconstructed [8]byte
		binary.LittleEndian.PutUint64(reconstructed[:], result)
		if !bytes.Equal(reconstructed[:], data) {
			t.Error("Byte order mismatch after reconstruction")
		}
	})
}
