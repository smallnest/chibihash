package chibihash

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"
)

func TestHash64Empty(t *testing.T) {
	seed := uint64(0)
	emptyHash := Hash64([]byte{}, seed)
	// 空字符串的预期哈希值
	if emptyHash == 0 {
		t.Error("Empty string should not hash to 0")
	}
}

func TestHash64Consistency(t *testing.T) {
	seed := uint64(0x12345678)
	data := []byte("Hello, World!")

	hash1 := Hash64(data, seed)
	hash2 := Hash64(data, seed)

	if hash1 != hash2 {
		t.Errorf("Hash function not consistent: %x != %x", hash1, hash2)
	}
}

func TestHash64DifferentSeeds(t *testing.T) {
	data := []byte("Hello, World!")
	seed1 := uint64(0x12345678)
	seed2 := uint64(0x87654321)

	hash1 := Hash64(data, seed1)
	hash2 := Hash64(data, seed2)

	if hash1 == hash2 {
		t.Error("Different seeds should produce different hashes")
	}
}

func TestHash64SmallChanges(t *testing.T) {
	seed := uint64(0)
	data1 := []byte("Hello, World!")
	data2 := []byte("Hello, World.")

	hash1 := Hash64(data1, seed)
	hash2 := Hash64(data2, seed)

	if hash1 == hash2 {
		t.Error("Small changes in input should produce different hashes")
	}
}

func TestHash64LengthEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"1 byte", []byte{0x42}},
		{"2 bytes", []byte{0x42, 0x43}},
		{"3 bytes", []byte{0x42, 0x43, 0x44}},
		{"7 bytes", []byte{0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48}},
		{"8 bytes", []byte{0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49}},
		{"9 bytes", []byte{0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A}},
		{"31 bytes", make([]byte, 31)},
		{"32 bytes", make([]byte, 32)},
		{"33 bytes", make([]byte, 33)},
	}

	seed := uint64(0x12345678)
	seen := make(map[uint64]string)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := Hash64(tt.data, seed)
			if prev, exists := seen[hash]; exists {
				t.Errorf("Hash collision between %s and %s", tt.name, prev)
			}
			seen[hash] = tt.name
		})
	}
}

func TestHash64Alignment(t *testing.T) {
	seed := uint64(0)
	data := make([]byte, 100)

	// 测试不同起始位置的对齐
	for i := 0; i < 8; i++ {
		subData := data[i : i+32]
		hash := Hash64(subData, seed)
		if hash == 0 {
			t.Errorf("Alignment %d produced zero hash", i)
		}
	}
}

func TestHash64Distribution(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping distribution test in short mode")
	}

	const numSamples = 100000
	buckets := make([]int, 16)
	seed := uint64(0x12345678)

	for i := 0; i < numSamples; i++ {
		data := make([]byte, 8)
		binary.LittleEndian.PutUint64(data, uint64(i))
		hash := Hash64(data, seed)
		// 使用高4位作为桶索引
		bucket := hash >> 60
		buckets[bucket]++
	}

	// 检查分布是否相对均匀（允许20%的偏差）
	expected := numSamples / 16
	for i, count := range buckets {
		deviation := float64(abs(count-expected)) / float64(expected)
		if deviation > 0.2 {
			t.Errorf("Bucket %d has poor distribution: got %d samples, expected %d (%.2f%% deviation)",
				i, count, expected, deviation*100)
		}
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func BenchmarkHash64(b *testing.B) {
	sizes := []int{8, 16, 32, 64, 128, 256, 512, 1024, 4096}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size-%d", size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)
			seed := uint64(0x12345678)

			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				Hash64(data, seed)
			}
		})
	}
}

// 测试验证load64le函数的正确性
func TestLoad64le(t *testing.T) {
	tests := []struct {
		input    []byte
		expected uint64
	}{
		{
			[]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
			0xEFCDAB8967452301,
		},
		{
			[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			0xFFFFFFFFFFFFFFFF,
		},
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			0x0000000000000000,
		},
	}

	for i, tt := range tests {
		result := load64le(tt.input)
		if result != tt.expected {
			t.Errorf("Test %d: expected %x, got %x", i, tt.expected, result)
		}
	}
}
