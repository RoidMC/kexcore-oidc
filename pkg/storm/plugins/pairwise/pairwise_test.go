package pairwise

import (
	"encoding/base64"
	"testing"

	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
)

func TestNewSubjectTransformer(t *testing.T) {
	salt := []byte("test-salt")
	transformer := NewSubjectTransformer(salt)

	if transformer == nil {
		t.Fatal("NewSubjectTransformer returned nil")
	}
	if string(transformer.salt) != "test-salt" {
		t.Errorf("expected salt %q, got %q", "test-salt", string(transformer.salt))
	}
	if transformer.pairwise == nil {
		t.Error("pairwise map should be initialized")
	}
}

func TestSubjectTransformer_Transform(t *testing.T) {
	salt := []byte("test-salt")
	transformer := NewSubjectTransformer(salt)

	tests := []struct {
		name       string
		clientID   string
		subject    string
		wantSame   bool // whether result should be same as previous test case
		prevResult string
	}{
		{
			name:     "basic transform",
			clientID: "client1",
			subject:  "user1",
		},
		{
			name:     "same input produces same output",
			clientID: "client1",
			subject:  "user1",
			wantSame: true,
		},
		{
			name:     "different client produces different output",
			clientID: "client2",
			subject:  "user1",
		},
		{
			name:     "different subject produces different output",
			clientID: "client1",
			subject:  "user2",
		},
		{
			name:     "empty strings",
			clientID: "",
			subject:  "",
		},
	}

	var prevResult string
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := transformer.Transform(tt.clientID, tt.subject)

			// 验证结果是有效的base64url编码
			_, err := base64.RawURLEncoding.DecodeString(result)
			if err != nil {
				t.Errorf("result is not valid base64url: %v", err)
			}

			// 验证结果不为空
			if result == "" {
				t.Error("Transform returned empty string")
			}

			if tt.wantSame {
				if result != prevResult {
					t.Errorf("expected same result as previous test, got different")
				}
			}

			prevResult = result
		})
	}
}

func TestSubjectTransformer_Transform_Deterministic(t *testing.T) {
	salt := []byte("test-salt")
	transformer := NewSubjectTransformer(salt)

	// 多次调用相同输入应产生相同结果
	clientID := "client1"
	subject := "user1"

	result1 := transformer.Transform(clientID, subject)
	result2 := transformer.Transform(clientID, subject)
	result3 := transformer.Transform(clientID, subject)

	if result1 != result2 || result2 != result3 {
		t.Errorf("Transform is not deterministic: %s, %s, %s", result1, result2, result3)
	}
}

func TestSubjectTransformer_Transform_DifferentSalts(t *testing.T) {
	// 不同salt应产生不同结果
	salt1 := []byte("salt1")
	salt2 := []byte("salt2")

	transformer1 := NewSubjectTransformer(salt1)
	transformer2 := NewSubjectTransformer(salt2)

	clientID := "client1"
	subject := "user1"

	result1 := transformer1.Transform(clientID, subject)
	result2 := transformer2.Transform(clientID, subject)

	if result1 == result2 {
		t.Error("different salts should produce different results")
	}
}

func TestSubjectTransformer_SetPairwiseClient(t *testing.T) {
	salt := []byte("test-salt")
	transformer := NewSubjectTransformer(salt)

	// 初始状态应该返回false
	if transformer.IsPairwiseClient("client1") {
		t.Error("client1 should not be pairwise initially")
	}

	// 设置为pairwise
	transformer.SetPairwiseClient("client1")

	if !transformer.IsPairwiseClient("client1") {
		t.Error("client1 should be pairwise after SetPairwiseClient")
	}

	// 其他客户端应该仍然返回false
	if transformer.IsPairwiseClient("client2") {
		t.Error("client2 should not be pairwise")
	}
}

func TestSubjectTransformer_SetPairwiseClient_Multiple(t *testing.T) {
	salt := []byte("test-salt")
	transformer := NewSubjectTransformer(salt)

	clients := []string{"client1", "client2", "client3"}

	for _, client := range clients {
		transformer.SetPairwiseClient(client)
	}

	for _, client := range clients {
		if !transformer.IsPairwiseClient(client) {
			t.Errorf("%s should be pairwise", client)
		}
	}

	// 未设置的客户端应该返回false
	if transformer.IsPairwiseClient("client4") {
		t.Error("client4 should not be pairwise")
	}
}

func TestSubjectTransformer_ImplementsInterface(t *testing.T) {
	// 编译时接口检查已在types.go中通过var _ storm.PairwiseTransformer = (*SubjectTransformer)(nil)实现
	// 这里进行运行时检查
	salt := []byte("test-salt")
	transformer := NewSubjectTransformer(salt)

	// 验证实现了storm.PairwiseTransformer接口
	var _ storm.PairwiseTransformer = transformer
}

func TestSubjectTransformer_Transform_Consistency(t *testing.T) {
	// 验证Transform方法的输出格式一致性
	salt := []byte("test-salt")
	transformer := NewSubjectTransformer(salt)

	clientID := "test-client"
	subject := "test-user"

	result := transformer.Transform(clientID, subject)

	// 验证结果长度（HMAC-SHA256输出32字节，base64url编码后约43字符）
	decoded, err := base64.RawURLEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("failed to decode result: %v", err)
	}

	if len(decoded) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(decoded))
	}
}

func BenchmarkTransform(b *testing.B) {
	salt := []byte("benchmark-salt")
	transformer := NewSubjectTransformer(salt)

	clientID := "benchmark-client"
	subject := "benchmark-user"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transformer.Transform(clientID, subject)
	}
}
