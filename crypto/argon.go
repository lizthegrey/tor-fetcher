package crypto

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

type ArgonParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	KeyLength   uint32
	Difficulty  int
	Prefix      string
	Salt        string
}

func (p ArgonParams) Check(n int) bool {
	password := fmt.Sprintf("%s%d", p.Prefix, n)
	hash := argon2.IDKey([]byte(password), []byte(p.Salt), p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	for i, v := range hash[:(p.Difficulty+1)/2] {
		if 2*i == p.Difficulty {
			return true
		}
		if v != 0 {
			if 2*i+1 == p.Difficulty && v>>4 == 0 {
				return true
			}
			break
		}
	}
	return false
}
