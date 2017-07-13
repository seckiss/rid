package rid

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/big"
	mathrand "math/rand"
	"regexp"
	"strconv"
	"sync"
)

///////////////////////////////////////////////////////////////////////////
// base62 n-char random UID, generated from 62-chars, can be decoded as base62 or base64 (resulting in a subset of n*8-bit values).
///////////////////////////////////////////////////////////////////////////

var B62ascii = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
var b62asciiMod = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
var b62regexp = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

type internalRandType struct {
	lk sync.Mutex
	r1 *mathrand.Rand
	r2 *mathrand.Rand
}

var internalRand = &internalRandType{r1: mathrand.New(mathrand.NewSource(NewInt63Crypto())), r2: mathrand.New(mathrand.NewSource(NewInt63Crypto()))}

// RID16: 16-chars of base62 gives about 95.3 bits of entropy
// This gives the space of about 10^10 generated ids with probability of collision = 10^-9 according to birthday paradox calcs
func NewRID16() string {
	return NewRIDn(16)
}

// RID20: 20-chars of base62 gives 119.1 bits of entropy
func NewRID20() string {
	return NewRIDn(20)
}

// total length should be 36 characters
func NewRID20Signed(secret string) string {
	var r = NewRIDn(20)
	return r + HMAC(r, secret)

}

// first 16 characters of hexed sha256 hmac
func HMAC(message string, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	bytes := mac.Sum(nil)
	return hex.EncodeToString(bytes[:8])
}

// Optimized version, should be crypto secure
func NewRIDn(n int) string {
	internalRand.lk.Lock()
	defer internalRand.lk.Unlock()
	var b = make([]byte, n)
	var b1 = make([]byte, n/2+1)
	var b2 = make([]byte, n/2+1)
	internalRand.r1.Read(b1)
	internalRand.r2.Read(b2)
	var c byte
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			c = b1[i/2]
		} else {
			c = b2[i/2]
		}
		if c >= 248 {
			c = byte(internalRand.r1.Intn(62))
		}
		b[i] = b62asciiMod[c]
	}
	// reseed with crypto seed from time to time
	if b1[0] == 0 && b2[0] == 0 {
		internalRand.r1.Seed(NewInt63Crypto())
		internalRand.r2.Seed(NewInt63Crypto())
	}
	return string(b)
}

func NewNID() string {
	return strconv.Itoa(int(NewInt63Crypto() % 1000000000))
}

func DashNID(nid string) string {
	return fmt.Sprintf("%s-%s-%s", nid[:3], nid[3:6], nid[6:])
}

///////////////////////////////////////////////////////////////////////////
// Pure crypto random generators
///////////////////////////////////////////////////////////////////////////

// RID16: 16-chars of base62 gives about 95.3 bits of entropy
// This gives the space of about 10^10 generated ids with probability of collision = 10^-9 according to birthday paradox calcs
func NewRID16Crypto() string {
	return NewRIDnCrypto(16)
}

// RID20: 20-chars of base62 gives 119.1 bits of entropy
func NewRID20Crypto() string {
	return NewRIDnCrypto(20)
}

func NewRIDnCrypto(n int) string {
	var b = make([]byte, n)
	for i := 0; i < n; i++ {
		biggie, err := rand.Int(rand.Reader, big.NewInt(62))
		if err != nil {
			//severe error - looks like a failure of system random number generator
			log.Fatal(err)
		}
		b[i] = B62ascii[biggie.Int64()]
	}
	return string(b)
}

func NewInt63Crypto() int64 {
	biggie, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		//severe error - looks like a failure of system random number generator
		log.Fatal(err)
	}
	return biggie.Int64()
}

///////////////////////////////////////////////////////////////////////////
// Replacements for testing purposes
///////////////////////////////////////////////////////////////////////////

func NewRID16Math() string {
	return NewRIDnMath(16)
}
func NewRID20Math() string {
	return NewRIDnMath(20)
}
func NewRIDnMath(n int) string {
	var b = make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = B62ascii[mathrand.Intn(62)]
	}
	return string(b)
}

///////////////////////////////////////////////////////////////////////////
// Validators
///////////////////////////////////////////////////////////////////////////

func ValidRID16(rid string) bool {
	return len(rid) == 16 && b62regexp.MatchString(rid)
}

func ValidRID20(rid string) bool {
	return len(rid) == 20 && b62regexp.MatchString(rid)
}

func ValidRID20Signed(r string, secret string) bool {
	//fmt.Printf("\n\n\nr=%v, len(r)=%v\n\n", r, len(r))
	if len(r) != 36 {
		return false
	}
	rid, hexed := r[:20], r[20:]
	//fmt.Printf("\n\nrid=%v, hexed=%v\n\n", rid, hexed)
	if !ValidRID20(rid) {
		return false
	}
	return hexed == HMAC(rid, secret)
}
