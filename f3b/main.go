// TDH2 workload for the F3B comparison. See PROVENANCE.md.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/smartcontractkit/tdh2/go/tdh2/lib/group/nist"
	"github.com/smartcontractkit/tdh2/go/tdh2/tdh2"
)

type randomStream struct{}

func (randomStream) XORKeyStream(dst, src []byte) {
	b := make([]byte, len(src))
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range src {
		dst[i] = src[i] ^ b[i]
	}
}

var group = nist.NewP256()
var random = randomStream{}

type committee struct {
	N, K   int
	PK     *tdh2.PublicKey
	Shares []*tdh2.PrivateShare
}
type envelope struct {
	Key         json.RawMessage
	Nonce, Body []byte
}
type metrics map[string]float64

func elapsed(t time.Time) float64 { return float64(time.Since(t).Nanoseconds()) / 1e6 }
func newCommittee(n, k int) (*committee, error) {
	if n < 1 || k < 1 || k > n {
		return nil, errors.New("invalid threshold")
	}
	ms, pk, shares, err := tdh2.GenerateKeys(group, nil, k, n, random)
	if err != nil {
		return nil, err
	}
	ms.Clear()
	return &committee{n, k, pk, shares}, nil
}
func aead(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
func (c *committee) encrypt(message []byte, context string) ([]byte, metrics, error) {
	m := metrics{}
	all := time.Now()
	t := time.Now()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, m, err
	}
	gcm, err := aead(key)
	if err != nil {
		return nil, m, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, m, err
	}
	label := sha256.Sum256([]byte(context))
	body := gcm.Seal(nil, nonce, message, label[:])
	m["symmetricEncryptMs"] = elapsed(t)
	t = time.Now()
	enc, err := tdh2.Encrypt(c.PK, key, label[:], random)
	if err != nil {
		return nil, m, err
	}
	m["keyEncryptMs"] = elapsed(t)
	t = time.Now()
	raw, err := enc.Marshal()
	if err != nil {
		return nil, m, err
	}
	out, err := json.Marshal(envelope{raw, nonce, body})
	m["cipherEncodeMs"] = elapsed(t)
	m["encryptMs"] = elapsed(all)
	return out, m, err
}
func (c *committee) decodeVerify(raw []byte, context string) (*envelope, *tdh2.Ciphertext, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, err
	}
	enc := &tdh2.Ciphertext{}
	if err := enc.Unmarshal(env.Key); err != nil {
		return nil, nil, err
	}
	if err := enc.Verify(c.PK); err != nil {
		return nil, nil, err
	}
	if enc.Label() != sha256.Sum256([]byte(context)) {
		return nil, nil, errors.New("wrong label")
	}
	if len(env.Nonce) != 12 || len(env.Body) < 16 {
		return nil, nil, errors.New("invalid AEAD framing")
	}
	return &env, enc, nil
}

// Verification and uniqueness checks are mandatory: TDH2 CombineShares assumes them.
func (c *committee) verifyShares(enc *tdh2.Ciphertext, raws [][]byte) ([]*tdh2.DecryptionShare, error) {
	if len(raws) < c.K {
		return nil, errors.New("below threshold")
	}
	shares := make([]*tdh2.DecryptionShare, 0, len(raws))
	seen := map[int]bool{}
	for _, raw := range raws {
		s := &tdh2.DecryptionShare{}
		if err := s.Unmarshal(raw); err != nil {
			return nil, err
		}
		if s.Index() < 0 || s.Index() >= c.N || seen[s.Index()] {
			return nil, errors.New("invalid or duplicate share index")
		}
		if err := tdh2.VerifyShare(c.PK, enc, s); err != nil {
			return nil, err
		}
		seen[s.Index()] = true
		shares = append(shares, s)
	}
	return shares, nil
}
func (c *committee) process(raw []byte, context string) ([]byte, metrics, error) {
	m := metrics{}
	all := time.Now()
	t := time.Now()
	env, enc, err := c.decodeVerify(raw, context)
	if err != nil {
		return nil, m, err
	}
	// One consensus-node check plus each trustee's own check before share generation.
	m["receiverCipherVerifyMs"] = elapsed(t)
	raws := make([][]byte, c.N)
	for i := 0; i < c.N; i++ {
		t = time.Now()
		_, ct, err := c.decodeVerify(raw, context)
		if err != nil {
			return nil, m, err
		}
		m["trusteeCipherVerifySumMs"] += elapsed(t)
		t = time.Now()
		share, err := ct.Decrypt(group, c.Shares[i], random)
		if err != nil {
			return nil, m, err
		}
		m["shareGenerateSumMs"] += elapsed(t)
		t = time.Now()
		raws[i], err = share.Marshal()
		if err != nil {
			return nil, m, err
		}
		m["shareEncodeSumMs"] += elapsed(t)
		m["allShareBytes"] += float64(len(raws[i]))
	}
	// A quorum suffices. Rotate the selected quorum by ciphertext hash; all trials
	// prepare N shares but one receiver verifies exactly K distinct shares.
	offset := int(sha256.Sum256(raw)[0]) % c.N
	quorum := make([][]byte, c.K)
	for i := range quorum {
		quorum[i] = raws[(offset+i)%c.N]
	}
	t = time.Now()
	shares, err := c.verifyShares(enc, quorum)
	if err != nil {
		return nil, m, err
	}
	m["quorumVerifyMs"] = elapsed(t)
	for _, s := range quorum {
		m["quorumShareBytes"] += float64(len(s))
	}
	t = time.Now()
	key, err := enc.CombineShares(group, shares, c.K, c.N)
	if err != nil {
		return nil, m, err
	}
	m["keyReconstructMs"] = elapsed(t)
	t = time.Now()
	gcm, err := aead(key)
	if err != nil {
		return nil, m, err
	}
	label := enc.Label()
	message, err := gcm.Open(nil, env.Nonce, env.Body, label[:])
	if err != nil {
		return nil, m, err
	}
	m["symmetricDecryptMs"] = elapsed(t)
	m["processSerialWorkMs"] = elapsed(all)
	m["trusteeWorkPerMemberMs"] = (m["trusteeCipherVerifySumMs"] + m["shareGenerateSumMs"] + m["shareEncodeSumMs"]) / float64(c.N)
	m["receiverRecoveryMs"] = m["quorumVerifyMs"] + m["keyReconstructMs"] + m["symmetricDecryptMs"]
	return message, m, nil
}

type request struct {
	Op                       string
	N, K                     int
	Message, Cipher, Context string
}

func fromHex(s string) ([]byte, error) { return hex.DecodeString(strings.TrimPrefix(s, "0x")) }
func main() {
	runtime.GOMAXPROCS(1)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 65536), 4<<20)
	out := json.NewEncoder(os.Stdout)
	var c *committee
	for scanner.Scan() {
		func() {
			var req request
			fail := func(err error) { _ = out.Encode(map[string]any{"error": err.Error()}) }
			if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
				fail(err)
				return
			}
			if req.Op == "setup" {
				var err error
				t := time.Now()
				c, err = newCommittee(req.N, req.K)
				if err != nil {
					fail(err)
					return
				}
				pk, _ := c.PK.Marshal()
				_ = out.Encode(map[string]any{"setupMs": elapsed(t), "n": c.N, "k": c.K, "go": runtime.Version(), "group": group.String(), "publicKeyHash": fmt.Sprintf("%x", sha256.Sum256(pk))})
				return
			}
			if c == nil {
				fail(errors.New("setup required"))
				return
			}
			if req.Op == "encrypt" {
				msg, err := fromHex(req.Message)
				if err != nil {
					fail(err)
					return
				}
				raw, m, err := c.encrypt(msg, req.Context)
				if err != nil {
					fail(err)
					return
				}
				_ = out.Encode(map[string]any{"cipher": "0x" + hex.EncodeToString(raw), "metrics": m})
				return
			}
			if req.Op == "process" {
				raw, err := fromHex(req.Cipher)
				if err != nil {
					fail(err)
					return
				}
				msg, m, err := c.process(raw, req.Context)
				if err != nil {
					fail(err)
					return
				}
				if req.Message != "" {
					want, e := fromHex(req.Message)
					if e != nil || !bytes.Equal(msg, want) {
						fail(errors.New("roundtrip mismatch"))
						return
					}
				}
				_ = out.Encode(map[string]any{"message": "0x" + hex.EncodeToString(msg), "metrics": m})
				return
			}
			fail(errors.New("unknown operation"))
		}()
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
