package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestThresholdRoundTrips(t *testing.T) {
	for _, n := range []int{8, 32, 128} {
		c, err := newCommittee(n, n/2)
		if err != nil {
			t.Fatal(err)
		}
		msg := bytes.Repeat([]byte{42}, 384)
		raw, _, err := c.encrypt(msg, "epoch1")
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := c.process(raw, "epoch1")
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("n=%d: %v", n, err)
		}
	}
}
func TestRejectCipherAndShareTampering(t *testing.T) {
	c, _ := newCommittee(8, 4)
	raw, _, _ := c.encrypt([]byte("transaction"), "epoch1")
	env, ct, err := c.decodeVerify(raw, "epoch1")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("wrong context", func(t *testing.T) {
		if _, _, e := c.decodeVerify(raw, "epoch2"); e == nil {
			t.Fatal("accepted wrong epoch")
		}
	})
	t.Run("wrong committee", func(t *testing.T) {
		other, _ := newCommittee(8, 4)
		if _, _, e := other.decodeVerify(raw, "epoch1"); e == nil {
			t.Fatal("accepted wrong committee")
		}
	})
	t.Run("tampered key ciphertext", func(t *testing.T) {
		var v map[string]json.RawMessage
		_ = json.Unmarshal(env.Key, &v)
		var b []byte
		_ = json.Unmarshal(v["C"], &b)
		b[0] ^= 1
		v["C"], _ = json.Marshal(b)
		k, _ := json.Marshal(v)
		e := *env
		e.Key = k
		bad, _ := json.Marshal(e)
		if _, _, err := c.decodeVerify(bad, "epoch1"); err == nil {
			t.Fatal("accepted corrupted key")
		}
	})
	t.Run("tampered symmetric ciphertext", func(t *testing.T) {
		e := *env
		e.Body = append([]byte{}, env.Body...)
		e.Body[0] ^= 1
		bad, _ := json.Marshal(e)
		if _, _, err := c.process(bad, "epoch1"); err == nil {
			t.Fatal("accepted corrupted payload")
		}
	})
	raws := make([][]byte, 4)
	for i := range raws {
		s, _ := ct.Decrypt(group, c.Shares[i], random)
		raws[i], _ = s.Marshal()
	}
	t.Run("below threshold", func(t *testing.T) {
		if _, e := c.verifyShares(ct, raws[:3]); e == nil {
			t.Fatal("accepted 3 of 4")
		}
	})
	t.Run("duplicate shares", func(t *testing.T) {
		b := append([][]byte{}, raws...)
		b[3] = b[0]
		if _, e := c.verifyShares(ct, b); e == nil {
			t.Fatal("accepted duplicate")
		}
	})
	t.Run("tampered share proof", func(t *testing.T) {
		var v map[string]json.RawMessage
		_ = json.Unmarshal(raws[0], &v)
		var b []byte
		_ = json.Unmarshal(v["F_i"], &b)
		b[len(b)-1] ^= 1
		v["F_i"], _ = json.Marshal(b)
		bad, _ := json.Marshal(v)
		rs := append([][]byte{}, raws...)
		rs[0] = bad
		if _, e := c.verifyShares(ct, rs); e == nil {
			t.Fatal("accepted bad proof")
		}
	})
	t.Run("share from different ciphertext", func(t *testing.T) {
		other, _, _ := c.encrypt([]byte("other"), "epoch1")
		_, ot, _ := c.decodeVerify(other, "epoch1")
		s, _ := ot.Decrypt(group, c.Shares[0], random)
		bad, _ := s.Marshal()
		rs := append([][]byte{}, raws...)
		rs[0] = bad
		if _, e := c.verifyShares(ct, rs); e == nil {
			t.Fatal("accepted unrelated share")
		}
	})
	t.Run("nonconsecutive quorum", func(t *testing.T) {
		rs := make([][]byte, 4)
		for j, i := range []int{1, 3, 5, 7} {
			s, _ := ct.Decrypt(group, c.Shares[i], random)
			rs[j], _ = s.Marshal()
		}
		shares, e := c.verifyShares(ct, rs)
		if e != nil {
			t.Fatal(e)
		}
		key, e := ct.CombineShares(group, shares, 4, 8)
		if e != nil {
			t.Fatal(e)
		}
		g, _ := aead(key)
		label := ct.Label()
		p, e := g.Open(nil, env.Nonce, env.Body, label[:])
		if e != nil || string(p) != "transaction" {
			t.Fatal("wrong recovered key")
		}
	})
	t.Run("invalid index", func(t *testing.T) {
		var v map[string]json.RawMessage
		_ = json.Unmarshal(raws[0], &v)
		v["Index"] = json.RawMessage("9")
		bad, _ := json.Marshal(v)
		rs := append([][]byte{}, raws...)
		rs[0] = bad
		if _, e := c.verifyShares(ct, rs); e == nil {
			t.Fatal("accepted bad index")
		}
	})
}
