package schnorr

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/chacha20"
)

var curve = secp256k1.S256()

func pad(x []byte, n int) []byte {
	pad := make([]byte, n-len(x))
	return append(pad, x...)
}

func bytes32(x *big.Int) []byte {
	return pad(x.Bytes(), 32)
}

func bytes64(x *big.Int) []byte {
	return pad(x.Bytes(), 64)
}

func is_infinity(x *big.Int, y *big.Int) bool {
	return x == nil || y == nil
}

func is_square(x *big.Int) bool {
	p := curve.Params().P
	exp := new(big.Int)
	exp.Sub(p, big.NewInt(1))
	exp.Div(exp, big.NewInt(2))
	return x.Exp(x, exp, p).Cmp(big.NewInt(1)) == 0
}

func has_square_y(x, y *big.Int) bool {
	return !is_infinity(x, y) && is_square(y)
}

func lift_x(x *big.Int) (*big.Int, *big.Int, error) {
	if x.Cmp(big.NewInt(0)) == -1 || x.Cmp(curve.P) == 1 {
		return nil, nil, errors.New("Bad x")
	}
	c := new(big.Int)
	c.Exp(x, big.NewInt(3), curve.P)
	c.Add(c, big.NewInt(7))
	c.Mod(c, curve.P)
	exp := new(big.Int)
	exp.Add(curve.P, big.NewInt(1))
	exp.Div(exp, big.NewInt(4))
	y := new(big.Int)
	y.Exp(c, exp, curve.P)
	ysquared := new(big.Int)
	ysquared.Exp(y, big.NewInt(2), curve.P)
	if c.Cmp(ysquared) != 0 {
		return nil, nil, errors.New("Bad c")
	}
	return x, y, nil
}

func lift_x_even_y(x *big.Int) (*big.Int, *big.Int, error) {
	Px, Py, err := lift_x(x)
	if err != nil {
		return nil, nil, err
	}
	if new(big.Int).Mod(Py, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		return Px, Py, nil
	} else {
		Py.Sub(curve.P, Py)
		return Px, Py, nil
	}
}

func point(x []byte) (*big.Int, *big.Int, error) {
	if len(x) != 32 {
		panic("Bad x len")
	}
	return lift_x(new(big.Int).SetBytes(x))
}

func hash(tag string, x []byte) []byte {
	tagHash := sha256.Sum256([]byte(tag))
	toHash := tagHash[:]
	toHash = append(toHash, tagHash[:]...)
	toHash = append(toHash, x...)
	hashed := sha256.Sum256(toHash)
	return pad(hashed[:], 32)
}

func PubKey(sk []byte) []byte {
	if len(sk) != 32 {
		panic("Bad secret key length")
	}
	d := new(big.Int)
	d.SetBytes(sk)
	n := curve.Params().N
	if d.Cmp(big.NewInt(0)) == 0 || d.Cmp(n) >= 0 {
		panic("Bad secret key value")
	}
	x, _ := curve.ScalarBaseMult(bytes32(d))
	return bytes32(x)
}

func Sign(sk, m []byte) []byte {
	if len(sk) != 32 {
		panic("Bad secret key length")
	}
	if len(m) != 32 {
		panic("Bad message length")
	}
	dprime := new(big.Int)
	dprime.SetBytes(sk)
	n := curve.Params().N
	if dprime.Cmp(big.NewInt(0)) == 0 || dprime.Cmp(n) >= 0 {
		panic("Bad secret key value")
	}
	Px := new(big.Int)
	Py := new(big.Int)
	Px, Py = curve.ScalarBaseMult(bytes32(dprime))
	d := new(big.Int)
	if has_square_y(Px, Py) {
		d.Set(dprime)
	} else {
		d.Sub(n, dprime)
	}
	rand := make([]byte, 0)
	rand = hash("BIPSchnorrDerive", append(bytes32(d), m...))
	kprime := new(big.Int)
	kprime.SetBytes(rand)
	kprime.Mod(kprime, n)
	if kprime.Cmp(big.NewInt(0)) == 0 {
		panic("Bad kprime")
	}
	Rx := new(big.Int)
	Ry := new(big.Int)
	Rx, Ry = curve.ScalarBaseMult(bytes32(kprime))
	k := new(big.Int)
	if has_square_y(Rx, Ry) {
		k.Set(kprime)
	} else {
		k.Sub(n, kprime)
	}
	e := new(big.Int)
	toHash := make([]byte, 0)
	toHash = append(toHash, bytes32(Rx)...)
	toHash = append(toHash, bytes32(Px)...)
	toHash = append(toHash, m...)
	e.SetBytes(hash("BIPSchnorr", toHash))
	e.Mod(e, n)
	sig := make([]byte, 0)
	sig = append(sig, bytes32(Rx)...)
	res := new(big.Int)
	res.Mul(e, d)
	res.Add(res, k)
	res.Mod(res, n)
	sig = append(sig, bytes32(res)...)
	return sig
}

func Verify(pk, m, sig []byte) bool {
	if len(pk) != 32 {
		panic("Bad pub key length")
	}
	if len(m) != 32 {
		panic("Bad message length")
	}
	if len(sig) != 64 {
		panic("Bad signature length")
	}
	Px, Py, err := point(pk)
	if err != nil {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	if r.Cmp(curve.P) >= 0 {
		return false
	}
	s := new(big.Int).SetBytes(sig[32:])
	if s.Cmp(curve.N) >= 0 {
		return false
	}
	toHash := bytes32(r)
	toHash = append(toHash, bytes32(Px)...)
	toHash = append(toHash, m...)
	e := new(big.Int).SetBytes(hash("BIPSchnorr", toHash))
	e.Mod(e, curve.N)
	e.Sub(curve.N, e)
	Rx1, Ry1 := curve.ScalarBaseMult(bytes32(s))
	Rx2, Ry2 := curve.ScalarMult(Px, Py, bytes32(e))
	recovered := false
	Rx := new(big.Int)
	Ry := new(big.Int)
	func() {
		defer func() {
			if r := recover(); r != nil {
				recovered = true
			}
		}()
		Rx, Ry = curve.Add(Rx1, Ry1, Rx2, Ry2)
	}()
	if recovered || !has_square_y(Rx, Ry) || Rx.Cmp(r) != 0 {
		return false
	}
	return true
}

func BatchVerify(u int, pk, m, sig [][]byte) bool {
	if len(pk) != u || len(m) != u || len(sig) != u {
		panic("Bad array length")
	}
	for i := 0; i < u; i++ {
		if len(pk[i]) != 32 {
			panic("Bad public key length")
		}
		if len(m[i]) != 32 {
			panic("Bad message length")
		}
		if len(sig[i]) != 64 {
			panic("Bad signature length")
		}
	}
	var a, Px, Py, r, s, e, Rx, Ry []*big.Int
	a = make([]*big.Int, u)
	Px = make([]*big.Int, u)
	Py = make([]*big.Int, u)
	r = make([]*big.Int, u)
	s = make([]*big.Int, u)
	e = make([]*big.Int, u)
	Rx = make([]*big.Int, u)
	Ry = make([]*big.Int, u)
	a[0] = big.NewInt(1)
	var seed []byte
	for i := 0; i < u; i++ {
		seed = append(seed, pk[i]...)
		seed = append(seed, m[i]...)
		seed = append(seed, sig[i]...)
	}
	seedFixed := sha256.Sum256(seed)
	seed = seedFixed[:]
	for i := 1; i < u; i++ {
		//a[i] = big.NewInt(int64(i + 1))
		bytes, _ := chacha20.HChaCha20(seed, pad(big.NewInt(0).Bytes(), 16))
		a[i] = new(big.Int).SetBytes(bytes)
		if a[i].Cmp(big.NewInt(0)) <= 0 || a[i].Cmp(curve.N) >= 0 {
			i--
		}
	}
	for i := 0; i < u; i++ {
		var err error
		Px[i], Py[i], err = lift_x_even_y(new(big.Int).SetBytes(pk[i]))
		if err != nil {
			return false
		}
		r[i] = new(big.Int).SetBytes(sig[i][:32])
		if r[i].Cmp(curve.P) >= 0 {
			return false
		}
		s[i] = new(big.Int).SetBytes(sig[i][32:])
		if s[i].Cmp(curve.N) >= 0 {
			return false
		}
		toHash := bytes32(r[i])
		toHash = append(toHash, bytes32(Px[i])...)
		toHash = append(toHash, m[i]...)
		e[i] = new(big.Int).SetBytes(hash("BIP340/challenge", toHash))
		e[i].Mod(e[i], curve.N)
		Rx[i], Ry[i], err = lift_x(r[i])
		if err != nil {
			return false
		}
	}
	var temp1, temp2x, temp2y, res1x, res1y, res2x, res2y *big.Int
	temp1 = big.NewInt(0)
	for i := 0; i < u; i++ {
		x := new(big.Int).Mul(a[i], s[i])
		temp1.Add(temp1, x)
	}
	temp1.Mod(temp1, curve.N)
	res1x, res1y = curve.ScalarBaseMult(temp1.Bytes())
	temp2x = Rx[0]
	temp2y = Ry[0]
	for i := 1; i < u; i++ {
		x, y := curve.ScalarMult(Rx[i], Ry[i], a[i].Bytes())
		temp2x, temp2y = curve.Add(temp2x, temp2y, x, y)
	}
	for i := 0; i < u; i++ {
		s := new(big.Int).Mul(a[i], e[i])
		s.Mod(s, curve.N)
		x, y := curve.ScalarMult(Px[i], Py[i], s.Bytes())
		temp2x, temp2y = curve.Add(temp2x, temp2y, x, y)
	}
	res2x = temp2x
	res2y = temp2y
	if res2x.Cmp(res1x) != 0 || res2y.Cmp(res1y) != 0 {
		return false
	}
	return true
}
