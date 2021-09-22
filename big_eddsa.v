module ed25519

import crypto.sha512
import math.big

const (
	// const using math.big
	big_noll  = big.integer_from_int(0)
	big_one   = big.integer_from_int(1)
	big_two   = big.integer_from_int(2)
	big_three = big.integer_from_int(3)
	big_four  = big.integer_from_int(4)
	big_five  = big.integer_from_int(5)
	big_eight = big.integer_from_int(8)

	
)

const (
	// base field, p = 2**255 - 19
	edp  = '57896044618658097711785492504343953926634992332820282019728792003956564819949'
	// curve constant, d = -121665 * inv(121666)%p
	edd  = '37095705934669439343138083508754565189542113879843219016388785533085940283555'
	// I = pow(2,(p-1)//4,p)
	edi  = '19681161376707505956807079304988542015446066515923890162744021073123829784752'
	// group order
	// q = 2**252 + 27742317777372353535851937790883648493
	edq  = '7237005577332262213973186563042994240857116359379907606001950938285454250989'
	// square root of -1, m1 = pow(2, (p-1) // 4, p)
	edm1 = '19681161376707505956807079304988542015446066515923890162744021073123829784752'
	// g_y = 4 * inv(5) % p
	edgy = '46316835694926478169428394003475163141307993866256225615783033603165251855960'
	// g_x = recover_x(g_y, 0)
	edgx = '15112221349535400772501151409588531511454012693041857206046113283949847762202'
)

const (
	big_edp      = big.integer_from_string(edp) or { panic(err) }
	big_edd      = big.integer_from_string(edd) or { panic(err) }
	big_edi      = big.integer_from_string(edi) or { panic(err) }
	big_edq      = big.integer_from_string(edq) or { panic(err) }

	big_edm1     = big.integer_from_string(edm1) or { panic(err) }
	big_edgy     = big.integer_from_string(edgy) or { panic(err) }
	big_edgx     = big.integer_from_string(edgx) or { panic(err) }

	

	big_edgcoord = BigXCoord{
		x: big_edgx
		y: big_edgy
		z: big_one
		t: big_edgx * big_edgy % big_edp
	}

	

	// Neutral element w big
	big_nqe = BigXCoord{
		x: big_noll
		y: big_one
		z: big_one
		t: big_noll
	}

	
)

// Points are represented as tuples (X, Y, Z, T) of extended
// coordinates, with x = X/Z, y = Y/Z, x*y = T/Z
struct BigXCoord {
	x big.Integer
	y big.Integer
	z big.Integer
	t big.Integer
}



fn inv(x big.Integer) big.Integer {
	return mod_pow_ext(x, ed25519.big_edp - ed25519.big_two, ed25519.big_edp)
}



fn mod_pow_ext(base big.Integer, expbig_onent big.Integer, divisor big.Integer) big.Integer {
	if expbig_onent == big.integer_from_int(0) {
		return ed25519.big_one // big_one_int
	}
	if expbig_onent == ed25519.big_one {
		return base % divisor
	}
	mut n := expbig_onent
	mut x := base % divisor
	mut y := ed25519.big_one
	for n > ed25519.big_one { // n > 1 {
		if n.bitwise_and(ed25519.big_one) == ed25519.big_one { // n & 1 == 1 {
			y = (y * x) % divisor
		}
		x = (x * x) % divisor
		n = n.rshift(1) // n >>= 1
	}
	return (x * y) % divisor
}


fn sha512(s []byte) []byte {
	return sha512.sum512(s)
}

fn from_bytes_modulo(s []byte) big.Integer {
	return big.integer_from_bytes(s) % ed25519.big_edq
}

fn point_add(p BigXCoord, q BigXCoord) BigXCoord {
	a := (p.y - p.x) * (q.y - q.x) % ed25519.big_edp
	b := (p.y + p.x) * (q.y + q.x) % ed25519.big_edp

	c := ed25519.big_two * p.t * q.t * ed25519.big_edd % ed25519.big_edp
	d := ed25519.big_two * p.z * q.z % ed25519.big_edp

	e := b - a
	f := d - c
	g := d + c
	h := b + a

	res := BigXCoord{
		x: e * f
		y: g * h
		z: f * g
		t: e * h
	}
	return res
}



// Computes Q = s * Q
fn point_mul(n big.Integer, p BigXCoord) BigXCoord {
	mut s := n
	mut q := ed25519.big_nqe
	mut pc := p
	for s > ed25519.big_noll {
		if s.bitwise_and(ed25519.big_one) > ed25519.big_noll {
			q = point_add(q, pc)
		}
		pc = point_add(pc, pc)
		s = s.rshift(1)
	}
	return q
}



fn point_equal(p BigXCoord, q BigXCoord) bool {
	// x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1
	if (p.x * q.z - q.x * p.z) % ed25519.big_edp != ed25519.big_noll {
		return false
	}
	if (p.y * q.z - q.y * p.z) % ed25519.big_edp != ed25519.big_noll {
		return false
	}

	return true
}


// Compute corresponding x-coordinate, with low bit corresponding to
// sign, or return error on failure
fn recover_x(y big.Integer, sign big.Integer) ?big.Integer {
	if y >= ed25519.big_edp {
		return error('Nbig_one result of y >= big_edp')
	}
	x2 := (y * y - ed25519.big_one) * inv(ed25519.big_edd * y * y + ed25519.big_one)
	if x2 == ed25519.big_noll {
		return if sign > ed25519.big_noll { error('Nbig_one result') } else { ed25519.big_noll } // if sign > 0 {}
	}

	// Compute square root of x2
	mut x := mod_pow_ext(x2, (ed25519.big_edp + ed25519.big_three) / ed25519.big_eight,
		ed25519.big_edp)
	if (x * x - x2) % ed25519.big_edp != ed25519.big_noll {
		x = x * ed25519.big_edm1 % ed25519.big_edp
	}
	if (x * x - x2) % ed25519.big_edp != ed25519.big_noll {
		return error('Nbig_one result')
	}

	if x.bitwise_and(ed25519.big_one) != sign {
		x = ed25519.big_edp - x
	}
	return x
}



fn point_compress(p BigXCoord) []byte {
	zi := inv(p.z)
	x := p.x * zi % ed25519.big_edp
	y := p.y * zi % ed25519.big_edp

	s := x.bitwise_and(ed25519.big_one)

	res := y.bitwise_or(s.lshift(255))
	// TODO: need to 32 bytes length
	rs, _ := res.bytes()
	return rs
}


fn point_decompress(s []byte) ?BigXCoord {
	if s.len != 32 {
		return error('not 32 bytes input')
	}
	mut y := big.integer_from_bytes(s)
	sign := y.rshift(255)
	mask := ed25519.big_one.lshift(255) - ed25519.big_one
	y = y.bitwise_and(mask)

	x := recover_x(y, sign) ?
	cord := BigXCoord{
		x: x
		y: y
		z: ed25519.big_one
		t: x * y % ed25519.big_edp
	}
	return cord
}



// These are functions for manipulating the private key.
fn secret_expand(secret []byte) ?(big.Integer, []byte) {
	if secret.len != 32 {
		return error('not 32 bytes input')
	}
	h := sha512(secret)
	mut a := big.integer_from_bytes(h[..32])
	a = a.bitwise_and(ed25519.big_one.lshift(254) - ed25519.big_eight)
	a = a.bitwise_or(ed25519.big_one.lshift(254))

	return a, h[32..]
}



fn publickey(secret []byte) ?[]byte {
	a, _ := secret_expand(secret) ?
	return point_compress(point_mul(a, ed25519.big_edgcoord))
}



// The signature function works as below.
fn signature(secret []byte, msg []byte) ?([]byte, []byte) {
	a, mut prefix := secret_expand(secret) ? // big.integer, []byte
	ap := point_compress(point_mul(a, ed25519.big_edgcoord)) //[]byte
	prefix << msg
	r := from_bytes_modulo(prefix) // big.Integer
	rmul := point_mul(r, ed25519.big_edgcoord) // xcord
	mut rs := point_compress(rmul) //[]byte
	rs << ap
	rs << msg
	h := from_bytes_modulo(rs)
	s := (r + h * a) % ed25519.big_edq
	res, _ := s.bytes()
	return rs, res
}



fn verify(public []byte, msg []byte, signature []byte) ?bool {
	if public.len != 32 {
		return error('not 32 length')
	}
	if signature.len != 64 {
		return error('not 64 length')
	}

	ap := point_decompress(public) ? // xcord
	mut rs := signature[..32].clone()
	r := point_decompress(rs) ?
	s := big.integer_from_bytes(signature[32..])

	if s >= ed25519.big_edq {
		return false
	}
	rs << public
	rs << msg
	h := from_bytes_modulo(rs)
	sb := point_mul(s, ed25519.big_edgcoord)
	ha := point_mul(h, ap)

	return point_equal(sb, point_add(r, ha))
}


