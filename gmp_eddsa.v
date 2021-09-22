module ed25519

import gmp 

const (
	// const using gmp.Bigint
	gmp_noll  = gmp.from_u64(0)
	gmp_one   = gmp.from_u64(1)
	gmp_two   = gmp.from_u64(2)
	gmp_three = gmp.from_u64(3)
	gmp_four  = gmp.from_u64(4)
	gmp_five  = gmp.from_u64(5)
	gmp_eight = gmp.from_u64(8)

	gmp_edp   = gmp.from_str(edp) or { panic(err) }
	gmp_edd   = gmp.from_str(edd) or { panic(err) }
	gmp_edi   = gmp.from_str(edi) or { panic(err) }
	gmp_edq   = gmp.from_str(edq) or { panic(err) }

	gmp_edm1  = gmp.from_str(edm1) or { panic(err) }
	gmp_edgy  = gmp.from_str(edgy) or { panic(err) }
	gmp_edgx  = gmp.from_str(edgx) or { panic(err) }

	gmp_edgcoord = GmpXCoord{
		x: gmp_edgx
		y: gmp_edgy
		z: gmp_one
		t: gmp_edgx * gmp_edgy % gmp_edp
	}

	// Neutral element w gmp
	gmp_nqe = GmpXCoord{
		x: gmp_noll
		y: gmp_one
		z: gmp_one
		t: gmp_noll
	}
)

// gmp version of xcoord
struct GmpXCoord {
	x gmp.Bigint
	y gmp.Bigint
	z gmp.Bigint
	t gmp.Bigint
}

fn gmp_modp_inv(x gmp.Bigint) gmp.Bigint {
	// fn invert(a Bigint, m Bigint) (Bigint, int)
	//invs, _ := gmp.invert(x, gmp_edp)
	invs := gmp.powm_sec(x, gmp_edp-gmp_two, gmp_edp)
	return invs
}

fn gmp_sha512_modq(s []byte) ?gmp.Bigint {
	res := gmp_from_little_endian(sha512(s)) ?
    return res % gmp_edq
}

// Points are represented as tuples (X, Y, Z, T) of extended
// coordinates, with x = X/Z, y = Y/Z, x*y = T/Z
fn gmp_point_add(p GmpXCoord, q GmpXCoord) GmpXCoord {
	a := (p.y - p.x) * (q.y - q.x) % gmp_edp
	b := (p.y + p.x) * (q.y + q.x) % gmp_edp

	c := gmp_two * p.t * q.t * gmp_edd % gmp_edp
	d := gmp_two * p.z * q.z % gmp_edp

	e := b - a
	f := d - c
	g := d + c
	h := b + a

	res := GmpXCoord{
		x: e * f
		y: g * h
		z: f * g
		t: e * h
	}
	return res
}

//# Computes Q = s * Q
fn gmp_point_mul(n gmp.Bigint, p GmpXCoord) GmpXCoord {
	mut s := n.clone()
	mut q := gmp_nqe
	mut pc := p
	for s > gmp_noll {
		if gmp.and(s, gmp_one) != gmp_noll {
			q = gmp_point_add(q, pc)
		}
		pc = gmp_point_add(pc, pc)
		// For positive n both mpz_fdiv_q_2exp and mpz_tdiv_q_2exp are simple bitwise right shifts
		// fn tdiv_q_2exp(n Bigint, b u64) Bigint
		s = gmp.tdiv_q_2exp(s, u64(1)) // s.rshift(1)
	}
	return q
}


fn gmp_point_equal(p GmpXCoord, q GmpXCoord) bool {
	// x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1
	if (p.x * q.z - q.x * p.z) % gmp_edp != gmp_noll {
		return false
	}
	if (p.y * q.z - q.y * p.z) % gmp_edp != gmp_noll {
		return false
	}

	return true
}

fn gmp_recover_x(y gmp.Bigint, sign gmp.Bigint) ?gmp.Bigint {
	if y >= gmp_edp {
		return error('gmp_one result of y >= gmp_edp')
	}
	x2 := (y * y - gmp_one) * gmp_modp_inv(gmp_edd * y * y + gmp_one)
	if x2 == gmp_noll {
		return if sign != gmp_noll { error('gmp_one result') } else { gmp_noll } // if sign > 0 {} //need attention!!
	}

	// Compute square root of x2
	mut x := gmp.powm_sec(x2, (gmp_edp + gmp_three) / gmp_eight, gmp_edp)
	if (x * x - x2) % gmp_edp != gmp_noll {
		x = x * gmp_edm1 % gmp_edp
	}
	if (x * x - x2) % gmp_edp != gmp_noll {
		return error('gmp_one result')
	}

	if gmp.and(x, gmp_one) != sign {
		x = gmp_edp - x
	}
	return x
}

fn gmp_point_compress(p GmpXCoord) ?[]byte {
	zi := gmp_modp_inv(p.z)
	x := p.x * zi % gmp_edp
	y := p.y * zi % gmp_edp

	

	// res := y.bitwise_or(s.lshift(255))
	// ior == inclusive bitwise or
	//res = int.to_bytes(y | ((x & 1) << 255), 32, "little")
	res := gmp.ior(y, gmp.mul_2exp(gmp.and(x, gmp_one), 255)) // y.bitwise_or(s.lshift(255))
	// TODO: need to 32 bytes length
	rs := gmp_to_little_endian(res, 32) ?
	
	return rs
}

fn gmp_point_decompress(s []byte) ?GmpXCoord {
	if s.len != 32 {
		return error('not 32 bytes input')
	}
	mut y := gmp_from_little_endian(s) ?

	sign := gmp.tdiv_q_2exp(y, 255) // right shift y >> 255
	// gmp.mul_2exp == lshift
	mask := gmp.mul_2exp(gmp_one, 255) - gmp_one
	y = gmp.and(y, mask)

	x := gmp_recover_x(y, sign) ?
	cord := GmpXCoord{
		x: x
		y: y
		z: gmp_one
		t: x * y % gmp_edp
	}
	return cord
}

fn gmp_secret_expand(secret []byte) ?(gmp.Bigint, []byte) {
	if secret.len != 32 {
		return error('not 32 bytes input')
	}
	h := sha512(secret)
	mut a := gmp_from_little_endian(h[..32].clone()) ?
	a = gmp.and(a, (gmp.mul_2exp(gmp_one, u64(254)) - gmp_eight))
	a = gmp.ior(a, gmp.mul_2exp(gmp_one, u64(254)))

	return a, h[32..]
}

fn gmp_publickey(secret []byte) ?[]byte {
	a, _ := gmp_secret_expand(secret) ?
	return gmp_point_compress(gmp_point_mul(a, gmp_edgcoord))
}


// The signature function works as below.
fn gmp_signature(secret []byte, msg []byte) ?[]byte {
	/*
	a, prefix = secret_expand(secret)
    A = point_compress(point_mul(a, G))
    r = sha512_modq(prefix + msg)
    R = point_mul(r, G)
    Rs = point_compress(R)
    h = sha512_modq(Rs + A + msg)
    s = (r + h * a) % q
    return Rs + int.to_bytes(s, 32, "little")
	*/
	a, mut prefix := gmp_secret_expand(secret) ? //
	ap := gmp_point_compress(gmp_point_mul(a, gmp_edgcoord)) ?//[]byte
	
	prefix << msg

	r := gmp_sha512_modq(prefix)?
	rmul := gmp_point_mul(r, gmp_edgcoord) // xcord
	
	mut rs := gmp_point_compress(rmul) ?//[]byte
	mut rsc := rs.clone()

	rsc << ap
	rsc << msg
	
	h := gmp_sha512_modq(rsc)?
	
	s := (r + h * a) % gmp_edq
	res := gmp_to_little_endian(s, 32) ?
	rs << res 
	
	return rs
}

fn gmp_verify(public []byte, msg []byte, signature []byte) ?bool {
	if public.len != 32 {
		return error('not 32 length')
	}
	if signature.len != 64 {
		return error('not 64 length')
	}

	ap := gmp_point_decompress(public) ? // xcord
	mut rs := signature[..32].clone()
	r := gmp_point_decompress(rs) ?
	s := gmp_from_little_endian(signature[32..].clone())?

	if s >= gmp_edq {
		return false
	}
	rs << public
	rs << msg
	h := gmp_sha512_modq(rs) ?
	sb := gmp_point_mul(s, gmp_edgcoord)
	ha := gmp_point_mul(h, ap)

	return gmp_point_equal(sb, gmp_point_add(r, ha))
}