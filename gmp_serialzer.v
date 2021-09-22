module ed25519

import gmp 


//serialize gmp.Bigint `n` to array of bytes with byteorder `order`
fn gmp_serialize_to_bytes(n gmp.Bigint, order int) ?[]byte {
	if order !in [1, -1] {
		return error('Not allowed order $order')
	}
	
	bits_needed := gmp.sizeinbase(n, 2)

	// from mpz manual
	size := sizeof(byte) // 1
	numb := 8 * size // - nail
	count := int((bits_needed + numb - 1) / numb)
	buf := []byte{len: count}
	res_count := u64(0)
	// pub fn export (ret &byte, count &u64, order int, size u64, endian int, nails u64, a Bigint)
	_ := gmp.export(buf.data, &res_count, order, size, 0, 0, n)
	// unsafe { assert res == buf.data }
	// assert res_count == count

	return buf

}

// to_bytes serialize the Bigint `n` number to fixed size of b bytes
// its taken from from gmp_integer_test.v
fn gmp_to_bytes(n gmp.Bigint, b int, order int) ?[]byte {
	if order !in [1, -1] {
		return error('Not allowed order $order')
	}
	bits_needed := gmp.sizeinbase(n, 2)

	// from mpz manual
	size := sizeof(byte) // 1
	numb := 8 * size // - nail
	count := int((bits_needed + numb - 1) / numb)
	if count > b {
		return error('Overflow error, $n.str() too big to convert to $b bytes')
	}
	// p = malloc (count * size)
	buf := []byte{len: b}
	res_count := u64(0)
	
	_ := gmp.export(buf.data, &res_count, order, size, 0, 0, n)

	return buf
}

fn gmp_to_little_endian(n gmp.Bigint, b int) ?[]byte {
	return gmp_to_bytes(n, b, -1)
}

// from_bytes converts array of bytes `buf` to gmp.Bigint
fn gmp_from_bytes(buf []byte, order int) ?gmp.Bigint {
	if order !in [1, -1] {
		return error('Not allowed order')
	}
	if buf.len == 0 {
		return gmp_noll
	}
	size := sizeof(byte)
	res_count := u64(buf.len)
	mut num := gmp.mpz_import(res_count, order, size, 0, 0, buf.data)
	return num
}

// from little endian
fn gmp_from_little_endian(s []byte) ?gmp.Bigint {
	// order=1 == msb (big), order = -1 == lsb (little)
	return gmp_from_bytes(s, -1)
}
