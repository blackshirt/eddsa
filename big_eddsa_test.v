module ed25519

import math.big
import encoding.hex 

fn test_mod_exp_extended() {
	divisor := big.integer_from_int(632)
	assert mod_pow_ext(big.integer_from_int(324), big.integer_from_int(315), divisor) == big.integer_from_int(512)

	a := big.integer_from_int(65)
	b := big.integer_from_int(2790)
	div := big.integer_from_int(3233)

	assert mod_pow_ext(a, big.integer_from_int(17), div) == b
	assert mod_pow_ext(b, big.integer_from_int(413), div) == a
}

//this test gets very long time to execute
/*
fn test_signature() {
	sk := hex.decode('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60') or {panic(err)}
	msg := []byte{}
	sig := hex.decode('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b') or {panic(err)}

	mut rs, sr := signature(sk, msg) or {panic(err)}
	rs << sr 
	assert sig == rs 

}
*/

