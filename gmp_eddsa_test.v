module ed25519

import encoding.hex 


fn test_gmp_signature_1() {
	//from rfc 8032 test vector
	sk := hex.decode('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60') or {panic(err)}
	pk := hex.decode('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a') or {panic(err)}
	msg := []byte{len:0}
	
	sign := hex.decode('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b') or {panic(err)}
	
	mut res := gmp_signature(sk, msg) or {panic(err)}
	
	assert res.len == sign.len 
	assert res == sign 
	//v := gmp_verify(pk, msg, res) or {panic(err)}
	//assert v == true 

}

fn test_gmp_signature_2() {
	//from rfc 8032 test vector
	sk := hex.decode('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb') or {panic(err)}
	pk := hex.decode('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c') or {panic(err)}
	msg := hex.decode('72') or {panic(err)}
	
	sign := hex.decode('92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00') or {panic(err)}
	
	mut res := gmp_signature(sk, msg) or {panic(err)}
	
	assert res.len == sign.len 
	assert res == sign 
	//v := gmp_verify(pk, msg, res) or {panic(err)}
	//assert v == true 

}

fn test_gmp_signature_3() {
	//from https://asecuritysite.com/encryption/eddsa2
	sk := hex.decode('38d555fc69d30269a371871473e4727f7406d40855840b32816367476f6d1f88') or {panic(err)}
	pk := hex.decode('e9f2dcb6bbfb9fbd41d984490265cb624918c3b0eb16b1b30cfeea656a243360') or {panic(err)}
	msg := 'Hello'.bytes()
	
	sign := hex.decode('b31effd71522fb03e1f932d5f4e2115b43f5ae9d793407c752a36b49373399539000dc10cf0ee2695c143df1ce7976102f50c8d999e365522e9b656db63b990f') or {panic(err)}
	
	mut res := gmp_signature(sk, msg) or {panic(err)}
	
	assert res.len == sign.len 
	assert res == sign 
	//v := gmp_verify(pk, msg, res) or {panic(err)}
	//assert v == true 
	

}