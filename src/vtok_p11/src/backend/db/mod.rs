// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::crypto;
use crate::defs;
use crate::pkcs11;

pub mod object;

pub use object::{Object, ObjectHandle, ObjectKind};

// NOTE: for now, we use these *Info structs to construct key objects. The source PEM is
// preserved, so that a crypto::Pkey (an EVP_PKEY wrapper) can be constructed whenever
// it is needed (e.g. at operation context initialization).
// If the PEM to EVP_PKEY conversion turns out to impact performance, we could construct
// the crypto::Pkey object at DB creation time, and replace the *Info structs with it,
// provided we also implement a proper cloning mechanism for crypto::Pkey. This is needed
// in order to make sure that each session gets its own copy of each key, and maintain
// thread safety.
// Cloning could be done via RSAPrivateKey_dup() and EC_KEY_dup(), together with a TryClone
// trait, since these operations can fail.
#[derive(Clone)]
pub struct RsaKeyInfo {
    pub priv_pem: String,
    pub id: pkcs11::CK_BYTE,
    pub label: String,
    pub num_bits: pkcs11::CK_ULONG,
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
}

#[derive(Clone)]
pub struct EcKeyInfo {
    pub priv_pem: String,
    pub id: pkcs11::CK_BYTE,
    pub label: String,
    pub params_x962: Vec<u8>,
    pub point_q_x962: Vec<u8>,
}

// TODO: Remove the test data and from_test_data() function after
// provisioning is up
const TEST_KEYS: [&str; 8] = [
    // EC secp224r1
    r#"-----BEGIN EC PRIVATE KEY-----
MGgCAQEEHBliO/7ebSnblR51A+5QpIuqoa7JNaYWa4FDSJOgBwYFK4EEACGhPAM6
AATcUKTxN60XBMV98ktDN6Nd0996BRa5gWOYHx/lErTx9Z33Z5gOTjxDV5REnhiT
IKMGescI2pcZsg==
-----END EC PRIVATE KEY-----"#,
    // EC secp384r1
    r#"-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAvvRqzCwO4NOlVMfzCnSjyFTXKWbaWe8utfFEjROwKxMjnq3IrQ06w
hGHRHHahEAKgBwYFK4EEACKhZANiAAQCsBlLwna/k7TMPZuY+MhVz3qcfPjt660H
9Uu1pH4gnIqJiz8nS9xc3CNMXQOaaCEtWoEVZbzXShzavpQLvH8S5u24dNcQDvvz
Xcec+aUTm4HWh8cuwo2/TEyx7eegoIs=
-----END EC PRIVATE KEY-----"#,
    // EC secp521r1
    r#"-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAA7FUvsn97Vv3YLI/v+AMjcqna9H2UJZTVKcQST5A0Zpxx3X/hPO1
6YqlBTzAoeMU00rTN9nTYLgwJ15+AyubFoGgBwYFK4EEACOhgYkDgYYABAC09996
lWIDSFwtQQ1eAtkhEAWed22gQKkbiR3NniDaJeMmcAsubX5kX0WTTruilDhPSIzD
gXe/wb59Ca95UY2UOwHtvm8GjJwRZ5rwpCd1D2286bE+2C5nborfsYzu8wqArEFu
/oTffTv7AgBjYAf8lYA/uqtkXUCTAknZtvNrrw+s0g==
-----END EC PRIVATE KEY-----"#,
    // EC prime256v1
    r#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINpl5sf1J1m/k6TcrSgQoNrPQ9tcArgfTQO/xdVpK8l8oAoGCCqGSM49
AwEHoUQDQgAEA1arY6mohfzvyH2TC6OMMGrg338CSY/B2Ev16gEDY0gz0sdpmYZY
u9dJIJy8PpVoRBB+RsZqBvmoShVOI97yHA==
-----END EC PRIVATE KEY-----"#,
    // RSA 1024
    r#"-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC7cNOXy0aIizwsB7d43H+RJAHXSGaKCqvzjO4osSr104Ci+5gH
i7g9y1+bI86y6gotszmbXuvUVQgpcNOqlGE9FZ6K35dUwFxfTdM1IMcc3OiTF8WJ
Btm6ZRTd1g/LUzBygKypSt5uk+m3kPOJM+QXjIKC8GaiuYWDoG3okekH1wIDAQAB
AoGBAKAgg/KySoBNiksHEJskq6ofe58hj8+vzDPVGoQSzmORmtwhWUBhATVxLyzG
y0cXHzjpWnY8AfWz6rQUWg7okaP5qEXV8ZsooBFo7wbSMn8C+2aEpwg0874FE4sb
NiFQjoeaKe09u2oZJjce8q6kKt6UTzBlQneYxLS4y9Dvxb+5AkEA50HqmUWCkPhz
NhYcejaH7NBtvj24rr2rzhVFbZ+aos1/Uygv/hjofrMaYoq5O6Cc2ZkGyJCwZn+G
gDasrAY0pQJBAM9+x8MAEH95+HrG3BPtmoOdW8j0e/osLy3GEWkv4oYSyx6fWVzT
wQ5nSXL4YZ0JFvoD7KoMEmGGpIboJ2tw1csCQD3Gswe8tNNLO2OwZm0TUh4l05sl
W8d6LYIA1qohH6rr4F5zdtaXCsyFxb+bNT5DeoL6SQCc/jJzUJfBg0D0620CQQCL
7Y+BbXWywepTwe+AcOeWgnP3XQiOeWWHlN8A9I3qpJneGNAGzbaPpA/gPKh3Yj3g
dO0Q7/slUct6Puz2g61pAkBZiayIAfb3oDvPVA+RJgfSK7Gx/pDXNK8NZrJ+P+ee
lFLs+UPv8RB2kbW/MkJF6Lm1/UI2oFtE0oBqAa4M/0Fi
-----END RSA PRIVATE KEY-----"#,
    // RSA 2048
    r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyIs5jOKydKsyf9zTwIOgdnozznZEwJqAoX3sTOL6aNBTMTUQ
ICFn8DUkkwQivmJOZ3jfssBvzRJAKdMjf1VVxF99XqJR/KkIlyW1Hx7L81z04zg1
2IrAjK/h/qphoLXgycURwBGQiDgzTpUkli/729oZdDYuGvoLwh323Oj0NJ/MUMNy
5pK3+cpf47MxwDpgYnN+IK5IeOF+H2Rv+mcAEbhuCPSTdqiLNSyr3cNV13R6Bw6a
Vjqs14NxAMq2sCsUywvk/t2d6d9i55SApPNZAef93XuiECissW7djyHnTzbwMONM
rdNoEJHay4VMT8d1a9/6NV6UQDq451GO0JR/VQIDAQABAoIBAD7val0rW6O/gjac
P5vf8wCbcxytAwCKvClyEjFC3iD8l88OfwQGV88LbnHwz1J+GWrhhRpcx/lMa/R0
PWSdjC/3Y6nKOP6YsYh1nfSpPooeNwADyOovCSRdogfAwqijy2qmvN5Q5NHLCVb0
+Slk355sQKa2xhtTM1N1Ad7sAI9us/9yzZaobtViHE6CgP+AFOwUt8GtAW1jYaWr
fj7P506VnmrZG/mpWJvPnH6gnDwfy28MlkoteM4886+VhDSTv0wJS9xWKydBcClO
Msh80Ele5JehuJ3blRW3EWilgrNIRM5+IzXgPFPvzXqzgRIlfv0ZEb14cGzc7DBY
X3fHicECgYEA9pemJ/5Q7PSp7YjWcG5jXlL5bPos/8qoPo1w0cX4RRszKzQYMO8+
VYe/hwZr2JEIVQklxmbq/7Bc1wryn8efCsPOt+uRksHYv9qyNulQqdLczByoKPVg
8/hkPg2O3g3wGTW4Er+yqmABEo79pqJNR846X3owX4BtUjVptkJSixECgYEA0DHX
cFrbfxhIl7BG333Qh8DEBHMOy0Io+r/UefFKeGohX3Q9YAR6xf/5EhfESpf88oh7
qZFWonCHk/ETB3w4ZWSSk7s7uCQlwxFJJmMUR5JVCykd2p7hBvyT428ERpjUhjb3
LRWnh0GcOnUaLXSJfIke8OVZX7ziqQKH99IrSAUCgYEAmFh+fczf4FUTur3Ehfed
CoRGtu4k6O8iXGrz3ZXqWX+BcFqh63GTWDIiwN/Vtxl7RVX+cYHaA5fI884+sToZ
5wOr7fLqn/mE2JrbaZNhk1nDsZKuzYczm+bEv5WOw19nC5wlmee3EQ14/Cc9TDqP
diJR6/TId+gXIif/pGt7JZECgYEAt1Ys0dQw1osb4fhpcQXqTKGD/CcWMAfi7m1f
PsMtQTy0hspmAdfwBcyUGUq0oLuXFDz8KSbDk+hke/MfPsg1IZSfP1jyDgZG+rCO
Ki+1/BDwsxNSJuMiZnSmBvIMYd7TyB0/LYSUMpekbBYTJ1QofnKBvME7IwPC1fJU
qfd6BcECgYEAl4gLlSkDRo+uRHFWwwPTUH28kMXO1TQGBzqJkE5TWkGnJVuYD9BQ
I0dXdAiES4mRgrzU1XeQ8Bo+6MGIrG+9GyHWJCjrEmzui9jhniDmvlE+YVEMXNcF
6oFe9ShS+iVM+zHP8mUrNErsO7+AfEGGtzb6uO0tt86eeNuj45166VE=
-----END RSA PRIVATE KEY-----"#,
    // RSA 4096
    r#"-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"#,
    // RSA 8192
    r#"-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"#,
];

#[derive(Clone, Copy, Debug)]
pub enum Error {
    GeneralError,
    CryptoError(crypto::Error),
    PemError(crypto::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct Db {
    token_pin: String,
    objects: Vec<Object>,
}

impl Db {
    pub fn from_test_data() -> Result<Self> {
        let mut objects = Vec::new();

        for mech in defs::TOKEN_MECH_LIST.iter() {
            objects.push(Object::new_mechanism(*mech));
        }

        let mut id: usize = 0;
        let key_info: Vec<(u8, &str)> = vec![
            (0x51, "secp224r1"),
            (0x52, "secp384r1"),
            (0x53, "secp521r1"),
            (0x54, "prime256v1"),
            (0x55, "rsa1024"),
            (0x56, "rsa2048"),
            (0x57, "rsa4096"),
            (0x58, "rsa8192"),
        ];
        for pem in TEST_KEYS.iter() {
            let pkey = crypto::Pkey::from_private_pem(pem).map_err(Error::PemError)?;
            match pkey.algo().map_err(Error::CryptoError)? {
                crypto::KeyAlgo::Rsa => {
                    let info = RsaKeyInfo {
                        id: key_info[id].0,
                        label: key_info[id].1.to_string(),
                        priv_pem: pem.to_string(),
                        num_bits: pkey.num_bits().map_err(Error::CryptoError)? as u64,
                        modulus: pkey.rsa_modulus().map_err(Error::CryptoError)?,
                        public_exponent: pkey.rsa_public_exponent().map_err(Error::CryptoError)?,
                    };
                    objects.push(Object::new_rsa_private_key(info.clone()));
                    objects.push(Object::new_rsa_public_key(info));
                }
                crypto::KeyAlgo::Ec => {
                    let info = EcKeyInfo {
                        id: key_info[id].0,
                        label: key_info[id].1.to_string(),
                        priv_pem: pem.to_string(),
                        params_x962: pkey.ec_params_x962().map_err(Error::CryptoError)?,
                        point_q_x962: pkey.ec_point_q_x962().map_err(Error::CryptoError)?,
                    };
                    objects.push(Object::new_ec_private_key(info.clone()));
                    objects.push(Object::new_ec_public_key(info));
                }
            }
            id += 1;
        }

        let token_pin = "1234".to_string();

        Ok(Self { token_pin, objects })
    }

    pub fn enumerate(&self) -> impl Iterator<Item = (ObjectHandle, &Object)> {
        self.objects
            .iter()
            .enumerate()
            .map(|(i, o)| (ObjectHandle::from(i), o))
    }

    pub fn object(&self, handle: ObjectHandle) -> Option<&Object> {
        if self.objects.len() <= usize::from(handle) {
            return None;
        }
        Some(&self.objects[usize::from(handle)])
    }

    pub fn token_pin(&self) -> &str {
        self.token_pin.as_str()
    }
}
