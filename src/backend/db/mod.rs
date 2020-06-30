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

// TODO: remove test data
const TEST_KEYS: [&str; 2] = [
    // EC secp224r1
    r#"-----BEGIN EC PRIVATE KEY-----
MGgCAQEEHBliO/7ebSnblR51A+5QpIuqoa7JNaYWa4FDSJOgBwYFK4EEACGhPAM6
AATcUKTxN60XBMV98ktDN6Nd0996BRa5gWOYHx/lErTx9Z33Z5gOTjxDV5REnhiT
IKMGescI2pcZsg==
-----END EC PRIVATE KEY-----"#,
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

        for pem in TEST_KEYS.iter() {
            let pkey = crypto::Pkey::from_private_pem(pem).map_err(Error::PemError)?;
            match pkey.algo().map_err(Error::CryptoError)? {
                crypto::KeyAlgo::Rsa => {
                    let info = RsaKeyInfo {
                        id: 0x52,
                        label: "rsa2048".to_string(),
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
                        id: 0x53,
                        label: "secp224r1".to_string(),
                        priv_pem: pem.to_string(),
                        params_x962: pkey.ec_params_x962().map_err(Error::CryptoError)?,
                        point_q_x962: pkey.ec_point_q_x962().map_err(Error::CryptoError)?,
                    };
                    objects.push(Object::new_ec_private_key(info.clone()));
                    objects.push(Object::new_ec_public_key(info));
                }
            }
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
