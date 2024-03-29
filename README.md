## Introduction

The goal of smcryptoR is to use national cryptographic algorithms in R. smcryptoR uses rust FFI bindings for [smcrypto crate](https://crates.io/crates/smcrypto).

**SM3**: message digest

**SM2**: encrypt/decrypt, sign/verify, key exchange

**SM4**: encrypt/decrypt

## Installation in R

Install from CRAN:

```{r}
install.packages('smcryptoR')
```

or install from source:

```{r}
remotes::install_github('zhuobie/smcryptoR')
```

*NOTE:*

On Windows, the R oldrelease(R 4.2/Rtools42) may generate warnings:`Warning: corrupt .drectve at end of def file`. See [here](https://stat.ethz.ch/pipermail/r-package-devel/2023q2/009229.html) and [here](https://github.com/rust-lang/rust/issues/112368).

## SM3

SM3 is similar to other well-known hash functions like SHA-256 in terms of its security properties and structure, which provides a fixed size output of 256 bits.

The `sm3_hash` function accepts a raw vector parameter, which is equivalent to a byte array represented in hexadecimal format. In R, the `charToRaw()` or `serialize()` functions can be used to convert strings or objects into the raw vector type.

```{r}
msg <- charToRaw('abc')
sm3_hash(msg)
```

You can also use `sm3_hash_string()` to hash a character string directly.

```{r}
sm3_hash_string('abc')
```

`sm3_hash_file()` is provided to hash a local file on your machine. For example use `sm3_hash_file('/etc/hosts')`.

## SM2

SM2 is based on the elliptic curve cryptography (ECC), which provides stronger security with shorter key lengths compared to traditional cryptography algorithms.

### Keypair

In asymmetric encryption, public keys and private keys appear in pairs. The public key is used for encryption and verification, while the private key is used for decryption and signing. The public key can be derived from the private key, but not the other way around.

```{r}
## generate a keypair
keypair <- sm2_gen_keypair()
sk <- keypair$private_key
pk <- keypair$public_key
sk
pk
```

You can also export the public key from a private key.

```{r}
pk <- sm2_pk_from_sk(sk)
pk
```

### Sign/Verify

This is to ensure the integrity of the data and guarantee its authenticity. Typically, the data owner uses the SM3 message digest algorithm to calculate the hash value and signs it with the private key, generating signed data. Then the owner distributes the original data and the signed data of the original data to the receiver. The receiver uses the public key and the received signed data to perform the verification operation. If the verification is successful, it is considered that the received original data has not been tampered with.

```{r}
id <- 'someone@company.com' |> charToRaw()
data <- 'abc' |> charToRaw()
sign <- sm2_sign(id, data, sk)
## return 1 or 0
sm2_verify(id, data, sign, pk)
```

### Encrypt/Decrypt

SM2 is an asymmetric encryption algorithm that can also be used to directly encrypt data. Typically, A encrypts a file or data using the public key, passes the ciphertext to B, and B decrypts it using the corresponding private key. SM2 encryption and decryption are suitable for shorter texts only. For larger files, the process can be very slow.

```{r}
## encrypt using public key
enc <- sm2_encrypt(data, pk)
## cipher text
enc
## decrypt using private key
dec <- sm2_decrypt(enc, sk)
## plain text
dec
## convert to character string
rawToChar(dec)
```

For ease of use, we have provided functions to encrypt data into hex or base64 format and decrypt them from these formats.

```{r}
enc <- sm2_encrypt_base64(data, pk)
## cipher text as base64
enc
sm2_decrypt_base64(enc, sk) |> rawToChar()
```

Or you can use hex as output instead.

```{r}
enc <- sm2_encrypt_hex(data, pk)
## cipher text as hex
enc
sm2_decrypt_hex(enc, sk) |> rawToChar()
```

### Key Exchange

If A and B want to generate a recognized key for encryption or authentication, this algorithm can ensure that the key itself will not be transmitted through untrusted channels, and the private keys of A and B will not be disclosed. Even if an attacker intercepts the data exchanged by A and B, they cannot calculate the key agreed upon by A and B.

```{r}
## Step 1
klen <- 16
id_a <- "a@company.com" |> charToRaw()
id_b <- "b@company.com" |> charToRaw()
private_key_a <- sm2_gen_keypair()$private_key
private_key_b <- sm2_gen_keypair()$private_key
step_1_a <- sm2_keyexchange_1ab(klen, id_a, private_key_a)
step_1_b <- sm2_keyexchange_1ab(klen, id_b, private_key_b)

## Step 2
step_2_a <- sm2_keyexchange_2a(id_a, private_key_a, step_1_a$private_key_r, step_1_b$data)
step_2_b <- sm2_keyexchange_2b(id_b, private_key_b, step_1_b$private_key_r, step_1_a$data)
step_2_a$k
step_2_b$k
```

The output key `k` should be length of 16 and `step_2_a$k` and `step_2_b$k` should be equal.

## SM4

The SM4 algorithm is a block symmetric encryption algorithm with a block size and key length of 128 bits. SM4 supports both the ECB (Electronic Codebook) mode and the CBC (Cipher Block Chaining) mode. The ECB mode is a simple block cipher encryption mode that encrypts each data block independently without depending on other blocks. The CBC mode, on the other hand, is a chained block cipher encryption mode where the encryption of each block depends on the previous ciphertext block. Therefore, it requires an initialization vector (IV) of the same 128-bit length. The CBC mode provides higher security than the ECB mode.

### Encrypt/Decrypt - ECB mode

In ECB mode, each block of plaintext is encrypted independently, without any chaining with previous blocks. This means that the same plaintext block will always produce the same ciphertext block, given the same key. 

```{r}
## ecb mode
key <- '1234567812345678' |> charToRaw()
enc <- sm4_encrypt_ecb(data, key)
## cipher text
enc
## plain text
sm4_decrypt_ecb(enc, key) |> rawToChar()
```

### Encrypt/Decrypt - CBC mode

In CBC mode, each block of plaintext is combined (usually through XOR operation) with the previous ciphertext block before being encrypted. This chaining of blocks ensures that even if there are repeated blocks in the plaintext, the resulting ciphertext blocks will be different due to the influence of the previous ciphertext blocks.

```{r}
iv <- '0000000000000000' |> charToRaw()
enc <- sm4_encrypt_cbc(data, key, iv)
## cipher text
enc
sm4_decrypt_cbc(enc, key, iv) |> rawToChar()
```
