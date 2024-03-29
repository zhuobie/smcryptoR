% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/sm4.R
\name{sm4_encrypt_ecb_base64}
\alias{sm4_encrypt_ecb_base64}
\alias{sm4_encrypt_ecb_hex}
\alias{sm4_decrypt_ecb_base64}
\alias{sm4_decrypt_ecb_hex}
\alias{sm4_encrypt_cbc_base64}
\alias{sm4_encrypt_cbc_hex}
\alias{sm4_decrypt_cbc_base64}
\alias{sm4_decrypt_cbc_hex}
\title{SM4 Encrypt/Decrypt - hex and base64}
\usage{
sm4_encrypt_ecb_base64(input_data, key)

sm4_encrypt_ecb_hex(input_data, key)

sm4_decrypt_ecb_base64(input_data, key)

sm4_decrypt_ecb_hex(input_data, key)

sm4_encrypt_cbc_base64(input_data, key, iv)

sm4_encrypt_cbc_hex(input_data, key, iv)

sm4_decrypt_cbc_base64(input_data, key, iv)

sm4_decrypt_cbc_hex(input_data, key, iv)
}
\arguments{
\item{input_data}{for encrypt, data is a raw vector, for decrypt, data is a hex or base64 string}

\item{key}{the key, must be a raw vector of length 16}

\item{iv}{the initialization vector, must be a raw vector of 16}
}
\value{
\describe{
  \item{\link{sm4_encrypt_ecb_base64}}{returns a base64 string of the cipher text using ecb mode}
  \item{\link{sm4_encrypt_ecb_hex}}{returns a hex string of the cipher text using ecb mode}
  \item{\link{sm4_decrypt_ecb_base64}}{returns a raw vector of the plain text}
  \item{\link{sm4_decrypt_ecb_hex}}{returns a raw vector of the plain text}
  \item{\link{sm4_encrypt_cbc_base64}}{returns a base64 string of the cipher text using cbc mode}
  \item{\link{sm4_encrypt_cbc_hex}}{returns a hex string of the cipher text using cbc mode}
  \item{\link{sm4_decrypt_cbc_base64}}{returns a raw vector of the plain text}
  \item{\link{sm4_decrypt_cbc_hex}}{returns a raw vector of the plain text}
}
}
\description{
For ease of use, we have provided functions to encrypt data into hex or
base64 format and decrypt them from these formats.
}
\examples{
## SM4 Encrypt/Decrypt - hex and base64
data <- 'abc' |> charToRaw()
key <- '1234567812345678' |> charToRaw()
iv <- '0000000000000000' |> charToRaw()
## ecb mode
enc <- sm4_encrypt_ecb_base64(data, key)
enc
dec <- sm4_decrypt_ecb_base64(enc, key)
dec
enc <- sm4_encrypt_ecb_hex(data, key)
enc
dec <- sm4_decrypt_ecb_hex(enc, key)
dec
## cbc mode
enc <- sm4_encrypt_cbc_base64(data, key, iv)
enc
dec <- sm4_decrypt_cbc_base64(enc, key, iv)
dec
enc <- sm4_encrypt_cbc_hex(data, key, iv)
enc
dec <- sm4_decrypt_cbc_hex(enc, key, iv)
dec
}
