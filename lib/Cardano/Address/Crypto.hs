{-# LANGUAGE TypeApplications #-}

{-# OPTIONS_HADDOCK prune #-}

-- |
-- Copyright: 2020 Input Output (Hong Kong) Ltd., 2021-2022 Input Output Global Inc. (IOG), 2023-2025 Intersect
-- License: Apache-2.0
--
-- Cryptographic primitives used by @cardano-addresses@.
--
-- This module centralises all cryptographic dependencies so that
-- alternative backends (e.g. libsodium, pure-Haskell, WebCrypto)
-- can be provided by replacing this single module.

module Cardano.Address.Crypto
    (
    -- * Hashing
      blake2b160
    , blake2b224
    , blake2b256
    , sha3_256
    , credentialHashSize

    -- * Key derivation functions
    , pbkdf2HmacSha512

    -- * HMAC
    , hmacSha256
    , hmacSha512

    -- * Symmetric encryption
    , encryptChaChaPoly1305
    , decryptChaChaPoly1305

    -- * Ed25519 curve operations
    , ed25519ScalarMult

    -- * Extended keys (re-exports from @cardano-crypto@)
    , XPrv
    , XPub (..)
    , XSignature
    , ChainCode (..)
    , DerivationScheme (..)
    , ccXPrv
    , ccXPub
    , ccUnXPrv
    , ccToXPub
    , ccSign
    , ccVerify
    , ccGenerate
    , ccGenerateNew
    , ccDeriveXPrv
    , ccDeriveXPub

    -- * Random
    , getEntropy

    -- * CRC32
    , crc32

    -- * Crypto error handling (re-exports from @crypton@)
    , CryptoError (..)
    , CryptoFailable (..)
    , eitherCryptoError

    -- * Byte array utilities (re-exports from @memory@)
    , ScrubbedBytes
    , ByteArrayAccess
    , BA.convert
    ) where

import Prelude

import Cardano.Crypto.Wallet
    ( ChainCode (..)
    , DerivationScheme (..)
    , XPrv
    , XPub (..)
    , XSignature
    )
import Crypto.Error
    ( CryptoError (..)
    , CryptoFailable (..)
    , eitherCryptoError
    )
import Data.ByteArray
    ( ByteArrayAccess
    , ScrubbedBytes
    )
import Data.ByteString
    ( ByteString )
import Data.Digest.CRC32
    ( crc32 )
import Data.Word
    ( Word32 )

import qualified Cardano.Crypto.Wallet as CC
import qualified Crypto.Cipher.ChaChaPoly1305 as Poly
import qualified Crypto.ECC.Edwards25519 as Ed25519
import qualified Crypto.Hash as Hash
import qualified Crypto.Hash.Algorithms as Alg
import qualified Crypto.Hash.IO as HashIO
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import qualified Crypto.MAC.HMAC as HMAC
import qualified Crypto.Random.Entropy as Entropy
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS

--
-- Hashing
--

-- | Blake2b-160 hash.
blake2b160
    :: ByteArrayAccess a
    => a -> ByteString
blake2b160 =
    BA.convert . Hash.hash @_ @Alg.Blake2b_160

-- | Blake2b-224 hash (28 bytes), used for credential hashing.
blake2b224
    :: ByteArrayAccess a
    => a -> ByteString
blake2b224 =
    BA.convert . Hash.hash @_ @Alg.Blake2b_224

-- | Blake2b-256 hash (32 bytes).
blake2b256
    :: ByteArrayAccess a
    => a -> ByteString
blake2b256 =
    BA.convert . Hash.hash @_ @Alg.Blake2b_256

-- | SHA3-256 hash.
sha3_256
    :: ByteArrayAccess a
    => a -> ByteString
sha3_256 =
    BA.convert . Hash.hash @_ @Alg.SHA3_256

-- | Size in bytes of a Blake2b-224 credential hash (28).
credentialHashSize :: Int
credentialHashSize =
    HashIO.hashDigestSize Alg.Blake2b_224

--
-- Key derivation functions
--

-- | PBKDF2 with HMAC-SHA512.
pbkdf2HmacSha512
    :: ByteArrayAccess password
    => ByteArrayAccess salt
    => Int
    -- ^ Number of iterations
    -> Int
    -- ^ Desired output length in bytes
    -> password
    -> salt
    -> ScrubbedBytes
pbkdf2HmacSha512 iters len password salt =
    PBKDF2.generate
        (PBKDF2.prfHMAC Alg.SHA512)
        (PBKDF2.Parameters iters len)
        password
        salt

--
-- HMAC
--

-- | HMAC-SHA256.
hmacSha256
    :: ByteArrayAccess key
    => ByteArrayAccess msg
    => key -> msg -> ByteString
hmacSha256 key msg =
    BA.convert (HMAC.hmac key msg :: HMAC.HMAC Alg.SHA256)

-- | HMAC-SHA512.
hmacSha512
    :: ByteArrayAccess key
    => ByteArrayAccess msg
    => key -> msg -> ByteString
hmacSha512 key msg =
    BA.convert (HMAC.hmac key msg :: HMAC.HMAC Alg.SHA512)

--
-- Symmetric encryption
--

-- | ChaCha20-Poly1305 authenticated encryption.
--
-- The key must be 32 bytes, the nonce 12 bytes.
encryptChaChaPoly1305
    :: ByteArrayAccess key
    => key
    -> ByteString
    -- ^ 12-byte nonce
    -> ByteString
    -- ^ Plaintext
    -> CryptoFailable ByteString
    -- ^ Ciphertext with 16-byte authentication tag appended
encryptChaChaPoly1305 key nonceBytes plaintext = do
    nonce <- Poly.nonce12 nonceBytes
    st1 <- Poly.finalizeAAD <$> Poly.initialize key nonce
    let (out, st2) = Poly.encrypt plaintext st1
    pure $ out <> BA.convert (Poly.finalize st2)

-- | ChaCha20-Poly1305 authenticated decryption.
--
-- The key must be 32 bytes, the nonce 12 bytes.
decryptChaChaPoly1305
    :: ByteArrayAccess key
    => key
    -> ByteString
    -- ^ 12-byte nonce
    -> ByteString
    -- ^ Ciphertext with 16-byte authentication tag appended
    -> CryptoFailable ByteString
decryptChaChaPoly1305 key nonceBytes ciphertext = do
    let (payload, tag) = BS.splitAt (BS.length ciphertext - 16) ciphertext
    nonce <- Poly.nonce12 nonceBytes
    st1 <- Poly.finalizeAAD <$> Poly.initialize key nonce
    let (out, st2) = Poly.decrypt payload st1
    if BA.convert (Poly.finalize st2) /= tag
        then CryptoFailed CryptoError_MacKeyInvalid
        else pure out

-- | Ed25519 scalar multiplication: decode a scalar from a long
-- bytestring and compute the corresponding public point.
ed25519ScalarMult :: ByteString -> Maybe ByteString
ed25519ScalarMult bs = do
    scalar <- either (const Nothing) Just
        $ eitherCryptoError
        $ Ed25519.scalarDecodeLong bs
    pure $ Ed25519.pointEncode $ Ed25519.toPoint scalar

--
-- Extended key operations (thin wrappers around @cardano-crypto@)
--

-- | Construct an 'XPrv' from raw bytes.
ccXPrv :: ByteString -> Either String XPrv
ccXPrv = CC.xprv

-- | Construct an 'XPub' from raw bytes.
ccXPub :: ByteString -> Either String XPub
ccXPub = CC.xpub

-- | Extract raw bytes from an 'XPrv' (128 bytes: 64 prv + 32 pub + 32 cc).
ccUnXPrv :: XPrv -> ByteString
ccUnXPrv = CC.unXPrv

-- | Derive the 'XPub' from an 'XPrv'.
ccToXPub :: XPrv -> XPub
ccToXPub = CC.toXPub

-- | Sign a message with an 'XPrv'.
ccSign
    :: ByteArrayAccess msg
    => ScrubbedBytes -> XPrv -> msg -> XSignature
ccSign = CC.sign

-- | Verify a signature with an 'XPub'.
ccVerify
    :: ByteArrayAccess msg
    => XPub -> msg -> XSignature -> Bool
ccVerify = CC.verify

-- | Generate an 'XPrv' from a seed (legacy Byron method).
ccGenerate
    :: ByteArrayAccess seed
    => seed -> ScrubbedBytes -> XPrv
ccGenerate = CC.generate

-- | Generate an 'XPrv' from a seed with second factor (Icarus method).
ccGenerateNew
    :: (ByteArrayAccess seed, ByteArrayAccess sndFactor)
    => seed -> sndFactor -> ScrubbedBytes -> XPrv
ccGenerateNew = CC.generateNew

-- | Derive a child 'XPrv' from a parent 'XPrv'.
ccDeriveXPrv
    :: DerivationScheme
    -> ScrubbedBytes
    -> XPrv
    -> Word32
    -> XPrv
ccDeriveXPrv = CC.deriveXPrv

-- | Derive a child 'XPub' from a parent 'XPub'.
ccDeriveXPub
    :: DerivationScheme
    -> XPub
    -> Word32
    -> Maybe XPub
ccDeriveXPub = CC.deriveXPub

--
-- Random
--

-- | Obtain cryptographic entropy from the system.
getEntropy :: Int -> IO ScrubbedBytes
getEntropy = Entropy.getEntropy
