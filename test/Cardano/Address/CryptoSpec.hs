{-# LANGUAGE OverloadedStrings #-}

-- | Known-answer tests for low-level crypto primitives.
--
-- These vectors pin the exact output of each primitive so that
-- swapping the underlying crypto backend (e.g. crypton -> libsodium,
-- memory -> ram) is caught immediately if results diverge.
module Cardano.Address.CryptoSpec
    ( spec
    ) where

import Prelude

import Cardano.Address.Derivation
    ( credentialHashSize
    , hashCredential
    , hashWalletId
    , xprvFromBytes
    , xprvToBytes
    )
import Codec.Binary.Encoding ( AbstractEncoding (..), encode )
import Data.ByteString ( ByteString )
import Test.Hspec ( Spec, describe, it, shouldBe )

import qualified Data.ByteArray.Encoding as BA
import qualified Data.ByteString as BS

spec :: Spec
spec = describe "Crypto primitive vectors" $ do

    describe "Blake2b-224 (hashCredential)" $ do
        it "empty input" $
            toHex (hashCredential "")
                `shouldBe`
                "836cc68931c2e4e3e838602eca1902591d216837bafddfe6f0c8cb07"
        it "\"abc\"" $
            toHex (hashCredential "abc")
                `shouldBe`
                "9bd237b02a29e43bdd6738afa5b53ff0eee178d6210b618e4511aec8"
        it "output is 28 bytes" $
            BS.length (hashCredential "test") `shouldBe` 28
        it "credentialHashSize is 28" $
            credentialHashSize `shouldBe` 28

    describe "Blake2b-160 (hashWalletId)" $ do
        it "empty input" $
            toHex (hashWalletId "")
                `shouldBe`
                "3345524abf6bbe1809449224b5972c41790b6cf2"
        it "\"abc\"" $
            toHex (hashWalletId "abc")
                `shouldBe`
                "384264f676f39536840523f284921cdc68b6846b"
        it "output is 20 bytes" $
            BS.length (hashWalletId "test") `shouldBe` 20

    describe "Ed25519 scalar multiply (xprvFromBytes roundtrip)" $ do
        -- xprvFromBytes performs ed25519ScalarMult internally:
        -- it takes 32 bytes of private key, decodes as scalar, computes
        -- the public point, and reconstructs the full XPrv.
        it "RFC 8032 vector 1: known private key reconstructs" $ do
            let prv = fromHex
                    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
                prv64 = prv <> BS.replicate 32 0
                cc = BS.replicate 32 0
                input = prv64 <> cc
            case xprvFromBytes input of
                Nothing -> fail "xprvFromBytes returned Nothing"
                Just xprv -> do
                    let roundtripped = xprvToBytes xprv
                    BS.take 64 roundtripped `shouldBe` prv64

        it "RFC 8032 vector 2: known private key reconstructs" $ do
            let prv = fromHex
                    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
                prv64 = prv <> BS.replicate 32 0
                cc = BS.replicate 32 0
                input = prv64 <> cc
            case xprvFromBytes input of
                Nothing -> fail "xprvFromBytes returned Nothing"
                Just xprv -> do
                    let roundtripped = xprvToBytes xprv
                    BS.take 64 roundtripped `shouldBe` prv64

{-------------------------------------------------------------------------------
                                  Helpers
-------------------------------------------------------------------------------}

toHex :: ByteString -> ByteString
toHex = encode EBase16

fromHex :: ByteString -> ByteString
fromHex bs = case BA.convertFromBase BA.Base16 bs of
    Right x -> x
    Left _ -> error "fromHex: invalid hex"
