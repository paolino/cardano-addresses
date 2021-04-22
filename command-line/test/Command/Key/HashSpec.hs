{-# LANGUAGE FlexibleContexts #-}

module Command.Key.HashSpec
    ( spec
    ) where

import Prelude

import Test.Hspec
    ( Spec, SpecWith, it, shouldBe, shouldContain, shouldStartWith )
import Test.Utils
    ( cli, describeCmd )

spec :: Spec
spec = describeCmd [ "key", "hash" ] $ do
    specKeyNotPublic
    specKeyPublic "icarus" "addr_vkh"   "1852H/1815H/0H/0/0" "--without-chain-code"
    specKeyPublic "icarus" "addr_vkh"   "1852H/1815H/0H/1/0" "--without-chain-code"
    specKeyPublic "icarus" "stake_vkh"  "1852H/1815H/0H/2/0" "--without-chain-code"
    specKeyPublic "shared" "addr_shared_vkh"   "1854H/1815H/0H/0/0" "--without-chain-code"
    specKeyPublic "shared" "stake_shared_vkh"  "1854H/1815H/0H/2/0" "--without-chain-code"

    specKeyPublic "icarus" "addr_vkh"   "1852H/1815H/0H/0/0" "--with-chain-code"
    specKeyPublic "icarus" "addr_vkh"   "1852H/1815H/0H/1/0" "--with-chain-code"
    specKeyPublic "icarus" "stake_vkh"  "1852H/1815H/0H/2/0" "--with-chain-code"
    specKeyPublic "shared" "addr_shared_vkh"   "1854H/1815H/0H/0/0" "--with-chain-code"
    specKeyPublic "shared" "stake_shared_vkh"  "1854H/1815H/0H/2/0" "--with-chain-code"

specKeyNotPublic :: SpecWith ()
specKeyNotPublic = it "fail if key isn't public" $ do
    (out, err) <- cli [ "recovery-phrase", "generate" ] ""
              >>= cli [ "key", "from-recovery-phrase", "icarus" ]
              >>= cli [ "key", "hash" ]

    out `shouldBe` ""
    err `shouldContain` "Invalid human-readable prefix."

specKeyPublic :: String -> String -> String -> String -> SpecWith ()
specKeyPublic style hrp path cc = it "succeeds if key is public" $ do
    out <- cli [ "recovery-phrase", "generate" ] ""
       >>= cli [ "key", "from-recovery-phrase", style ]
       >>= cli [ "key", "child", path ]
       >>= cli [ "key", "public", cc ]
       >>= cli [ "key", "hash" ]
    out `shouldStartWith` hrp
