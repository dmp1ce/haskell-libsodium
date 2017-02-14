module BindingTests where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Test.Tasty.QuickCheck as QC
import qualified Test.QuickCheck.Monadic as QC
import qualified Test.Tasty.SmallCheck as SC

import Bindings.LibSodium

import Foreign.ForeignPtr
import Foreign.C.Types
import Foreign.C.String
import Foreign.Storable
import Foreign.Ptr
import Foreign.Marshal.Array
import Data.Word
import System.Process
import System.Exit
import Control.Monad
import Numeric (showHex)
import Text.Printf

import TestHelpers

bindingTests :: [TestTree]
bindingTests =
  [ testCase "c'sodium_init" test_c'sodium_init
  , testCase "c'sodium_memcmp" test_c'sodium_memcmp
  , QC.testProperty "c'sodium_bin2hex" prop_c'sodium_bin2hex
  , QC.testProperty "c'sodium_hex2bin" prop_c'sodium_hex2bin
  , QC.testProperty "hex2bin_bin2hex" prop_hex2bin_bin2hex
  , testCase "c'sodium_increment" test_c'sodium_increment
  , testCase "c'sodium_add" test_c'sodium_add
  , testCase "c'sodium_compare" test_c'sodium_compare
  , testCase "c'sodium_is_zero" test_c'sodium_is_zero
  , testCase "c'sodium_memzero" test_c'sodium_memzero
  , testCase "c'sodium_mlock" test_c'sodium_mlock
  , testCase "c'sodium_allocarray" test_c'sodium_allocarray
  , testCase "c'sodium_mprotect" test_c'sodium_mprotect
  , testCase "c'sodium_allocarray_crash" $ test_c'sodium_crash "allocarray"
  , testCase "c'sodium_mprotect_noaccess_crash" $
             test_c'sodium_crash "mprotect_noaccess"
  , testCase "c'sodium_mprotect_readonly_crash" $
             test_c'sodium_crash "mprotect_readonly"
  , testCase "c'randombytes_random" test_c'randombytes_random
  , testCase "c'randombytes_uniform" test_c'randombytes_uniform
  , testCase "c'randombytes_buf" test_c'randombytes_buf
  , testCase "c'randombytes_stir" test_c'randombytes_buf
  , SC.testProperty "c'cypto_secretbox_easy" prop_c'crypto_secretbox_easy
  ]

test_c'sodium_init :: Assertion
test_c'sodium_init = do
  n <- c'sodium_init
  assertBool ("c'sodium_init failed with " ++ show n) (n == 0 || n == 1)

test_c'sodium_memcmp :: Assertion
test_c'sodium_memcmp = do
  fPtr1 <- mallocForeignPtr :: IO (ForeignPtr CInt)
  fPtr2 <- mallocForeignPtr :: IO (ForeignPtr CInt)
  withForeignPtr fPtr1 $ \ptr1 -> withForeignPtr fPtr2 $ \ptr2 -> withCString "Hello" $ \ptr3 -> do
    poke ptr1 1; poke ptr2 2

    v1 <- peek ptr1
    let v1_size = sizeOf v1

    -- Compare two CInt of different values
    r1 <- c'sodium_memcmp (castPtr ptr1) (castPtr ptr2) (toEnum v1_size)
    r1 @?= (-1)

    -- Compare the same CInt
    r2 <- c'sodium_memcmp (castPtr ptr1) (castPtr ptr1) (toEnum v1_size)
    r2 @?= 0

    v3 <- peek ptr3
    let v3_size = sizeOf v3

    -- Compare a CInt and a CString
    r3 <- c'sodium_memcmp (castPtr ptr1) (castPtr ptr3) (toEnum v3_size)
    r3 @?= (-1)

    -- Change the value of ptr1 and compare to ptr2 again
    poke ptr1 2
    r4 <- c'sodium_memcmp (castPtr ptr1) (castPtr ptr2) (toEnum v1_size)
    r4 @?= 0

prop_c'sodium_bin2hex :: QC.NonNegative (QC.Large Word) -> QC.Property
prop_c'sodium_bin2hex (QC.NonNegative (QC.Large i)) = QC.monadicIO $ do
  fPtrBin <- QC.run $ mallocForeignPtr :: QC.PropertyM IO (ForeignPtr Word)
  fPtrHex <- QC.run $ mallocForeignPtr :: QC.PropertyM IO (ForeignPtr CChar)

  res <- QC.run $ withForeignPtr fPtrBin $ \ptrBin ->
    withForeignPtr fPtrHex $ \ptrHex -> do

    poke ptrBin i
    binSize <- peek ptrBin >>= return . sizeOf
    let hexSize = binSize * 2 + 1

    res <- c'sodium_bin2hex ptrHex (toEnum hexSize)
                            (castPtr ptrBin) (toEnum binSize)

    resValue <- peekCAString res
    hexValue <- peekCAString ptrHex

    assertEqual "Return and hex memory addresses are NOT equal" ptrHex res
    assertEqual "Return value and hex values are NOT equal" resValue hexValue

    -- For whatever reason, bin2hex prints hexadecimal in little endian
    -- but most converters use big endian, including @Numeric.showHex@.
    return $ isHexEqual (convertEndian hexValue) (showHex i "")

  QC.assert res

prop_c'sodium_hex2bin :: QC.NonNegative (QC.Large CUInt)
                      -> SafeString
                      -> QC.Property
prop_c'sodium_hex2bin (QC.NonNegative (QC.Large i)) (SafeString s) =
  QC.monadicIO $ do
  let hexString = (padHex $ showHex i "") ++ '-':s
      hexLength = length hexString
      binMax = (hexLength `div` 2) + 1
  fPtrBin <- QC.run $ mallocForeignPtrArray binMax :: QC.PropertyM IO (ForeignPtr CUChar)
  fPtrBinLen <- QC.run $ mallocForeignPtr :: QC.PropertyM IO (ForeignPtr CSize)
  fPtrHexEnd <- QC.run $ mallocForeignPtr :: QC.PropertyM IO (ForeignPtr (Ptr CChar))

  (res, binValue, hexEndValue) <-
    QC.run $ withForeignPtr fPtrBin $ \ptrBin ->
    withCString hexString $ \ptrHex ->
      withForeignPtr fPtrBinLen $ \ptrBinLen ->
        withForeignPtr fPtrHexEnd $ \ptrHexEnd -> do

    res <- c'sodium_hex2bin (castPtr ptrBin) (toEnum hexLength)
                            ptrHex (toEnum hexLength) nullPtr
                            ptrBinLen ptrHexEnd

    binLenValue <- peek ptrBinLen
    binValue    <- peekArray (fromEnum binLenValue) ptrBin
    hexEndValue <- peek ptrHexEnd >>= peekCAString
    return (res, binValue, hexEndValue)

  QC.assert $ res == 0
  QC.assert $ (padHex $ showHexCUCharList binValue) == (padHex $ showHex i "")
  QC.assert $ hexEndValue == "-" ++ s

prop_hex2bin_bin2hex :: QC.NonNegative (QC.Large CUInt)
                     -> QC.Property
prop_hex2bin_bin2hex (QC.NonNegative (QC.Large i)) =
  QC.monadicIO $ do
  fPtrBin <- QC.run $ mallocForeignPtr :: QC.PropertyM IO (ForeignPtr CUInt)
  fPtrBinLen <-
    QC.run $ mallocForeignPtr :: QC.PropertyM IO (ForeignPtr CSize)
  fPtrHexEnd <-
    QC.run $ mallocForeignPtr :: QC.PropertyM IO (ForeignPtr (Ptr CChar))
  let hexString = printf "%08s" $ showHex (i::CUInt) ""
      hexLength = length hexString

  resValue <- QC.run $ withForeignPtr fPtrBin $ \ptrBin ->
    withCString hexString $ \ptrHex ->
      withForeignPtr fPtrBinLen $ \ptrBinLen ->
        withForeignPtr fPtrHexEnd $ \ptrHexEnd -> do

    binSizeMax <- peek ptrBin >>= return . sizeOf

    -- Convert to bin
    _ <- c'sodium_hex2bin (castPtr ptrBin) (toEnum binSizeMax)
                            ptrHex (toEnum hexLength) nullPtr
                            ptrBinLen ptrHexEnd

    -- Convert back to hex
    binSize' <- peek ptrBin >>= return . sizeOf
    let hexSize = binSize' * 2 + 1
    res <- c'sodium_bin2hex ptrHex (toEnum hexSize)
                            (castPtr ptrBin) (toEnum binSize')
    peekCAString res

  QC.assert $ resValue == hexString

test_c'sodium_increment :: Assertion
test_c'sodium_increment = do
  let bigNum = 1000000000000000000
  fPtrNum <- mallocForeignPtr :: IO (ForeignPtr Word64)
  withForeignPtr fPtrNum $ \ptrNum -> do
    poke ptrNum bigNum
    c'sodium_increment (castPtr ptrNum) ((toEnum . sizeOf) bigNum)
    res <- peek ptrNum
    res @?= (bigNum + 1)

test_c'sodium_add :: Assertion
test_c'sodium_add = do
  let num1 = 10000000
  let num2 = 3434343
  fPtrNum1 <- mallocForeignPtr :: IO (ForeignPtr Word64)
  fPtrNum2 <- mallocForeignPtr :: IO (ForeignPtr Word64)
  withForeignPtr fPtrNum1 $ \ptrNum1 ->
    withForeignPtr fPtrNum2 $ \ptrNum2 -> do

    poke ptrNum1 num1
    poke ptrNum2 num2
    c'sodium_add (castPtr ptrNum1) (castPtr ptrNum2) ((toEnum . sizeOf) num1)
    res <- peek ptrNum1
    res @?= (num1 + num2)

test_c'sodium_compare :: Assertion
test_c'sodium_compare = do
  let num1 = 10000000
  let num2 = 3434343
  fPtrNum1 <- mallocForeignPtr :: IO (ForeignPtr Word64)
  fPtrNum2 <- mallocForeignPtr :: IO (ForeignPtr Word64)
  withForeignPtr fPtrNum1 $ \ptrNum1 ->
    withForeignPtr fPtrNum2 $ \ptrNum2 -> do

    poke ptrNum1 num1
    poke ptrNum2 num2

    -- Compare num1 and num2
    res <- c'sodium_compare (castPtr ptrNum1) (castPtr ptrNum2) ((toEnum . sizeOf) num1)
    res @?= 1

    -- Compare num1 and num1
    res2 <- c'sodium_compare (castPtr ptrNum1) (castPtr ptrNum1) ((toEnum . sizeOf) num1)
    res2 @?= 0

    -- Compare num2 and num1
    res3 <- c'sodium_compare (castPtr ptrNum2) (castPtr ptrNum1) ((toEnum . sizeOf) num1)
    res3 @?= (-1)

test_c'sodium_is_zero :: Assertion
test_c'sodium_is_zero = do
  let num1 = 10000000
  let num2 = 0
  fPtrNum1 <- mallocForeignPtr :: IO (ForeignPtr Word64)
  fPtrNum2 <- mallocForeignPtr :: IO (ForeignPtr Word64)
  withForeignPtr fPtrNum1 $ \ptrNum1 ->
    withForeignPtr fPtrNum2 $ \ptrNum2 -> do

    poke ptrNum1 num1
    poke ptrNum2 num2

    -- Is not all zero
    res <- c'sodium_is_zero (castPtr ptrNum1) ((toEnum . sizeOf) num1)
    res @?= 0

    -- Is all zero
    res2 <- c'sodium_is_zero (castPtr ptrNum2) ((toEnum . sizeOf) num1)
    res2 @?= 1

test_c'sodium_memzero :: Assertion
test_c'sodium_memzero = do
  let num = 711
  fPtrNum <- mallocForeignPtr :: IO (ForeignPtr Word64)
  withForeignPtr fPtrNum $ \ptrNum -> do

    poke ptrNum num
    c'sodium_memzero (castPtr ptrNum) ((toEnum . sizeOf) num)

    res <- peek ptrNum
    res @?= 0

test_c'sodium_mlock :: Assertion
test_c'sodium_mlock = do
  let num = 10
  fPtrNum <- mallocForeignPtr :: IO (ForeignPtr Word64)
  withForeignPtr fPtrNum $ \ptrNum -> do

    poke ptrNum num
    res <- c'sodium_mlock (castPtr ptrNum) ((toEnum . sizeOf) num)
    res @?= 0

    res2 <- c'sodium_munlock (castPtr ptrNum) ((toEnum . sizeOf) num)
    res2 @?= 0

test_c'sodium_allocarray :: Assertion
test_c'sodium_allocarray = do
  let num1 = 123 :: Word64
      num2 = 4567:: Word64
  ptr <- c'sodium_allocarray (toEnum $ sizeOf num1) 2
  pokeElemOff (castPtr ptr) 0 num1
  pokeElemOff (castPtr ptr) 1 num2

  peekElemOff (castPtr ptr) 0 >>= (num1 @=?)
  peekElemOff (castPtr ptr) 1 >>= (num2 @=?)

  -- Free memory
  c'sodium_free (castPtr ptr)

test_c'sodium_mprotect :: Assertion
test_c'sodium_mprotect = do
  let num = 11109 :: Word64
  ptr <- c'sodium_malloc (toEnum $ sizeOf num)
  poke (castPtr ptr) num

  -- Set noaccess
  c'sodium_mprotect_noaccess (castPtr ptr) >>= (0 @=?)

  -- Allow readonly
  c'sodium_mprotect_readonly (castPtr ptr) >>= (0 @=?)

  -- readonly allows read access
  ptrPeek <- peek (castPtr ptr)
  ptrPeek @?= num

  -- Allow readwrite access again
  c'sodium_mprotect_readwrite (castPtr ptr) >>= (0 @=?)

  poke (castPtr ptr) (num + 1)
  peek (castPtr ptr) >>= ((num + 1) @=?)

  -- Free memory
  c'sodium_free (castPtr ptr)

test_c'sodium_crash :: String -> Assertion
test_c'sodium_crash s = do
  -- Run a script which tries to access memory which is off limits.
  res <- readCreateProcessWithExitCode
         (shell $ "stack runghc -- src-test/sodium_crash_tests.hs " ++ s)
         ""
  -- Verify that a crash occured.
  case res of
    (ExitFailure i, _, _) -> i @?= (-11)
    (ExitSuccess, _, _)  -> assertFailure
                             "Crash script didn't return error code"

test_c'randombytes_random :: Assertion
test_c'randombytes_random = replicateM_ 1000 $ do
  n <- c'randombytes_random
  assertBool ("Random byte '" ++ (show n) ++ "' is negative") ( n >= 0 )

test_c'randombytes_uniform :: Assertion
test_c'randombytes_uniform = do
  let upperBound = 4
  n <- c'randombytes_uniform upperBound
  assertBool ("Random byte '" ++ (show n) ++ "' is negative") ( n >= 0 )
  assertBool ("Random byte '" ++ (show n) ++
              "' greater than or equal to " ++ show upperBound)
             ( n < upperBound )

test_c'randombytes_buf :: Assertion
test_c'randombytes_buf = do
  let size = 32
  fPtr <- mallocForeignPtrBytes size
  withForeignPtr fPtr $ \ptr -> do
    c'randombytes_buf (castPtr ptr) (toEnum size)
    n <- peek ptr :: IO CUInt
    assertBool ("Random byte '" ++ (show n) ++ "' is negative") ( n >= 0 )

test_c'randombytes_stir :: Assertion
test_c'randombytes_stir = do
  -- Close random resources
  c'randombytes_close >>= (0 @=?)

  -- Open random resources
  c'randombytes_stir

  -- Make sure random still works
  test_c'randombytes_random
  test_c'randombytes_uniform

-- Verify that random messages encrypt and then decrypt
prop_c'crypto_secretbox_easy :: String -> SC.Property IO
prop_c'crypto_secretbox_easy message = SC.monadic $ do
  withCString message $ \ptrMessage -> do
    -- Length in bytes of message
    mlen <- lengthArray0 (castCharToCChar '\NUL') ptrMessage
    let clen = c'crypto_secretbox_MACBYTES + mlen
    fPtrCypher <- mallocForeignPtrBytes (clen)
    fPtrNonce <- mallocForeignPtrBytes (c'crypto_secretbox_NONCEBYTES)
    fPtrKey <- mallocForeignPtrBytes (c'crypto_secretbox_KEYBYTES)
    withForeignPtr fPtrCypher $ \ptrCypher ->
      withForeignPtr fPtrNonce $ \ptrNonce ->
        withForeignPtr fPtrKey $ \ptrKey -> do
      retEncrypt <- c'crypto_secretbox_easy ptrCypher (castPtr ptrMessage) (toEnum mlen) ptrNonce ptrKey
      case retEncrypt of
        0 -> return ()
        i -> assertFailure $ "Encrypt returned: " ++ show i

      -- See if we get the message back out
      c'sodium_memzero (castPtr ptrMessage) (toEnum mlen)
      retDecrypt  <- c'crypto_secretbox_open_easy (castPtr ptrMessage) ptrCypher (toEnum clen) ptrNonce ptrKey
      case retDecrypt of
        0 -> return ()
        i -> assertFailure $ "Decrypt returned: " ++ show i

      peekCString ptrMessage >>= (message @=?)
  return True

-- Can be used to look at raw bit list for debugging
--bitList :: (Bits b) => b -> Maybe [Bool]
--bitList b =
--  let bSizeM = bitSizeMaybe b
--      createBitList :: (Bits b) => b -> Int -> [Bool]
--      createBitList b' i
--        | i < 0     = []
--        | otherwise = (testBit b' (i)):(createBitList b' (i-1))
--  in  maybe Nothing (Just <$> reverse . createBitList b) bSizeM
