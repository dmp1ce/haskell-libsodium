import Test.Tasty
--import Test.Tasty.HUnit
--import Test.Tasty.SmallCheck

import BindingTests
import HighLevelTests
import Bindings.LibSodium

main :: IO ()
main = do
  _ <- c'sodium_init -- Initialize sodium first
  defaultMain $ testGroup "all-tests" tests

tests :: [TestTree]
tests =
  [ testGroup "Unit_tests_bindings" bindingTests
  , testGroup "Unit_tests_high-level" hlTests
  --, testGroup "SmallCheck" scTests
  ]

--scTests :: [TestTree]
--scTests =
--  [ testProperty "n > (-1)" prop_not_negative
--  ]

--prop_not_negative :: Integer -> Bool
--prop_not_negative = (> (-1))
