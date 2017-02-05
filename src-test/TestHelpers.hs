module TestHelpers where

import Data.Text

convertEndian :: [a] -> [a]
convertEndian (x1:x2:xs) = (convertEndian xs) ++ [x1,x2]
convertEndian xs = xs

-- | Useful for trimming Hexadecimal 'Text' for testing equality
trim0s :: Text -> Text
trim0s = dropAround ('0'==)

isHexEqual :: String -> String -> Bool
isHexEqual x y = (trim0s $ pack x) == (trim0s $ pack y)
