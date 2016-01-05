{-# LANGUAGE ViewPatterns #-}

module Codec.Binary.ModHex 
    (
        encode,
        decode,
        modHexToByteString
    ) where

import Data.Bits
import Data.Word
import qualified Data.ByteString as BS

modHexToMaybeInt :: Char -> Maybe Int
modHexToMaybeInt 'c' = Just 0
modHexToMaybeInt 'b' = Just 1
modHexToMaybeInt 'd' = Just 2
modHexToMaybeInt 'e' = Just 3
modHexToMaybeInt 'f' = Just 4
modHexToMaybeInt 'g' = Just 5
modHexToMaybeInt 'h' = Just 6
modHexToMaybeInt 'i' = Just 7
modHexToMaybeInt 'j' = Just 8
modHexToMaybeInt 'k' = Just 9
modHexToMaybeInt 'L' = Just 10
modHexToMaybeInt 'N' = Just 11
modHexToMaybeInt 'R' = Just 12
modHexToMaybeInt 'T' = Just 13
modHexToMaybeInt 'U' = Just 14
modHexToMaybeInt 'V' = Just 15
modHexToMaybeInt 'l' = Just 10
modHexToMaybeInt 'n' = Just 11
modHexToMaybeInt 'r' = Just 12
modHexToMaybeInt 't' = Just 13
modHexToMaybeInt 'u' = Just 14
modHexToMaybeInt 'v' = Just 15
modHexToMaybeInt _ = Nothing

intToMaybeModHex :: Int -> Maybe Char
intToMaybeModHex 0 = Just 'c'
intToMaybeModHex 1 = Just 'b'
intToMaybeModHex 2 = Just 'd'
intToMaybeModHex 3 = Just 'e'
intToMaybeModHex 4 = Just 'f'
intToMaybeModHex 5 = Just 'g'
intToMaybeModHex 6 = Just 'h'
intToMaybeModHex 7 = Just 'i'
intToMaybeModHex 8 = Just 'j'
intToMaybeModHex 9 = Just 'k'
intToMaybeModHex 10 = Just 'l'
intToMaybeModHex 11 = Just 'n'
intToMaybeModHex 12 = Just 'r'
intToMaybeModHex 13 = Just 't'
intToMaybeModHex 14 = Just 'u'
intToMaybeModHex 15 = Just 'v'
intToMaybeModHex _ = Nothing

toModHex :: Word8 -> String
toModHex byte =
    let
        hi = fromIntegral (byte `shiftR` 4)
        lo = fromIntegral (byte .&. 0xf)
        Just hiModHex = intToMaybeModHex hi
        Just loModHex = intToMaybeModHex lo
    in [hiModHex, loModHex]

fromModHex :: String -> Maybe Word8
fromModHex ((modHexToMaybeInt -> Just hi):(modHexToMaybeInt -> Just lo):[]) = Just (fromIntegral (hi * 16 + lo))
fromModHex _ = Nothing

stringToCharPairs :: String -> Maybe [String]
stringToCharPairs [] = Just []
stringToCharPairs (a:b:[]) = Just [[a,b]]
stringToCharPairs (a:b:(stringToCharPairs -> Just cs)) = Just ([a,b]:cs)
stringToCharPairs _ = Nothing

modHexToByteString :: String -> Maybe BS.ByteString
modHexToByteString (decode -> Just words) = Just (BS.pack words)
modHexToByteString _ = Nothing

encode :: [Word8] -> String
encode = (>>= toModHex)

decode :: String -> Maybe [Word8]
decode (stringToCharPairs -> Just xs) = mapM fromModHex xs
decode _ = Nothing
