{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE ExistentialQuantification #-}

module Codec.Crypto.YubiKeyOTP
    -- (
    --  YubiKeyToken(..),
    --  getYubiKeyToken,
    --  verifyYubiKeyToken,
    --  checkOTP
    -- )
    where

import Codec.Binary.CRC
import Codec.Binary.DataEncoding as DE
import Codec.Binary.Hex
import Codec.Binary.ModHex
import Codec.Crypto.AES
import Data.Bits
import Data.Word.Word24
import Data.List
import Data.Word
import qualified Data.ByteString as BS

data FailureType
    = OTPReplay
    | InvalidPrefix
    | InvalidOTP
    | InvalidKey
    | InvalidModHex
    | InvalidDeviceID
    | InvalidCRC
    | InvalidToken
    | UnknownFailure String
    deriving (Show)

data VerificationResult
    = VerificationSuccessful Int Int
    | VerificationFailed FailureType
    deriving (Show)

data YubiKeyToken = YubiKeyToken {
    deviceID :: [Word8],        -- 8 bytes
    sessionCounter :: Word16,   -- 2 bytes
    timeStamp :: Word24,        -- 2+1 bytes
    sessionUse :: Word8,
    pseudoRandom :: Word16,     -- 2 bytes
    crc16 :: Word16,                -- 2 bytes
    bytes :: [Word8]
}

toYubiKeyToken :: BS.ByteString -> Either FailureType YubiKeyToken
toYubiKeyToken (BS.unpack -> verifyCRC -> False) = Left InvalidCRC
toYubiKeyToken (BS.unpack -> map fromIntegral -> (n1:n2:n3:n4:n5:n6:n7:n8:n9:n10:n11:n12:n13:n14:n15:n16:[])) = Right YubiKeyToken {
    deviceID = [n1,n2,n3,n4,n5,n6],
    sessionCounter = int8sToWord16 LittleEndian n7 n8,
    timeStamp = int8sToWord24 LittleEndian n9 n10 n11,
    sessionUse = n12,
    pseudoRandom = int8sToWord16 LittleEndian n13 n14,
    crc16 = int8sToWord16 LittleEndian n15 n16,
    bytes = map fromIntegral (n1:n2:n3:n4:n5:n6:n7:n8:n9:n10:n11:n12:n13:n14:n15:n16:[])
}
toYubiKeyToken _ = Left InvalidToken

data Endianness
    = BigEndian
    | LittleEndian

int8sToWord16 :: Endianness -> Word8 -> Word8 -> Word16
int8sToWord16 BigEndian n1 n2 = (shiftL (fromIntegral n1 :: Word16) 8) + (fromIntegral n2)
int8sToWord16 LittleEndian n2 n1 = (shiftL (fromIntegral n1 :: Word16) 8) + (fromIntegral n2)

int8sToWord24 :: Endianness -> Word8 -> Word8 -> Word8 -> Word24
int8sToWord24 BigEndian n1 n2 n3 = (shiftL (fromIntegral n1 :: Word24) 16) + (shiftL (fromIntegral n2 :: Word24) 8) + (fromIntegral n3)
int8sToWord24 LittleEndian n3 n2 n1 = (shiftL (fromIntegral n1 :: Word24) 16) + (shiftL (fromIntegral n2 :: Word24) 8) + (fromIntegral n3)

nullIV :: BS.ByteString
nullIV = BS.pack (replicate 16 ((fromIntegral 0) :: Word8))

getYubiKeyToken :: String -> String -> String -> Either FailureType YubiKeyToken
getYubiKeyToken _ (hexToByteString -> Nothing) _ = Left InvalidKey
getYubiKeyToken prefix _ (stripPrefix prefix -> Nothing) = Left InvalidPrefix
getYubiKeyToken prefix _ (stripPrefix prefix -> Just (modHexToByteString -> Nothing)) = Left InvalidModHex
getYubiKeyToken prefix (hexToByteString -> Just key) (stripPrefix prefix -> Just (modHexToByteString -> Just otp)) = case (toYubiKeyToken (crypt' ECB key nullIV Decrypt otp)) of
    Right token -> Right token
    Left error -> Left error

verifyYubiKeyToken :: [Word8] -> Int -> Int -> YubiKeyToken -> VerificationResult
verifyYubiKeyToken deviceID lastSession lastSessionUse (YubiKeyToken { deviceID = tokenID, sessionCounter = tokenSession, sessionUse = tokenSessionUse })
    | deviceID /= (map fromIntegral tokenID) = VerificationFailed InvalidDeviceID
    | tokenSession > (fromIntegral lastSession) = VerificationSuccessful (fromIntegral tokenSession) (fromIntegral tokenSessionUse)
    | tokenSession == (fromIntegral lastSession) && tokenSessionUse > (fromIntegral lastSessionUse) = VerificationSuccessful (fromIntegral tokenSession) (fromIntegral tokenSessionUse)
    | otherwise = VerificationFailed OTPReplay


checkOTP :: String -> String -> String -> [Word8] -> Int -> Int -> VerificationResult
checkOTP prefix key otp deviceID lastSession lastSessionUse = case (getYubiKeyToken prefix key otp) of
    Left failure -> VerificationFailed failure
    Right token -> verifyYubiKeyToken deviceID lastSession lastSessionUse token