{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module HYubikeyFFI where

import Foreign
import Foreign.C
import Foreign.C.String
import Foreign.Ptr
import Foreign.Marshal.Alloc

import Codec.Crypto.YubiKeyOTP
-- import System.PAM

import qualified Codec.Binary.Hex as H
import qualified Codec.Binary.ModHex as MH
import Data.List
import Data.Maybe

foreign export ccall "check_otp" foreignCheckOTP :: CString -> CString -> CString -> CString -> CInt -> CInt -> IO (Ptr HYubiKeyResult)

foreignCheckOTP :: CString -> CString -> CString -> CString -> CInt -> CInt -> IO (Ptr HYubiKeyResult)
foreignCheckOTP cPrefix cKey cOtp cDeviceID lastSession lastSessionUse =
    do
        prefix <- peekCAString cPrefix
        key <- peekCAString cKey
        otp <- peekCAString cOtp
        deviceIDStr <- peekCAString cDeviceID

        let res = case (H.decode deviceIDStr) of
             Just deviceID -> checkOTP prefix key otp deviceID (fromIntegral lastSession) (fromIntegral lastSessionUse)
             _ -> VerificationFailed InvalidDeviceID

        case res of
            VerificationSuccessful x y -> new (HYubiKeyResult True x y)
            VerificationFailed x -> new (HYubiKeyResult False 0 0)