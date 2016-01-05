{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module PamYubiKey where

import Foreign
import Foreign.C
import Foreign.C.String
import Foreign.Ptr
import Foreign.Marshal.Alloc

import Codec.Crypto.YubiKeyOTP
import System.PAM

import qualified Codec.Binary.Hex as H
import qualified Codec.Binary.ModHex as MH
import Data.List
import Data.Maybe

--instance Storable Struct where
--	alignment _ = #{alignment my_struct}
--	sizeOf _ = #{size my_struct}
--	peek ptr = do
--		a <- #{peek my_struct, a} ptr
--		b <- #{peek my_struct, b} ptr
--		c <- #{peek my_struct, c} ptr
--		return (MyStruct a, b, c)
--	poke ptr (Foo a b c) = do
--		#{poke my_struct, a} ptr a
--		#{poke my_struct, b} ptr b
--		#{poke my_struct, c} ptr c

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
			VerificationSuccessful x y -> new (HYubiKeyResult (fromIntegral (fromEnum PAMSuccess)) x y)
			VerificationFailed x -> new (HYubiKeyResult (fromIntegral (fromEnum PAMAuthErr)) 0 0)

		--let result = checkOTP prefix key otp deviceID (fromIntegral lastSession) (fromIntegral lastSessionUse)

		--case result of
		--	VerificationSuccessful _ _ -> return (fromIntegral (fromEnum PAMSuccess))
		--	_ -> return (fromIntegral (fromEnum PAMAuthErr))
--foreignCheckOTP :: CString -> CString -> CString -> CString -> CInt -> CInt
--foreignCheckOTP a b c 