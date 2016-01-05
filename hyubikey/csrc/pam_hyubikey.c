/*-
 * Copyright (c) 2002 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by ThinkSec AS and
 * Network Associates Laboratories, the Security Research Division of
 * Network Associates, Inc.  under DARPA/SPAWAR contract N66001-01-C-8035
 * ("CBOSS"), as part of the DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $P4: //depot/projects/openpam/modules/pam_unix/pam_unix.c#3 $
 * $FreeBSD: head/en_US.ISO8859-1/articles/pam/pam_unix.c 38826 2012-05-17 19:12:14Z hrs $
 */

#include <sys/param.h>

#include <pwd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <OpenDirectory/OpenDirectory.h>
// #include <OpenDirectory/OpenDirectoryPriv.h>
#include <DirectoryService/DirectoryService.h>

#define PAM_SM_AUTH 
#define PAM_SM_ACCOUNT 

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#include "PamYubiKey_stub.h"

#include "System/PAM.chs.h"

#ifndef _OPENPAM
static char password_prompt[] = "Password:";
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

struct YubiParameters
{
	char* key;
	char* id;
	char* prefix;
	char* serial;
	int lastSession;
	int lastSessionUse;
};

struct YubiParameters GetYubiParameters(ODRecordRef cfRecord)
{
	struct YubiParameters result;

	CFErrorRef odErr;

	CFStringRef cAttrs[] = {
		CFSTR("dsAttrTypeNative:YubiKeyAESKey"),
		CFSTR("dsAttrTypeNative:YubiKeyInternalID"),
		CFSTR("dsAttrTypeNative:YubiKeyPrefix"),
		CFSTR("dsAttrTypeNative:YubiKeySerialNumber"),
		CFSTR("dsAttrTypeNative:YubiKeyLastSession"),
		CFSTR("dsAttrTypeNative:YubiKeyLastSessionUse")
	};
	CFArrayRef attributes = CFArrayCreate(kCFAllocatorDefault, (const void**)cAttrs, 6, &kCFTypeArrayCallBacks);

	CFDictionaryRef yubiKeyRecords = ODRecordCopyDetails(cfRecord, attributes, &odErr);

	CFStringRef aes = CFArrayGetValueAtIndex(CFDictionaryGetValue(yubiKeyRecords, CFSTR("dsAttrTypeNative:YubiKeyAESKey")), 0);
	CFStringRef id = CFArrayGetValueAtIndex(CFDictionaryGetValue(yubiKeyRecords, CFSTR("dsAttrTypeNative:YubiKeyInternalID")), 0);
	CFStringRef prefix = CFArrayGetValueAtIndex(CFDictionaryGetValue(yubiKeyRecords, CFSTR("dsAttrTypeNative:YubiKeyPrefix")), 0);
	CFStringRef serialNumber = CFArrayGetValueAtIndex(CFDictionaryGetValue(yubiKeyRecords, CFSTR("dsAttrTypeNative:YubiKeySerialNumber")), 0);
	int lastSession = CFStringGetIntValue(CFArrayGetValueAtIndex(CFDictionaryGetValue(yubiKeyRecords, CFSTR("dsAttrTypeNative:YubiKeyLastSession")), 0));
	int lastSessionUse = CFStringGetIntValue(CFArrayGetValueAtIndex(CFDictionaryGetValue(yubiKeyRecords, CFSTR("dsAttrTypeNative:YubiKeyLastSessionUse")), 0));

	result.key = CFStringGetCStringPtr(aes, kCFStringEncodingUTF8);
	result.id = CFStringGetCStringPtr(id, kCFStringEncodingUTF8);
	result.prefix = CFStringGetCStringPtr(prefix, kCFStringEncodingUTF8);
	result.serial = CFStringGetCStringPtr(serialNumber, kCFStringEncodingUTF8);
	result.lastSession = lastSession;
	result.lastSessionUse = lastSessionUse;

	return result;

}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	static const char password_prompt[] = "Password:";
	int retval = PAM_SUCCESS;
	const char *user = NULL;
	const char *password = NULL;
	CFErrorRef odErr = NULL;


	if ((retval = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
	{
		return retval;
	}
	if (PAM_SUCCESS != (retval = pam_get_item(pamh, PAM_AUTHTOK, (void *)&password)))
	{
		return retval;
	}
	if (NULL == password)
	{
		if (PAM_SUCCESS != (retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL))) //password_prompt)))
		{
			return PAM_AUTH_ERR;
		}
	}
	if ((password[0] == '\0') && ((NULL == openpam_get_option(pamh, "nullok")) || (flags & PAM_DISALLOW_NULL_AUTHTOK)))
	{
		return PAM_AUTH_ERR;
	}

	/* verify the user's password */
	retval = PAM_USER_UNKNOWN;
	ODNodeRef cfNodeRef = ODNodeCreateWithNodeType(kCFAllocatorDefault, kODSessionDefault, eDSAuthenticationSearchNodeName, NULL);
	if (cfNodeRef != NULL)
	{
		CFStringRef cfUser = CFStringCreateWithCString(NULL, user, kCFStringEncodingUTF8);
		CFStringRef cfPassword = CFStringCreateWithCString(NULL, password, kCFStringEncodingUTF8);
		if ((cfUser != NULL) && (cfPassword != NULL))
		{
			ODRecordRef cfRecord = ODNodeCopyRecord(cfNodeRef, CFSTR(kDSStdRecordTypeUsers), cfUser, NULL, NULL);
			if (cfRecord != NULL)
			{

				struct YubiParameters params = GetYubiParameters(cfRecord);

				hs_init(&argc, &argv);

				hyubikey_result* result = NULL;
				result = check_otp(params.prefix, params.key, password, params.id, params.lastSession, params.lastSessionUse);
				if(result == NULL)
				{
					retval = PAM_AUTH_ERR;
				}
				else
				{
					retval = result->pam_return;
					if(retval == PAM_SUCCESS)
					{
						ODRecordSetValue(cfRecord, CFSTR("dsAttrTypeNative:YubiKeyLastSession"), CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("%d"), result->last_session), &odErr);
						ODRecordSetValue(cfRecord, CFSTR("dsAttrTypeNative:YubiKeyLastSessionUse"), CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("%d"), result->last_session_use), &odErr);
					}
					free(result);
				}
				
				CFRelease(cfRecord);
				if (odErr)
				{
					CFRelease(odErr);
				}
			}
			else
			{
				retval = PAM_AUTH_ERR;
			}
			CFRelease(cfUser);
			CFRelease(cfPassword);
		}
		CFRelease(cfNodeRef);
	}

	return retval;
}


PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_hyubikey");
#endif