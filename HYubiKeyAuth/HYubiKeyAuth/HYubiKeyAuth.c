//
//  HYubiKeyAuth.c
//  HYubiKeyAuth
//
//  Created by Turing Eret on 9/1/14.
//  Copyright (c) 2014 Turing Eret. All rights reserved.
//

#include <CoreServices/CoreServices.h>

#include <Security/AuthorizationPlugin.h>
#include <Security/AuthSession.h>
#include <Security/AuthorizationTags.h>

#include <syslog.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <OpenDirectory/OpenDirectory.h>
#include <DirectoryService/DirectoryService.h>


#include "HsFFI.h"
#ifdef __cplusplus
extern "C" {
#endif
    extern HsPtr check_otp(HsPtr a1, HsPtr a2, HsPtr a3, HsPtr a4, HsInt32 a5, HsInt32 a6);
#ifdef __cplusplus
}
#endif

#pragma mark ***** Core Data Structures

typedef struct PluginRecord PluginRecord;           // forward decl

#pragma mark *     Mechanism

// MechanismRecord is the per-mechanism data structure.  One of these
// is created for each mechanism that's instantiated, and holds all
// of the data needed to run that mechanism.  In this trivial example,
// that data set is very small.
//
// Mechanisms are single threaded; the code does not have to guard
// against multiple threads running inside the mechanism simultaneously.

enum
{
    kMechanismMagic = 'Mchn'
};

struct MechanismRecord
{
    OSType                          fMagic;         // must be kMechanismMagic
    AuthorizationEngineRef          fEngine;
    const PluginRecord *            fPlugin;
};
typedef struct MechanismRecord MechanismRecord;

static Boolean MechanismValid(const MechanismRecord *mechanism)
{
    return (mechanism != NULL)
    && (mechanism->fMagic == kMechanismMagic)
    && (mechanism->fEngine != NULL)
    && (mechanism->fPlugin != NULL);
}

#pragma mark *     Plugin

// PluginRecord is the per-plugin data structure.  As the system only
// instantiates a plugin once per plugin host, this information could
// just as easily be kept in global variables.  However, just to keep
// things tidy, I pushed it all into a single record.
//
// As a plugin may host multiple mechanism, and there's no guarantee
// that these mechanisms won't be running on different threads, data
// in this record should be protected from multiple concurrent access.
// In my case, however, all of the data is read-only, so I don't need
// to do anything special.

enum
{
    kPluginMagic = 'PlgN'
};

struct PluginRecord
{
    OSType                          fMagic;         // must be kPluginMagic
    const AuthorizationCallbacks *  fCallbacks;
};

static Boolean PluginValid(const PluginRecord *plugin)
{
    return (plugin != NULL)
    && (plugin->fMagic == kPluginMagic)
    && (plugin->fCallbacks != NULL)
    && (plugin->fCallbacks->version >= kAuthorizationCallbacksVersion);
}


/////////////////////////////////////////////////////////////////////
#pragma mark ***** Mechanism Entry Points

static OSStatus MechanismCreate(
                                AuthorizationPluginRef      inPlugin,
                                AuthorizationEngineRef      inEngine,
                                AuthorizationMechanismId    mechanismId,
                                AuthorizationMechanismRef * outMechanism
                                )
// Called by the plugin host to create a mechanism, that is, a specific
// instance of authentication.
//
// inPlugin is the plugin reference, that is, the value returned by
// AuthorizationPluginCreate.
//
// inEngine is a reference to the engine that's running the plugin.
// We need to keep it around because it's a parameter to all the
// callbacks.
//
// mechanismId is the name of the mechanism.  When you configure your
// mechanism in "/etc/authorization", you supply a string of the
// form:
//
//   plugin:mechanism[,privileged]
//
// where:
//
// o plugin is the name of this bundle (without the extension)
// o mechanism is the string that's passed to mechanismId
// o privileged, if present, causes this mechanism to be
//   instantiated in the privileged (rather than the GUI-capable)
//   plug-in host
//
// You can use the mechanismId to support multiple types of
// operation within the same plugin code.  For example, your plugin
// might have two cooperating mechanisms, one that needs to use the
// GUI and one that needs to run privileged.  This allows you to put
// both mechanisms in the same plugin.
//
// outMechanism is a pointer to a place where you return a reference to
// the newly created mechanism.
{
    OSStatus            err;
    PluginRecord *      plugin;
    MechanismRecord *   mechanism;
    
    plugin = (PluginRecord *) inPlugin;
    assert(PluginValid(plugin));
    assert(inEngine != NULL);
    assert(mechanismId != NULL);
    assert(outMechanism != NULL);
    
    // Allocate the space for the MechanismRecord.
    
    err = noErr;
    mechanism = (MechanismRecord *) malloc(sizeof(*mechanism));
    if (mechanism == NULL)
    {
        err = memFullErr;
    }
    
    // Fill it in.
    
    if (err == noErr)
    {
        mechanism->fMagic = kMechanismMagic;
        mechanism->fEngine = inEngine;
        mechanism->fPlugin = plugin;
    }
    
    *outMechanism = mechanism;
    
    assert( (err == noErr) == (*outMechanism != NULL) );
    
    return err;
}

typedef struct {
	int success;
	int last_session;
	int last_session_use;
} hyubikey_result;

#define AUTH_SUCCESS 1
#define AUTH_FAILURE 0


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

static int yubikey_authenticate(char* user, char* password)
{
	CFErrorRef odErr = NULL;
    int retval = 0;
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
                int argc = 0;
                char **argv = (char**)(char*[]){
                    "HYubiKeyAuth", NULL
                };
				struct YubiParameters params = GetYubiParameters(cfRecord);
                
				hs_init(&argc, &argv);
                
				hyubikey_result* result = NULL;
				result = check_otp(params.prefix, params.key, password, params.id, params.lastSession, params.lastSessionUse);
				if(result == NULL)
				{
					retval = AUTH_FAILURE;
				}
				else
				{
					retval = result->success;
					if(retval == AUTH_SUCCESS)
					{
						ODRecordSetValue(cfRecord, CFSTR("dsAttrTypeNative:YubiKeyLastSession"), CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("%d"), result->last_session), &odErr);
                        
                        if(odErr)
                        {
                            CFShow(odErr);
                            retval = AUTH_FAILURE;
                        }
						ODRecordSetValue(cfRecord, CFSTR("dsAttrTypeNative:YubiKeyLastSessionUse"), CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("%d"), result->last_session_use), &odErr);
                        if(odErr)
                        {
                            CFShow(odErr);
                            retval = AUTH_FAILURE;
                        }
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
				retval = AUTH_FAILURE;
			}
			CFRelease(cfUser);
			CFRelease(cfPassword);
		}
		CFRelease(cfNodeRef);
	}
    
	return retval;
}

static bool GetUsernameAndPassword(MechanismRecord* mechanism, const AuthorizationValue** username, const AuthorizationValue** password)
{
    AuthorizationContextFlags contextFlags;
    OSStatus err;
    
    //First, let's get the username. We'll try in the Context values first.
    err = mechanism->fPlugin->fCallbacks->GetContextValue(mechanism->fEngine,
                                                          kAuthorizationEnvironmentUsername,
                                                          &contextFlags,
                                                          username);
    
    //Uh oh, it isn't there. Let's try the hints.
    if(err)
    {
        err = mechanism->fPlugin->fCallbacks->GetHintValue(mechanism->fEngine,
                                                           kAuthorizationEnvironmentUsername,
                                                           username);
        
        //Failed to get it from the hints. No where else to look. We failed.
        if(err)
        {
            return false;
        }
    }
    
    //Now, let's get the password.
    err = mechanism->fPlugin->fCallbacks->GetContextValue(mechanism->fEngine,
                                                          kAuthorizationEnvironmentPassword,
                                                          &contextFlags,
                                                          password);
    
    //Not there. Hints.
    if(err)
    {
        err = mechanism->fPlugin->fCallbacks->GetHintValue(mechanism->fEngine,
                                                           kAuthorizationEnvironmentPassword,
                                                           password);
        
        //Not there either. We failed. Bail.
        if(err)
        {
            return false;
        }
    }
    
    //If we made it here, we're successful.
    return true;
}

/**
 *   A simple non-UI mechanism.
 */
static OSStatus invokeYubiKey(MechanismRecord* mechanism)
{
    const AuthorizationValue* passValue;
    const AuthorizationValue* usernameValue;
    OSStatus status;
    
    if(!GetUsernameAndPassword(mechanism, &usernameValue, &passValue))
    {
        return errAuthorizationInternal;
    }
    
    int result = yubikey_authenticate(usernameValue->data, passValue->data);
    
    
    if(result)
    {
        status = mechanism->fPlugin->fCallbacks->SetResult(mechanism->fEngine,
                                                         kAuthorizationResultAllow);
    }
    else
    {
        status = mechanism->fPlugin->fCallbacks->SetResult(mechanism->fEngine,
                                                         kAuthorizationResultDeny);
    }
    
    return status;
}

static OSStatus MechanismInvoke(AuthorizationMechanismRef inMechanism)
// Called by the system to start authentication using this mechanism.
// In a real plugin, this is where the real work is done.
{
    OSStatus                    err;
    MechanismRecord *           mechanism;
    
    mechanism = (MechanismRecord *) inMechanism;
    
    assert(MechanismValid(mechanism));
    
    err = invokeYubiKey(mechanism);
    
    return err;
}

static OSStatus MechanismDeactivate(AuthorizationMechanismRef inMechanism)
// Called by the system to deactivate the mechanism, in the traditional
// GUI sense of deactivating a window.  After your plugin has deactivated
// it's UI, it should call the DidDeactivate callback.
//
// In our case, we have no UI, so we just call DidDeactivate immediately.
{
    OSStatus            err;
    MechanismRecord *   mechanism;
    
    mechanism = (MechanismRecord *) inMechanism;
    
    assert(MechanismValid(mechanism));
    
    err = mechanism->fPlugin->fCallbacks->DidDeactivate(mechanism->fEngine);
    
    return err;
}

static OSStatus MechanismDestroy(AuthorizationMechanismRef inMechanism)
// Called by the system when it's done with the mechanism.
{
    MechanismRecord *   mechanism;
    
    mechanism = (MechanismRecord *) inMechanism;
    
    assert(MechanismValid(mechanism));
    
    free(mechanism);
    
    return noErr;
}

/////////////////////////////////////////////////////////////////////
#pragma mark ***** Plugin Entry Points

static OSStatus PluginDestroy(AuthorizationPluginRef inPlugin)
// Called by the system when it's done with the plugin.
// All of the mechanisms should have been destroyed by this time.
{
    PluginRecord *  plugin;
    
    plugin = (PluginRecord *) inPlugin;
    assert(PluginValid(plugin));
    
    free(plugin);
    
    return noErr;
}

// gPluginInterface is the plugin's dispatch table, a pointer to
// which you return from AuthorizationPluginCreate.  This is what
// allows the system to call the various entry points in the plugin.

static AuthorizationPluginInterface gPluginInterface = {
    kAuthorizationPluginInterfaceVersion,
    &PluginDestroy,
    &MechanismCreate,
    &MechanismInvoke,
    &MechanismDeactivate,
    &MechanismDestroy
};

extern OSStatus AuthorizationPluginCreate(
                                          const AuthorizationCallbacks *          callbacks,
                                          AuthorizationPluginRef *                outPlugin,
                                          const AuthorizationPluginInterface **   outPluginInterface
                                          )
// The primary entry point of the plugin.  Called by the system
// to instantiate the plugin.
//
// callbacks is a pointer to a bunch of callbacks that allow
// your plugin to ask the system to do operations on your behalf.
//
// outPlugin is a pointer to a place where you can return a
// reference to the newly created plugin.
//
// outPluginInterface is a pointer to a place where you can return
// a pointer to your plugin dispatch table.
{
    OSStatus        err;
    PluginRecord *  plugin;
    
    assert(callbacks != NULL);
    assert(callbacks->version >= kAuthorizationCallbacksVersion);
    assert(outPlugin != NULL);
    assert(outPluginInterface != NULL);
    
    // Create the plugin.
    
    err = noErr;
    plugin = (PluginRecord *) malloc(sizeof(*plugin));
    if (plugin == NULL)
    {
        err = memFullErr;
    }
    
    // Fill it in.
    
    if (err == noErr)
    {
        plugin->fMagic     = kPluginMagic;
        plugin->fCallbacks = callbacks;
    }
    
    *outPlugin = plugin;
    *outPluginInterface = &gPluginInterface;
    
    assert( (err == noErr) == (*outPlugin != NULL) );
    
    return err;
}

