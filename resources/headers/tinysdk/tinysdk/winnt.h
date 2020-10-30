#define ANYSIZE_ARRAY 1
#include <guiddef.h>

#if (defined(_M_IX86) || defined(_M_IA64) || defined(_M_AMD64) || defined(_M_ARM) || defined(_M_ARM64)) && !defined(MIDL_PASS)
#define DECLSPEC_IMPORT __declspec(dllimport)
#else
#define DECLSPEC_IMPORT
#endif


#if !defined(_NTSYSTEM_)
#define NTSYSAPI     DECLSPEC_IMPORT
#define NTSYSCALLAPI DECLSPEC_IMPORT
#else
#define NTSYSAPI
#if defined(_NTDLLBUILD_)
#define NTSYSCALLAPI
#else
#define NTSYSCALLAPI DECLSPEC_ADDRSAFE
#endif
#endif


#if (_MSC_VER >= 800) || defined(_STDCALL_SUPPORTED)
#define NTAPI __stdcall
#else
#define _cdecl
#define __cdecl
#define NTAPI
#endif


typedef struct _LUID {
    DWORD LowPart;
    LONG HighPart;
} LUID, *PLUID;

typedef unsigned char SECURITY_CONTEXT_TRACKING_MODE, *PSECURITY_CONTEXT_TRACKING_MODE;
typedef enum _SECURITY_IMPERSONATION_LEVEL {
  SecurityAnonymous,
  SecurityIdentification,
  SecurityImpersonation,
  SecurityDelegation
} SECURITY_IMPERSONATION_LEVEL, *PSECURITY_IMPERSONATION_LEVEL;
typedef struct _SECURITY_QUALITY_OF_SERVICE {
  DWORD                          Length;
  SECURITY_IMPERSONATION_LEVEL   ImpersonationLevel;
  SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode;
  BOOLEAN                        EffectiveOnly;
} SECURITY_QUALITY_OF_SERVICE, *PSECURITY_QUALITY_OF_SERVICE;

/*
typedef struct _SID_IDENTIFIER_AUTHORITY {
  BYTE Value[6];
} SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY;

typedef DWORD ACCESS_MASK;
typedef ACCESS_MASK* PACCESS_MASK;
typedef WORD SECURITY_DESCRIPTOR_CONTROL, *PSECURITY_DESCRIPTOR_CONTROL;
typedef struct _SID {
   BYTE  Revision;
   BYTE  SubAuthorityCount;
   SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
#ifdef MIDL_PASS
   DWORD SubAuthority[*];
#else // MIDL_PASS
   DWORD SubAuthority[ANYSIZE_ARRAY];
#endif // MIDL_PASS
} SID, *PSID, *PISID;


typedef struct _SECURITY_DESCRIPTOR {
  BYTE                        Revision;
  BYTE                        Sbz1;
  SECURITY_DESCRIPTOR_CONTROL Control;
  PSID                        Owner;
  PSID                        Group;
  PACL                        Sacl;
  PACL                        Dacl;
} SECURITY_DESCRIPTOR, *PISECURITY_DESCRIPTOR;
*/


typedef PVOID PACCESS_TOKEN;
typedef PVOID PSECURITY_DESCRIPTOR;
typedef PVOID PSID;
typedef PVOID PCLAIMS_BLOB;



typedef DWORD ACCESS_MASK;
typedef ACCESS_MASK *PACCESS_MASK;

#define DELETE                           (0x00010000L)
#define READ_CONTROL                     (0x00020000L)
#define WRITE_DAC                        (0x00040000L)
#define WRITE_OWNER                      (0x00080000L)
#define SYNCHRONIZE                      (0x00100000L)

#define STANDARD_RIGHTS_REQUIRED         (0x000F0000L)

#define STANDARD_RIGHTS_READ             (READ_CONTROL)
#define STANDARD_RIGHTS_WRITE            (READ_CONTROL)
#define STANDARD_RIGHTS_EXECUTE          (READ_CONTROL)

#define STANDARD_RIGHTS_ALL              (0x001F0000L)

#define SPECIFIC_RIGHTS_ALL              (0x0000FFFFL)


#define ACCESS_SYSTEM_SECURITY           (0x01000000L)


#define MAXIMUM_ALLOWED                  (0x02000000L)


#define GENERIC_READ                     (0x80000000L)
#define GENERIC_WRITE                    (0x40000000L)
#define GENERIC_EXECUTE                  (0x20000000L)
#define GENERIC_ALL                      (0x10000000L)

#define SECTION_QUERY                0x0001
#define SECTION_MAP_WRITE            0x0002
#define SECTION_MAP_READ             0x0004
#define SECTION_MAP_EXECUTE          0x0008
#define SECTION_EXTEND_SIZE          0x0010
#define SECTION_MAP_EXECUTE_EXPLICIT 0x0020 // not included in SECTION_ALL_ACCESS

#define SECTION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SECTION_QUERY|\
                            SECTION_MAP_WRITE |      \
                            SECTION_MAP_READ |       \
                            SECTION_MAP_EXECUTE |    \
                            SECTION_EXTEND_SIZE)


typedef struct _GENERIC_MAPPING {
    ACCESS_MASK GenericRead;
    ACCESS_MASK GenericWrite;
    ACCESS_MASK GenericExecute;
    ACCESS_MASK GenericAll;
} GENERIC_MAPPING;
typedef GENERIC_MAPPING *PGENERIC_MAPPING;


#include <pshpack4.h>

typedef struct _LUID_AND_ATTRIBUTES {
    LUID Luid;
    DWORD Attributes;
    } LUID_AND_ATTRIBUTES, * PLUID_AND_ATTRIBUTES;
typedef LUID_AND_ATTRIBUTES LUID_AND_ATTRIBUTES_ARRAY[ANYSIZE_ARRAY];
typedef LUID_AND_ATTRIBUTES_ARRAY *PLUID_AND_ATTRIBUTES_ARRAY;

#include <poppack.h>


#ifndef SID_IDENTIFIER_AUTHORITY_DEFINED
#define SID_IDENTIFIER_AUTHORITY_DEFINED
typedef struct _SID_IDENTIFIER_AUTHORITY {
    BYTE  Value[6];
} SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY;
#endif

#ifndef SID_DEFINED
#define SID_DEFINED
typedef struct _SID {
   BYTE  Revision;
   BYTE  SubAuthorityCount;
   SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
#ifdef MIDL_PASS
   [size_is(SubAuthorityCount)] DWORD SubAuthority[*];
#else // MIDL_PASS
   DWORD SubAuthority[ANYSIZE_ARRAY];
#endif // MIDL_PASS
} SID, *PISID;
#endif

#define SID_REVISION                     (1)    
#define SID_MAX_SUB_AUTHORITIES          (15)
#define SID_RECOMMENDED_SUB_AUTHORITIES  (1)    

#ifndef MIDL_PASS
#define SECURITY_MAX_SID_SIZE  \
      (sizeof(SID) - sizeof(DWORD) + (SID_MAX_SUB_AUTHORITIES * sizeof(DWORD)))

#define SECURITY_SID_SIZE(SubAuthorityCount_) (sizeof(SID) - sizeof(DWORD) + \
                                                (SubAuthorityCount_) * sizeof(DWORD))


#define SECURITY_MAX_SID_STRING_CHARACTERS \
    (2 + 4 + 15 + (11 * SID_MAX_SUB_AUTHORITIES) + 1)


typedef union _SE_SID {
    SID Sid;
    BYTE  Buffer[SECURITY_MAX_SID_SIZE];
} SE_SID, *PSE_SID;

#endif 


typedef enum _SID_NAME_USE {
    SidTypeUser = 1,
    SidTypeGroup,
    SidTypeDomain,
    SidTypeAlias,
    SidTypeWellKnownGroup,
    SidTypeDeletedAccount,
    SidTypeInvalid,
    SidTypeUnknown,
    SidTypeComputer,
    SidTypeLabel,
    SidTypeLogonSession
} SID_NAME_USE, *PSID_NAME_USE;

typedef struct _SID_AND_ATTRIBUTES {
#ifdef MIDL_PASS
    PISID Sid;
#else // MIDL_PASS
    PSID Sid;
#endif // MIDL_PASS
    DWORD Attributes;
    } SID_AND_ATTRIBUTES, * PSID_AND_ATTRIBUTES;

typedef SID_AND_ATTRIBUTES SID_AND_ATTRIBUTES_ARRAY[ANYSIZE_ARRAY];
typedef SID_AND_ATTRIBUTES_ARRAY *PSID_AND_ATTRIBUTES_ARRAY;

#define SID_HASH_SIZE 32
typedef ULONG_PTR SID_HASH_ENTRY, *PSID_HASH_ENTRY;

typedef struct _SID_AND_ATTRIBUTES_HASH {
    DWORD SidCount;
    PSID_AND_ATTRIBUTES SidAttr;
    SID_HASH_ENTRY Hash[SID_HASH_SIZE];
} SID_AND_ATTRIBUTES_HASH, *PSID_AND_ATTRIBUTES_HASH;



#define SECURITY_NULL_SID_AUTHORITY         {0,0,0,0,0,0}
#define SECURITY_WORLD_SID_AUTHORITY        {0,0,0,0,0,1}
#define SECURITY_LOCAL_SID_AUTHORITY        {0,0,0,0,0,2}
#define SECURITY_CREATOR_SID_AUTHORITY      {0,0,0,0,0,3}
#define SECURITY_NON_UNIQUE_AUTHORITY       {0,0,0,0,0,4}
#define SECURITY_RESOURCE_MANAGER_AUTHORITY {0,0,0,0,0,9}


#define SECURITY_NULL_RID                 (0x00000000L)
#define SECURITY_WORLD_RID                (0x00000000L)
#define SECURITY_LOCAL_RID                (0x00000000L)
#define SECURITY_LOCAL_LOGON_RID          (0x00000001L)

#define SECURITY_CREATOR_OWNER_RID        (0x00000000L)
#define SECURITY_CREATOR_GROUP_RID        (0x00000001L)

#define SECURITY_CREATOR_OWNER_SERVER_RID (0x00000002L)
#define SECURITY_CREATOR_GROUP_SERVER_RID (0x00000003L)

#define SECURITY_CREATOR_OWNER_RIGHTS_RID (0x00000004L)



#define SECURITY_NT_AUTHORITY           {0,0,0,0,0,5}   // ntifs

#define SECURITY_DIALUP_RID             (0x00000001L)
#define SECURITY_NETWORK_RID            (0x00000002L)
#define SECURITY_BATCH_RID              (0x00000003L)
#define SECURITY_INTERACTIVE_RID        (0x00000004L)
#define SECURITY_LOGON_IDS_RID          (0x00000005L)
#define SECURITY_LOGON_IDS_RID_COUNT    (3L)
#define SECURITY_SERVICE_RID            (0x00000006L)
#define SECURITY_ANONYMOUS_LOGON_RID    (0x00000007L)
#define SECURITY_PROXY_RID              (0x00000008L)
#define SECURITY_ENTERPRISE_CONTROLLERS_RID (0x00000009L)
#define SECURITY_SERVER_LOGON_RID       SECURITY_ENTERPRISE_CONTROLLERS_RID
#define SECURITY_PRINCIPAL_SELF_RID     (0x0000000AL)
#define SECURITY_AUTHENTICATED_USER_RID (0x0000000BL)
#define SECURITY_RESTRICTED_CODE_RID    (0x0000000CL)
#define SECURITY_TERMINAL_SERVER_RID    (0x0000000DL)
#define SECURITY_REMOTE_LOGON_RID       (0x0000000EL)
#define SECURITY_THIS_ORGANIZATION_RID  (0x0000000FL)
#define SECURITY_IUSER_RID              (0x00000011L)
#define SECURITY_LOCAL_SYSTEM_RID       (0x00000012L)
#define SECURITY_LOCAL_SERVICE_RID      (0x00000013L)
#define SECURITY_NETWORK_SERVICE_RID    (0x00000014L)

#define SECURITY_NT_NON_UNIQUE          (0x00000015L)
#define SECURITY_NT_NON_UNIQUE_SUB_AUTH_COUNT  (3L)

#define SECURITY_ENTERPRISE_READONLY_CONTROLLERS_RID (0x00000016L)

#define SECURITY_BUILTIN_DOMAIN_RID     (0x00000020L)
#define SECURITY_WRITE_RESTRICTED_CODE_RID (0x00000021L)


#define SECURITY_PACKAGE_BASE_RID       (0x00000040L)
#define SECURITY_PACKAGE_RID_COUNT      (2L)
#define SECURITY_PACKAGE_NTLM_RID       (0x0000000AL)
#define SECURITY_PACKAGE_SCHANNEL_RID   (0x0000000EL)
#define SECURITY_PACKAGE_DIGEST_RID     (0x00000015L)

#define SECURITY_CRED_TYPE_BASE_RID             (0x00000041L)
#define SECURITY_CRED_TYPE_RID_COUNT            (2L)
#define SECURITY_CRED_TYPE_THIS_ORG_CERT_RID    (0x00000001L)

#define SECURITY_MIN_BASE_RID           (0x00000050L)

#define SECURITY_SERVICE_ID_BASE_RID    (0x00000050L)
#define SECURITY_SERVICE_ID_RID_COUNT   (6L)

#define SECURITY_RESERVED_ID_BASE_RID   (0x00000051L)

#define SECURITY_APPPOOL_ID_BASE_RID    (0x00000052L)
#define SECURITY_APPPOOL_ID_RID_COUNT   (6L)

#define SECURITY_VIRTUALSERVER_ID_BASE_RID    (0x00000053L)
#define SECURITY_VIRTUALSERVER_ID_RID_COUNT   (6L)

#define SECURITY_USERMODEDRIVERHOST_ID_BASE_RID  (0x00000054L)
#define SECURITY_USERMODEDRIVERHOST_ID_RID_COUNT (6L)

#define SECURITY_CLOUD_INFRASTRUCTURE_SERVICES_ID_BASE_RID  (0x00000055L)
#define SECURITY_CLOUD_INFRASTRUCTURE_SERVICES_ID_RID_COUNT (6L)

#define SECURITY_WMIHOST_ID_BASE_RID  (0x00000056L)
#define SECURITY_WMIHOST_ID_RID_COUNT (6L)

#define SECURITY_TASK_ID_BASE_RID                 (0x00000057L)

#define SECURITY_NFS_ID_BASE_RID        (0x00000058L)

#define SECURITY_COM_ID_BASE_RID        (0x00000059L)

#define SECURITY_WINDOW_MANAGER_BASE_RID     (0x0000005AL)

#define SECURITY_RDV_GFX_BASE_RID       (0x0000005BL)

#define SECURITY_DASHOST_ID_BASE_RID    (0x0000005CL)
#define SECURITY_DASHOST_ID_RID_COUNT   (6L)

#define SECURITY_USERMANAGER_ID_BASE_RID    (0x0000005DL)
#define SECURITY_USERMANAGER_ID_RID_COUNT   (6L)

#define SECURITY_WINRM_ID_BASE_RID      (0x0000005EL)
#define SECURITY_WINRM_ID_RID_COUNT     (6L)

#define SECURITY_CCG_ID_BASE_RID        (0x0000005FL)
#define SECURITY_UMFD_BASE_RID          (0x00000060L)

#define SECURITY_VIRTUALACCOUNT_ID_RID_COUNT   (6L)


#define SECURITY_MAX_BASE_RID           (0x0000006FL)
#define SECURITY_MAX_ALWAYS_FILTERED    (0x000003E7L)
#define SECURITY_MIN_NEVER_FILTERED     (0x000003E8L)

#define SECURITY_OTHER_ORGANIZATION_RID (0x000003E8L)


#define SECURITY_WINDOWSMOBILE_ID_BASE_RID (0x00000070L)


#define SECURITY_INSTALLER_GROUP_CAPABILITY_BASE (0x20)
#define SECURITY_INSTALLER_GROUP_CAPABILITY_RID_COUNT (9)


#define SECURITY_INSTALLER_CAPABILITY_RID_COUNT (10)


#define SECURITY_LOCAL_ACCOUNT_RID (0x00000071L)
#define SECURITY_LOCAL_ACCOUNT_AND_ADMIN_RID (0x00000072L)


#define DOMAIN_GROUP_RID_AUTHORIZATION_DATA_IS_COMPOUNDED       (0x000001F0L)
#define DOMAIN_GROUP_RID_AUTHORIZATION_DATA_CONTAINS_CLAIMS     (0x000001F1L)
#define DOMAIN_GROUP_RID_ENTERPRISE_READONLY_DOMAIN_CONTROLLERS (0x000001F2L)

#define FOREST_USER_RID_MAX            (0x000001F3L)


#define DOMAIN_USER_RID_ADMIN                (0x000001F4L)
#define DOMAIN_USER_RID_GUEST                (0x000001F5L)
#define DOMAIN_USER_RID_KRBTGT               (0x000001F6L)
#define DOMAIN_USER_RID_DEFAULT_ACCOUNT      (0x000001F7L)
#define DOMAIN_USER_RID_WDAG_ACCOUNT         (0x000001F8L)

#define DOMAIN_USER_RID_MAX            (0x000003E7L)



#define DOMAIN_GROUP_RID_ADMINS        (0x00000200L)
#define DOMAIN_GROUP_RID_USERS         (0x00000201L)
#define DOMAIN_GROUP_RID_GUESTS        (0x00000202L)
#define DOMAIN_GROUP_RID_COMPUTERS     (0x00000203L)
#define DOMAIN_GROUP_RID_CONTROLLERS   (0x00000204L)
#define DOMAIN_GROUP_RID_CERT_ADMINS   (0x00000205L)
#define DOMAIN_GROUP_RID_SCHEMA_ADMINS (0x00000206L)
#define DOMAIN_GROUP_RID_ENTERPRISE_ADMINS (0x00000207L)
#define DOMAIN_GROUP_RID_POLICY_ADMINS (0x00000208L)
#define DOMAIN_GROUP_RID_READONLY_CONTROLLERS (0x00000209L)
#define DOMAIN_GROUP_RID_CLONEABLE_CONTROLLERS (0x0000020AL)
#define DOMAIN_GROUP_RID_CDC_RESERVED    (0x0000020CL)
#define DOMAIN_GROUP_RID_PROTECTED_USERS (0x0000020DL)
#define DOMAIN_GROUP_RID_KEY_ADMINS      (0x0000020EL)
#define DOMAIN_GROUP_RID_ENTERPRISE_KEY_ADMINS (0x0000020FL)


#define DOMAIN_ALIAS_RID_ADMINS                         (0x00000220L)
#define DOMAIN_ALIAS_RID_USERS                          (0x00000221L)
#define DOMAIN_ALIAS_RID_GUESTS                         (0x00000222L)
#define DOMAIN_ALIAS_RID_POWER_USERS                    (0x00000223L)

#define DOMAIN_ALIAS_RID_ACCOUNT_OPS                    (0x00000224L)
#define DOMAIN_ALIAS_RID_SYSTEM_OPS                     (0x00000225L)
#define DOMAIN_ALIAS_RID_PRINT_OPS                      (0x00000226L)
#define DOMAIN_ALIAS_RID_BACKUP_OPS                     (0x00000227L)

#define DOMAIN_ALIAS_RID_REPLICATOR                     (0x00000228L)
#define DOMAIN_ALIAS_RID_RAS_SERVERS                    (0x00000229L)
#define DOMAIN_ALIAS_RID_PREW2KCOMPACCESS               (0x0000022AL)
#define DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS           (0x0000022BL)
#define DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS      (0x0000022CL)
#define DOMAIN_ALIAS_RID_INCOMING_FOREST_TRUST_BUILDERS (0x0000022DL)

#define DOMAIN_ALIAS_RID_MONITORING_USERS               (0x0000022EL)
#define DOMAIN_ALIAS_RID_LOGGING_USERS                  (0x0000022FL)
#define DOMAIN_ALIAS_RID_AUTHORIZATIONACCESS            (0x00000230L)
#define DOMAIN_ALIAS_RID_TS_LICENSE_SERVERS             (0x00000231L)
#define DOMAIN_ALIAS_RID_DCOM_USERS                     (0x00000232L)
#define DOMAIN_ALIAS_RID_IUSERS                         (0x00000238L)
#define DOMAIN_ALIAS_RID_CRYPTO_OPERATORS               (0x00000239L)
#define DOMAIN_ALIAS_RID_CACHEABLE_PRINCIPALS_GROUP     (0x0000023BL)
#define DOMAIN_ALIAS_RID_NON_CACHEABLE_PRINCIPALS_GROUP (0x0000023CL)
#define DOMAIN_ALIAS_RID_EVENT_LOG_READERS_GROUP        (0x0000023DL)
#define DOMAIN_ALIAS_RID_CERTSVC_DCOM_ACCESS_GROUP      (0x0000023EL)
#define DOMAIN_ALIAS_RID_RDS_REMOTE_ACCESS_SERVERS      (0x0000023FL)
#define DOMAIN_ALIAS_RID_RDS_ENDPOINT_SERVERS           (0x00000240L)
#define DOMAIN_ALIAS_RID_RDS_MANAGEMENT_SERVERS         (0x00000241L)
#define DOMAIN_ALIAS_RID_HYPER_V_ADMINS                 (0x00000242L)
#define DOMAIN_ALIAS_RID_ACCESS_CONTROL_ASSISTANCE_OPS  (0x00000243L)
#define DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS        (0x00000244L)
#define DOMAIN_ALIAS_RID_DEFAULT_ACCOUNT                (0x00000245L)
#define DOMAIN_ALIAS_RID_STORAGE_REPLICA_ADMINS         (0x00000246L)
#define DOMAIN_ALIAS_RID_DEVICE_OWNERS                  (0x00000247L)


#define SECURITY_APP_PACKAGE_AUTHORITY              {0,0,0,0,0,15}

#define SECURITY_APP_PACKAGE_BASE_RID               (0x00000002L)
#define SECURITY_BUILTIN_APP_PACKAGE_RID_COUNT      (2L)
#define SECURITY_APP_PACKAGE_RID_COUNT              (8L)
#define SECURITY_CAPABILITY_BASE_RID                (0x00000003L)
#define SECURITY_CAPABILITY_APP_RID                 (0x000000400)
#define SECURITY_BUILTIN_CAPABILITY_RID_COUNT       (2L)
#define SECURITY_CAPABILITY_RID_COUNT               (5L)
#define SECURITY_PARENT_PACKAGE_RID_COUNT           (SECURITY_APP_PACKAGE_RID_COUNT)
#define SECURITY_CHILD_PACKAGE_RID_COUNT            (12L)



#define SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE        	(0x00000001L)
#define SECURITY_BUILTIN_PACKAGE_ANY_RESTRICTED_PACKAGE (0x00000002L)



#define SECURITY_CAPABILITY_INTERNET_CLIENT                     (0x00000001L)
#define SECURITY_CAPABILITY_INTERNET_CLIENT_SERVER              (0x00000002L)
#define SECURITY_CAPABILITY_PRIVATE_NETWORK_CLIENT_SERVER       (0x00000003L)
#define SECURITY_CAPABILITY_PICTURES_LIBRARY                    (0x00000004L)
#define SECURITY_CAPABILITY_VIDEOS_LIBRARY                      (0x00000005L)
#define SECURITY_CAPABILITY_MUSIC_LIBRARY                       (0x00000006L)
#define SECURITY_CAPABILITY_DOCUMENTS_LIBRARY                   (0x00000007L)
#define SECURITY_CAPABILITY_ENTERPRISE_AUTHENTICATION           (0x00000008L)
#define SECURITY_CAPABILITY_SHARED_USER_CERTIFICATES            (0x00000009L)
#define SECURITY_CAPABILITY_REMOVABLE_STORAGE                   (0x0000000AL)
#define SECURITY_CAPABILITY_APPOINTMENTS                        (0x0000000BL)
#define SECURITY_CAPABILITY_CONTACTS                            (0x0000000CL)

#define SECURITY_CAPABILITY_INTERNET_EXPLORER                   (0x00001000L)



#define SECURITY_MANDATORY_LABEL_AUTHORITY          {0,0,0,0,0,16}
#define SECURITY_MANDATORY_UNTRUSTED_RID            (0x00000000L)
#define SECURITY_MANDATORY_LOW_RID                  (0x00001000L)
#define SECURITY_MANDATORY_MEDIUM_RID               (0x00002000L)
#define SECURITY_MANDATORY_MEDIUM_PLUS_RID          (SECURITY_MANDATORY_MEDIUM_RID + 0x100)
#define SECURITY_MANDATORY_HIGH_RID                 (0x00003000L)
#define SECURITY_MANDATORY_SYSTEM_RID               (0x00004000L)
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID    (0x00005000L)



#define SECURITY_MANDATORY_MAXIMUM_USER_RID   SECURITY_MANDATORY_SYSTEM_RID

#define MANDATORY_LEVEL_TO_MANDATORY_RID(IL) (IL * 0x1000)

#define SECURITY_SCOPED_POLICY_ID_AUTHORITY             {0,0,0,0,0,17}



#define SECURITY_AUTHENTICATION_AUTHORITY                        {0,0,0,0,0,18}
#define SECURITY_AUTHENTICATION_AUTHORITY_RID_COUNT              (1L)
#define SECURITY_AUTHENTICATION_AUTHORITY_ASSERTED_RID           (0x00000001L)
#define SECURITY_AUTHENTICATION_SERVICE_ASSERTED_RID             (0x00000002L)
#define SECURITY_AUTHENTICATION_FRESH_KEY_AUTH_RID               (0x00000003L)
#define SECURITY_AUTHENTICATION_KEY_TRUST_RID                    (0x00000004L)
#define SECURITY_AUTHENTICATION_KEY_PROPERTY_MFA_RID             (0x00000005L)
#define SECURITY_AUTHENTICATION_KEY_PROPERTY_ATTESTATION_RID     (0x00000006L)

#define SECURITY_PROCESS_TRUST_AUTHORITY    {0,0,0,0,0,19}
#define SECURITY_PROCESS_TRUST_AUTHORITY_RID_COUNT (2L)

#define SECURITY_PROCESS_PROTECTION_TYPE_FULL_RID           (0x00000400L)
#define SECURITY_PROCESS_PROTECTION_TYPE_LITE_RID           (0x00000200L)
#define SECURITY_PROCESS_PROTECTION_TYPE_NONE_RID           (0x00000000L)

#define SECURITY_PROCESS_PROTECTION_LEVEL_WINTCB_RID        (0x00002000L)
#define SECURITY_PROCESS_PROTECTION_LEVEL_WINDOWS_RID       (0x00001000L)
#define SECURITY_PROCESS_PROTECTION_LEVEL_APP_RID           (0x00000800L)
#define SECURITY_PROCESS_PROTECTION_LEVEL_ANTIMALWARE_RID   (0x00000600L)
#define SECURITY_PROCESS_PROTECTION_LEVEL_AUTHENTICODE_RID  (0x00000400L)
#define SECURITY_PROCESS_PROTECTION_LEVEL_NONE_RID          (0x00000000L)



#define SECURITY_TRUSTED_INSTALLER_RID1 956008885
#define SECURITY_TRUSTED_INSTALLER_RID2 3418522649
#define SECURITY_TRUSTED_INSTALLER_RID3 1831038044
#define SECURITY_TRUSTED_INSTALLER_RID4 1853292631
#define SECURITY_TRUSTED_INSTALLER_RID5 2271478464





typedef enum {

    WinNullSid                                  = 0,
    WinWorldSid                                 = 1,
    WinLocalSid                                 = 2,
    WinCreatorOwnerSid                          = 3,
    WinCreatorGroupSid                          = 4,
    WinCreatorOwnerServerSid                    = 5,
    WinCreatorGroupServerSid                    = 6,
    WinNtAuthoritySid                           = 7,
    WinDialupSid                                = 8,
    WinNetworkSid                               = 9,
    WinBatchSid                                 = 10,
    WinInteractiveSid                           = 11,
    WinServiceSid                               = 12,
    WinAnonymousSid                             = 13,
    WinProxySid                                 = 14,
    WinEnterpriseControllersSid                 = 15,
    WinSelfSid                                  = 16,
    WinAuthenticatedUserSid                     = 17,
    WinRestrictedCodeSid                        = 18,
    WinTerminalServerSid                        = 19,
    WinRemoteLogonIdSid                         = 20,
    WinLogonIdsSid                              = 21,
    WinLocalSystemSid                           = 22,
    WinLocalServiceSid                          = 23,
    WinNetworkServiceSid                        = 24,
    WinBuiltinDomainSid                         = 25,
    WinBuiltinAdministratorsSid                 = 26,
    WinBuiltinUsersSid                          = 27,
    WinBuiltinGuestsSid                         = 28,
    WinBuiltinPowerUsersSid                     = 29,
    WinBuiltinAccountOperatorsSid               = 30,
    WinBuiltinSystemOperatorsSid                = 31,
    WinBuiltinPrintOperatorsSid                 = 32,
    WinBuiltinBackupOperatorsSid                = 33,
    WinBuiltinReplicatorSid                     = 34,
    WinBuiltinPreWindows2000CompatibleAccessSid = 35,
    WinBuiltinRemoteDesktopUsersSid             = 36,
    WinBuiltinNetworkConfigurationOperatorsSid  = 37,
    WinAccountAdministratorSid                  = 38,
    WinAccountGuestSid                          = 39,
    WinAccountKrbtgtSid                         = 40,
    WinAccountDomainAdminsSid                   = 41,
    WinAccountDomainUsersSid                    = 42,
    WinAccountDomainGuestsSid                   = 43,
    WinAccountComputersSid                      = 44,
    WinAccountControllersSid                    = 45,
    WinAccountCertAdminsSid                     = 46,
    WinAccountSchemaAdminsSid                   = 47,
    WinAccountEnterpriseAdminsSid               = 48,
    WinAccountPolicyAdminsSid                   = 49,
    WinAccountRasAndIasServersSid               = 50,
    WinNTLMAuthenticationSid                    = 51,
    WinDigestAuthenticationSid                  = 52,
    WinSChannelAuthenticationSid                = 53,
    WinThisOrganizationSid                      = 54,
    WinOtherOrganizationSid                     = 55,
    WinBuiltinIncomingForestTrustBuildersSid    = 56,
    WinBuiltinPerfMonitoringUsersSid            = 57,
    WinBuiltinPerfLoggingUsersSid               = 58,
    WinBuiltinAuthorizationAccessSid            = 59,
    WinBuiltinTerminalServerLicenseServersSid   = 60,
    WinBuiltinDCOMUsersSid                      = 61,
    WinBuiltinIUsersSid                         = 62,
    WinIUserSid                                 = 63,
    WinBuiltinCryptoOperatorsSid                = 64,
    WinUntrustedLabelSid                        = 65,
    WinLowLabelSid                              = 66,
    WinMediumLabelSid                           = 67,
    WinHighLabelSid                             = 68,
    WinSystemLabelSid                           = 69,
    WinWriteRestrictedCodeSid                   = 70,
    WinCreatorOwnerRightsSid                    = 71,
    WinCacheablePrincipalsGroupSid              = 72,
    WinNonCacheablePrincipalsGroupSid           = 73,
    WinEnterpriseReadonlyControllersSid         = 74,
    WinAccountReadonlyControllersSid            = 75,
    WinBuiltinEventLogReadersGroup              = 76,
    WinNewEnterpriseReadonlyControllersSid      = 77,
    WinBuiltinCertSvcDComAccessGroup            = 78,
    WinMediumPlusLabelSid                       = 79,
    WinLocalLogonSid                            = 80,
    WinConsoleLogonSid                          = 81,
    WinThisOrganizationCertificateSid           = 82,
    WinApplicationPackageAuthoritySid           = 83,
    WinBuiltinAnyPackageSid                     = 84,
    WinCapabilityInternetClientSid              = 85,
    WinCapabilityInternetClientServerSid        = 86,
    WinCapabilityPrivateNetworkClientServerSid  = 87,
    WinCapabilityPicturesLibrarySid             = 88,
    WinCapabilityVideosLibrarySid               = 89,
    WinCapabilityMusicLibrarySid                = 90,
    WinCapabilityDocumentsLibrarySid            = 91,
    WinCapabilitySharedUserCertificatesSid      = 92,
    WinCapabilityEnterpriseAuthenticationSid    = 93,
    WinCapabilityRemovableStorageSid            = 94,
    WinBuiltinRDSRemoteAccessServersSid         = 95,
    WinBuiltinRDSEndpointServersSid             = 96,
    WinBuiltinRDSManagementServersSid           = 97,
    WinUserModeDriversSid                       = 98,
    WinBuiltinHyperVAdminsSid                   = 99,
    WinAccountCloneableControllersSid           = 100,
    WinBuiltinAccessControlAssistanceOperatorsSid = 101,
    WinBuiltinRemoteManagementUsersSid          = 102,
    WinAuthenticationAuthorityAssertedSid       = 103,
    WinAuthenticationServiceAssertedSid         = 104,
    WinLocalAccountSid                          = 105,
    WinLocalAccountAndAdministratorSid          = 106,
    WinAccountProtectedUsersSid                 = 107,
    WinCapabilityAppointmentsSid                = 108,
    WinCapabilityContactsSid                    = 109,
    WinAccountDefaultSystemManagedSid           = 110,
    WinBuiltinDefaultSystemManagedGroupSid      = 111,
    WinBuiltinStorageReplicaAdminsSid           = 112,
    WinAccountKeyAdminsSid                      = 113,
    WinAccountEnterpriseKeyAdminsSid            = 114,
    WinAuthenticationKeyTrustSid                = 115,
    WinAuthenticationKeyPropertyMFASid          = 116,
    WinAuthenticationKeyPropertyAttestationSid  = 117,
    WinAuthenticationFreshKeyAuthSid            = 118,
    WinBuiltinDeviceOwnersSid                   = 119,
} WELL_KNOWN_SID_TYPE;



#define SYSTEM_LUID                     { 0x3e7, 0x0 }
#define ANONYMOUS_LOGON_LUID            { 0x3e6, 0x0 }
#define LOCALSERVICE_LUID               { 0x3e5, 0x0 }
#define NETWORKSERVICE_LUID             { 0x3e4, 0x0 }
#define IUSER_LUID                      { 0x3e3, 0x0 }
#define PROTECTED_TO_SYSTEM_LUID        { 0x3e2, 0x0 }



#define SE_GROUP_MANDATORY                 (0x00000001L)
#define SE_GROUP_ENABLED_BY_DEFAULT        (0x00000002L)
#define SE_GROUP_ENABLED                   (0x00000004L)
#define SE_GROUP_OWNER                     (0x00000008L)
#define SE_GROUP_USE_FOR_DENY_ONLY         (0x00000010L)
#define SE_GROUP_INTEGRITY                 (0x00000020L)
#define SE_GROUP_INTEGRITY_ENABLED         (0x00000040L)
#define SE_GROUP_LOGON_ID                  (0xC0000000L)
#define SE_GROUP_RESOURCE                  (0x20000000L)

#define SE_GROUP_VALID_ATTRIBUTES          (SE_GROUP_MANDATORY          | \
                                            SE_GROUP_ENABLED_BY_DEFAULT | \
                                            SE_GROUP_ENABLED            | \
                                            SE_GROUP_OWNER              | \
                                            SE_GROUP_USE_FOR_DENY_ONLY  | \
                                            SE_GROUP_LOGON_ID           | \
                                            SE_GROUP_RESOURCE           | \
                                            SE_GROUP_INTEGRITY          | \
                                            SE_GROUP_INTEGRITY_ENABLED)




#define ACL_REVISION     (2)
#define ACL_REVISION_DS  (4)


#define ACL_REVISION1   (1)
#define MIN_ACL_REVISION ACL_REVISION2
#define ACL_REVISION2   (2)
#define ACL_REVISION3   (3)
#define ACL_REVISION4   (4)
#define MAX_ACL_REVISION ACL_REVISION4

typedef struct _ACL {
    BYTE  AclRevision;
    BYTE  Sbz1;
    WORD   AclSize;
    WORD   AceCount;
    WORD   Sbz2;
} ACL;
typedef ACL *PACL;



typedef struct _ACE_HEADER {
    BYTE  AceType;
    BYTE  AceFlags;
    WORD   AceSize;
} ACE_HEADER;
typedef ACE_HEADER *PACE_HEADER;

#define ACCESS_MIN_MS_ACE_TYPE                  (0x0)
#define ACCESS_ALLOWED_ACE_TYPE                 (0x0)
#define ACCESS_DENIED_ACE_TYPE                  (0x1)
#define SYSTEM_AUDIT_ACE_TYPE                   (0x2)
#define SYSTEM_ALARM_ACE_TYPE                   (0x3)
#define ACCESS_MAX_MS_V2_ACE_TYPE               (0x3)

#define ACCESS_ALLOWED_COMPOUND_ACE_TYPE        (0x4)
#define ACCESS_MAX_MS_V3_ACE_TYPE               (0x4)

#define ACCESS_MIN_MS_OBJECT_ACE_TYPE           (0x5)
#define ACCESS_ALLOWED_OBJECT_ACE_TYPE          (0x5)
#define ACCESS_DENIED_OBJECT_ACE_TYPE           (0x6)
#define SYSTEM_AUDIT_OBJECT_ACE_TYPE            (0x7)
#define SYSTEM_ALARM_OBJECT_ACE_TYPE            (0x8)
#define ACCESS_MAX_MS_OBJECT_ACE_TYPE           (0x8)

#define ACCESS_MAX_MS_V4_ACE_TYPE               (0x8)
#define ACCESS_MAX_MS_ACE_TYPE                  (0x8)

#define ACCESS_ALLOWED_CALLBACK_ACE_TYPE        (0x9)
#define ACCESS_DENIED_CALLBACK_ACE_TYPE         (0xA)
#define ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE (0xB)
#define ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  (0xC)
#define SYSTEM_AUDIT_CALLBACK_ACE_TYPE          (0xD)
#define SYSTEM_ALARM_CALLBACK_ACE_TYPE          (0xE)
#define SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   (0xF)
#define SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   (0x10)

#define SYSTEM_MANDATORY_LABEL_ACE_TYPE         (0x11)
#define SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE      (0x12)
#define SYSTEM_SCOPED_POLICY_ID_ACE_TYPE        (0x13)
#define SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE     (0x14)
#define SYSTEM_ACCESS_FILTER_ACE_TYPE           (0x15)
#define ACCESS_MAX_MS_V5_ACE_TYPE               (0x15)



#define OBJECT_INHERIT_ACE                (0x1)
#define CONTAINER_INHERIT_ACE             (0x2)
#define NO_PROPAGATE_INHERIT_ACE          (0x4)
#define INHERIT_ONLY_ACE                  (0x8)
#define INHERITED_ACE                     (0x10)
#define VALID_INHERIT_FLAGS               (0x1F)




#define CRITICAL_ACE_FLAG              (0x20)


#define SUCCESSFUL_ACCESS_ACE_FLAG       (0x40)
#define FAILED_ACCESS_ACE_FLAG           (0x80)



#define TRUST_PROTECTED_FILTER_ACE_FLAG  (0x40)



typedef struct _ACCESS_ALLOWED_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
} ACCESS_ALLOWED_ACE;

typedef ACCESS_ALLOWED_ACE *PACCESS_ALLOWED_ACE;

typedef struct _ACCESS_DENIED_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
} ACCESS_DENIED_ACE;
typedef ACCESS_DENIED_ACE *PACCESS_DENIED_ACE;

typedef struct _SYSTEM_AUDIT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
} SYSTEM_AUDIT_ACE;
typedef SYSTEM_AUDIT_ACE *PSYSTEM_AUDIT_ACE;

typedef struct _SYSTEM_ALARM_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
} SYSTEM_ALARM_ACE;
typedef SYSTEM_ALARM_ACE *PSYSTEM_ALARM_ACE;

typedef struct _SYSTEM_RESOURCE_ATTRIBUTE_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
} SYSTEM_RESOURCE_ATTRIBUTE_ACE, *PSYSTEM_RESOURCE_ATTRIBUTE_ACE;

typedef struct _SYSTEM_SCOPED_POLICY_ID_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
} SYSTEM_SCOPED_POLICY_ID_ACE, *PSYSTEM_SCOPED_POLICY_ID_ACE;

typedef struct _SYSTEM_MANDATORY_LABEL_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
} SYSTEM_MANDATORY_LABEL_ACE, *PSYSTEM_MANDATORY_LABEL_ACE;

typedef struct _SYSTEM_PROCESS_TRUST_LABEL_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
} SYSTEM_PROCESS_TRUST_LABEL_ACE, *PSYSTEM_PROCESS_TRUST_LABEL_ACE;

typedef struct _SYSTEM_ACCESS_FILTER_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
} SYSTEM_ACCESS_FILTER_ACE, *PSYSTEM_ACCESS_FILTER_ACE;

#define SYSTEM_MANDATORY_LABEL_NO_WRITE_UP         0x1
#define SYSTEM_MANDATORY_LABEL_NO_READ_UP          0x2
#define SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP       0x4

#define SYSTEM_MANDATORY_LABEL_VALID_MASK (SYSTEM_MANDATORY_LABEL_NO_WRITE_UP   | \
                                           SYSTEM_MANDATORY_LABEL_NO_READ_UP    | \
                                           SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP)

#define SYSTEM_PROCESS_TRUST_LABEL_VALID_MASK      0x00ffffff
#define SYSTEM_PROCESS_TRUST_NOCONSTRAINT_MASK     0xffffffff
#define SYSTEM_ACCESS_FILTER_VALID_MASK            0x00ffffff
#define SYSTEM_ACCESS_FILTER_NOCONSTRAINT_MASK     0xffffffff


typedef struct _ACCESS_ALLOWED_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
} ACCESS_ALLOWED_OBJECT_ACE, *PACCESS_ALLOWED_OBJECT_ACE;

typedef struct _ACCESS_DENIED_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
} ACCESS_DENIED_OBJECT_ACE, *PACCESS_DENIED_OBJECT_ACE;

typedef struct _SYSTEM_AUDIT_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
} SYSTEM_AUDIT_OBJECT_ACE, *PSYSTEM_AUDIT_OBJECT_ACE;

typedef struct _SYSTEM_ALARM_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
} SYSTEM_ALARM_OBJECT_ACE, *PSYSTEM_ALARM_OBJECT_ACE;



typedef struct _ACCESS_ALLOWED_CALLBACK_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
} ACCESS_ALLOWED_CALLBACK_ACE, *PACCESS_ALLOWED_CALLBACK_ACE;

typedef struct _ACCESS_DENIED_CALLBACK_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
} ACCESS_DENIED_CALLBACK_ACE, *PACCESS_DENIED_CALLBACK_ACE;

typedef struct _SYSTEM_AUDIT_CALLBACK_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
} SYSTEM_AUDIT_CALLBACK_ACE, *PSYSTEM_AUDIT_CALLBACK_ACE;

typedef struct _SYSTEM_ALARM_CALLBACK_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
} SYSTEM_ALARM_CALLBACK_ACE, *PSYSTEM_ALARM_CALLBACK_ACE;

typedef struct _ACCESS_ALLOWED_CALLBACK_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
} ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, *PACCESS_ALLOWED_CALLBACK_OBJECT_ACE;

typedef struct _ACCESS_DENIED_CALLBACK_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
} ACCESS_DENIED_CALLBACK_OBJECT_ACE, *PACCESS_DENIED_CALLBACK_OBJECT_ACE;

typedef struct _SYSTEM_AUDIT_CALLBACK_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
} SYSTEM_AUDIT_CALLBACK_OBJECT_ACE, *PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE;

typedef struct _SYSTEM_ALARM_CALLBACK_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
} SYSTEM_ALARM_CALLBACK_OBJECT_ACE, *PSYSTEM_ALARM_CALLBACK_OBJECT_ACE;


#define ACE_OBJECT_TYPE_PRESENT           0x1
#define ACE_INHERITED_OBJECT_TYPE_PRESENT 0x2



typedef enum _ACL_INFORMATION_CLASS {
    AclRevisionInformation = 1,
    AclSizeInformation
} ACL_INFORMATION_CLASS;


typedef struct _ACL_REVISION_INFORMATION {
    DWORD AclRevision;
} ACL_REVISION_INFORMATION;
typedef ACL_REVISION_INFORMATION *PACL_REVISION_INFORMATION;


typedef struct _ACL_SIZE_INFORMATION {
    DWORD AceCount;
    DWORD AclBytesInUse;
    DWORD AclBytesFree;
} ACL_SIZE_INFORMATION;
typedef ACL_SIZE_INFORMATION *PACL_SIZE_INFORMATION;


#define SECURITY_DESCRIPTOR_REVISION     (1)
#define SECURITY_DESCRIPTOR_REVISION1    (1)

#define SECURITY_DESCRIPTOR_MIN_LENGTH   (sizeof(SECURITY_DESCRIPTOR))


typedef WORD   SECURITY_DESCRIPTOR_CONTROL, *PSECURITY_DESCRIPTOR_CONTROL;

#define SE_OWNER_DEFAULTED               (0x0001)
#define SE_GROUP_DEFAULTED               (0x0002)
#define SE_DACL_PRESENT                  (0x0004)
#define SE_DACL_DEFAULTED                (0x0008)
#define SE_SACL_PRESENT                  (0x0010)
#define SE_SACL_DEFAULTED                (0x0020)
#define SE_DACL_AUTO_INHERIT_REQ         (0x0100)
#define SE_SACL_AUTO_INHERIT_REQ         (0x0200)
#define SE_DACL_AUTO_INHERITED           (0x0400)
#define SE_SACL_AUTO_INHERITED           (0x0800)
#define SE_DACL_PROTECTED                (0x1000)
#define SE_SACL_PROTECTED                (0x2000)
#define SE_RM_CONTROL_VALID              (0x4000)
#define SE_SELF_RELATIVE                 (0x8000)


typedef struct _SECURITY_DESCRIPTOR_RELATIVE {
    BYTE  Revision;
    BYTE  Sbz1;
    SECURITY_DESCRIPTOR_CONTROL Control;
    DWORD Owner;
    DWORD Group;
    DWORD Sacl;
    DWORD Dacl;
    } SECURITY_DESCRIPTOR_RELATIVE, *PISECURITY_DESCRIPTOR_RELATIVE;

typedef struct _SECURITY_DESCRIPTOR {
   BYTE  Revision;
   BYTE  Sbz1;
   SECURITY_DESCRIPTOR_CONTROL Control;
   PSID Owner;
   PSID Group;
   PACL Sacl;
   PACL Dacl;

   } SECURITY_DESCRIPTOR, *PISECURITY_DESCRIPTOR;


typedef struct _SECURITY_OBJECT_AI_PARAMS {
    DWORD Size;             
    DWORD ConstraintMask;
} SECURITY_OBJECT_AI_PARAMS, *PSECURITY_OBJECT_AI_PARAMS;


typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        DWORD LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER;

typedef LARGE_INTEGER *PLARGE_INTEGER;

typedef union _ULARGE_INTEGER {
    struct {
        DWORD LowPart;
        DWORD HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        DWORD LowPart;
        DWORD HighPart;
    } u;
    ULONGLONG QuadPart;
} ULARGE_INTEGER;

typedef ULARGE_INTEGER *PULARGE_INTEGER;

