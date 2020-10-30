# frozen_string_literal: true

module TurboRex
  class Windows < Metasm::WinOS
    module Constants
      # Impersonation Level
      SecurityAnonymous = 0
      SecurityIdentification = 1
      SecurityImpersonation = 2
      SecurityDelegation = 3

      # Security Descriptor Control
      SE_OWNER_DEFAULTED  =             0x0001
      SE_GROUP_DEFAULTED  =             0x0002
      SE_DACL_PRESENT     =             0x0004
      SE_DACL_DEFAULTED   =             0x0008
      SE_SACL_PRESENT     =             0x0010
      SE_SACL_DEFAULTED   =             0x0020
      SE_DACL_AUTO_INHERIT_REQ  =       0x0100
      SE_SACL_AUTO_INHERIT_REQ  =       0x0200
      SE_DACL_AUTO_INHERITED  =         0x0400
      SE_SACL_AUTO_INHERITED  =         0x0800
      SE_DACL_PROTECTED  =              0x1000
      SE_SACL_PROTECTED  =              0x2000
      SE_RM_CONTROL_VALID =             0x4000
      SE_SELF_RELATIVE = 0x8000

      ## ACE Type
      ACCESS_MIN_MS_ACE_TYPE  =                0x0
      ACCESS_ALLOWED_ACE_TYPE =                0x0
      ACCESS_DENIED_ACE_TYPE  =                0x1
      SYSTEM_AUDIT_ACE_TYPE   =                0x2
      SYSTEM_ALARM_ACE_TYPE   =                0x3
      ACCESS_MAX_MS_V2_ACE_TYPE =              0x3

      ACCESS_ALLOWED_COMPOUND_ACE_TYPE =       0x4
      ACCESS_MAX_MS_V3_ACE_TYPE =              0x4

      ACCESS_MIN_MS_OBJECT_ACE_TYPE  =         0x5
      ACCESS_ALLOWED_OBJECT_ACE_TYPE  =        0x5
      ACCESS_DENIED_OBJECT_ACE_TYPE  =         0x6
      SYSTEM_AUDIT_OBJECT_ACE_TYPE =           0x7
      SYSTEM_ALARM_OBJECT_ACE_TYPE =           0x8
      ACCESS_MAX_MS_OBJECT_ACE_TYPE  =         0x8

      ACCESS_MAX_MS_V4_ACE_TYPE  =             0x8
      ACCESS_MAX_MS_ACE_TYPE =                 0x8

      ACCESS_ALLOWED_CALLBACK_ACE_TYPE =       0x9
      ACCESS_DENIED_CALLBACK_ACE_TYPE  =       0xA
      ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0xB
      ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE =  0xC
      SYSTEM_AUDIT_CALLBACK_ACE_TYPE =         0xD
      SYSTEM_ALARM_CALLBACK_ACE_TYPE =         0xE
      SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE  = 0xF
      SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE  = 0x10

      SYSTEM_MANDATORY_LABEL_ACE_TYPE =        0x11
      SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE =     0x12
      SYSTEM_SCOPED_POLICY_ID_ACE_TYPE =       0x13
      SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE =    0x14
      SYSTEM_ACCESS_FILTER_ACE_TYPE =          0x15
      ACCESS_MAX_MS_V5_ACE_TYPE =              0x15

      # ACE Flag
      OBJECT_INHERIT_ACE  =              0x1
      CONTAINER_INHERIT_ACE =            0x2
      NO_PROPAGATE_INHERIT_ACE =         0x4
      INHERIT_ONLY_ACE =                 0x8
      INHERITED_ACE  =                   0x10
      VALID_INHERIT_FLAGS =              0x1F
      CRITICAL_ACE_FLAG =                0x20
      SUCCESSFUL_ACCESS_ACE_FLAG =       0x40
      FAILED_ACCESS_ACE_FLAG =           0x80
      TRUST_PROTECTED_FILTER_ACE_FLAG =  0x40


      # UnOfficial
      MAX_BUCKETS_NUM = 0x17
    end
  end
end
