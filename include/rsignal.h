#ifndef __RSIGNAL_H
#define __RESIGNAL_H

enum RSIGENUM {
	RSIG_BASE                           = 0x4000,
	RSIG_RESERVED1                      = 0x4003,
	RSIG_GETEINFO                       = 0x4004,
	RSIG_VIRINFO                        = 0x4005,
	RSIG_UNLOADENGINE                   = 0x400A,
	RSIG_RESERVED2                      = 0x400B,
	RSIG_SCANFILE_TS_W                  = 0x4014,
	RSIG_SCANPATH_TS_W                  = 0x4015,
	RSIG_RESERVED3                      = 0x4019,
	RSIG_CONFIGURE_NEW_W                = 0x401A,
	RSIG_RESERVED4                      = 0x401C,
	RSIG_FIW32_CONFIG                   = 0x401D,
	RSIG_SPLIT_VIRNAME                  = 0x401E,
	RSIG_HOOK_API                       = 0x401F,
	RSIG_INIT_ENGINE_CONTEXT            = 0x4020,
	RSIG_CLEANUP_ENGINE_CONTEXT         = 0x4021,
	RSIG_SCANFILE_TS_WCONTEXT           = 0x4023,
	RSIG_SCANPATH_TS_WCONTEXT           = 0x4024,
	RSIG_VIRINFO_FILTERED               = 0x4025,
	RSIG_SCAN_OPEN                      = 0x4026,
	RSIG_SCAN_GETEVENT                  = 0x4027,
	RSIG_SCAN_CLOSE                     = 0x4028,
	RSIG_GET_THREAT_INFO                = 0x4030,
	RSIG_SCANSTREAMW                    = 0x4031,
	RSIG_SCANSTREAMW_WCONTEXT           = 0x4032,
	RSIG_CHECK_PRIVILEGES               = 0x4033,
	RSIG_ADJUST_PRIVILEGES              = 0x4034,
	RSIG_SET_FILECHANGEQUERY            = 0x4035,
	RSIG_BOOTENGINE                     = 0x4036,
	RSIG_RTP_GETINITDATA                = 0x4037,
	RSIG_RTP_SETEVENTCALLBACK           = 0x4038,
	RSIG_RTP_NOTIFYCHANGE               = 0x4039,
	RSIG_RTP_GETBEHAVIORCONTEXT         = 0x403A,
	RSIG_RTP_SETBEHAVIORCONTEXT         = 0x403B,
	RSIG_RTP_FREEBEHAVIORCONTEXT        = 0x403C,
	RSIG_SCAN_STREAMBUFFER              = 0x403D,
	RSIG_RTP_STARTBEHAVIORMONITOR       = 0x403E,
	RSIG_RTP_STOPBEHAVIORMONITOR        = 0x403F,
	RSIG_GET_SIG_DATA                   = 0x4041,
	RSIG_VALIDATE_FEATURE               = 0x4042,
	RSIG_SET_CALLBACK                   = 0x4043,
	RSIG_OBFUSCATE_DATA                 = 0x4044,
	RSIG_DROP_BMDATA                    = 0x4045,
	RSIG_SCANEXTRACT                    = 0x4046,
	RSIG_CHANGE_SETTINGS                = 0x4047,
	RSIG_RTSIG_DATA                     = 0x4048,
	RSIG_SYSTEM_REBOOT                  = 0x4049,
	RSIG_REVOKE_QUERY                   = 0x4050,
	RSIG_CHECK_EXCLUSIONS               = 0x4051,
	RSIG_COMPLETE_INITIALIZATION        = 0x4052,
	RSIG_STATE_CHANGE                   = 0x4053,
	RSIG_SEND_CALLISTO_TELEMETRY        = 0x4054,
	RSIG_DYNAMIC_CONFIG                 = 0x4055,
	RSIG_SEND_EARLY_BOOT_DATA           = 0x4056,
	RSIG_SCAN_TCG_LOG                   = 0x4057,
	RSIG_CANCEL_ENGINE_LOAD             = 0x4058,
	RSIG_SQM_CONFIG                     = 0x4059,
	RSIG_SERVICE_NOTIFICATION           = 0x405A,
	RSIG_SCAN_TCG_LOG_EX                = 0x405B,
	RSIG_FREE_TCG_EXTENDED_DATA         = 0x405C,
	RSIG_NOTIFY_MAINTENANCE_WINDOW_STATE= 0x405D,
	RSIG_SEND_REMOTE_ATTESTATION_DATA   = 0x405E,
	RSIG_SUSPICIOUS_SCAN                = 0x405F,
	RSIG_ON_CLOUD_COMPLETION            = 0x4060,
	RSIG_CONTROL_SPLI                   = 0x4061,
	RSIG_THREAT_UPDATE_STATUS           = 0x4062,
	RSIG_VERIFY_MACHINE_GUID            = 0x4063,
	RSIG_NRI_UPDATE_STATE               = 0x4064,
	RSIG_TPM_CONFIG                     = 0x4065,
	RSIG_GET_RESOURCE_INFO              = 0x4066,
	RSIG_GET_ASYNC_QUEUE_LENGTH         = 0x4067,
	RSIG_RTP_IMAGENAME_CONFIG           = 0x4068,
	RSIG_SET_CUSTOM_SET_ID              = 0x4069,
	RSIG_CONFIGURE_ROLES                = 0x4070,
	RSIG_HOOK_WOW                       = 0x4071,
	RSIG_AMSI_SESSION_END               = 0x4072,
	RSIG_RESOURCE_CONTEXT_CONSOLIDATION = 0x4073,
};

#endif
