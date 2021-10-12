//+build windows

package api

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379593.aspx
const (
	SE_UNKNOWN_OBJECT_TYPE = iota
	SE_FILE_OBJECT
	SE_SERVICE
	SE_PRINTER
	SE_REGISTRY_KEY
	SE_LMSHARE
	SE_KERNEL_OBJECT
	SE_WINDOW_OBJECT
	SE_DS_OBJECT
	SE_DS_OBJECT_ALL
	SE_PROVIDER_DEFINED_OBJECT
	SE_WMIGUID_OBJECT
	SE_REGISTRY_WOW64_32KEY
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379573.aspx
const (
	OWNER_SECURITY_INFORMATION               = 0x00001
	GROUP_SECURITY_INFORMATION               = 0x00002
	DACL_SECURITY_INFORMATION                = 0x00004
	SACL_SECURITY_INFORMATION                = 0x00008
	LABEL_SECURITY_INFORMATION               = 0x00010
	ATTRIBUTE_SECURITY_INFORMATION           = 0x00020
	SCOPE_SECURITY_INFORMATION               = 0x00040
	PROCESS_TRUST_LABEL_SECURITY_INFORMATION = 0x00080
	BACKUP_SECURITY_INFORMATION              = 0x10000

	PROTECTED_DACL_SECURITY_INFORMATION   = 0x80000000
	PROTECTED_SACL_SECURITY_INFORMATION   = 0x40000000
	UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
	UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
)

//go:generate mkwinsyscall -output secinfogen_windows.go secinfo.go

//sys GetNamedSecurityInfo(objectName string, objectType int32, secInfo uint32, owner **windows.SID, group **windows.SID, dacl *windows.Handle, sacl *windows.Handle, secDesc *windows.Handle) (rtn error) = advapi32.GetNamedSecurityInfoW
//sys SetNamedSecurityInfo(objectName string, objectType int32, secInfo uint32, owner *windows.SID, group *windows.SID, dacl windows.Handle, sacl windows.Handle) (rtn error) = advapi32.SetNamedSecurityInfoW
//sys GetSecurityInfo(handle windows.Handle, objectType int32, secInfo uint32, owner **windows.SID, group **windows.SID, dacl *windows.Handle, sacl *windows.Handle, secDesc *windows.Handle) (rtn error) = advapi32.GetSecurityInfo
//sys SetSecurityInfo(handle windows.Handle, objectType int32, secInfo uint32, owner *windows.SID, group *windows.SID, dacl windows.Handle, sacl windows.Handle) (rtn error) = advapi32.SetSecurityInfo
