//+build windows

package acl

import (
	"unsafe"

	"github.com/jazzy-crane/go-acl/api"
	"golang.org/x/sys/windows"
)

// RemoveACL removes any access control entries pertaining to the given sid, from a file
func RemoveACL(name string, sid *windows.SID) error {
	var oldAcl windows.Handle
	var secDesc windows.Handle

	if err := api.GetNamedSecurityInfo(
		name,
		api.SE_FILE_OBJECT,
		api.DACL_SECURITY_INFORMATION,
		nil,
		nil,
		&oldAcl,
		nil,
		&secDesc,
	); err != nil {
		return err
	}
	defer windows.LocalFree(secDesc)

	oldEAs, err := api.GetExplicitEntriesFromAcl(oldAcl)
	if err != nil {
		return err
	}

	newEAs := make([]api.ExplicitAccess, 0, len(oldEAs))
	for _, ea := range oldEAs {
		if ea.Trustee.TrusteeForm == api.TRUSTEE_IS_SID {
			trusteeSid := (*windows.SID)(unsafe.Pointer(ea.Trustee.Name))
			if windows.EqualSid(trusteeSid, sid) {
				continue
			}
		}
		newEAs = append(newEAs, ea)
	}

	var acl windows.Handle
	if err := api.SetEntriesInAcl(
		newEAs,
		0,
		&acl,
	); err != nil {
		return err
	}
	defer windows.LocalFree(acl)

	return api.SetNamedSecurityInfo(
		name,
		api.SE_FILE_OBJECT,
		api.DACL_SECURITY_INFORMATION|api.UNPROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		0,
	)
}

// RemoveACLHandle removes any access control entries pertaining to the given sid, from a handle and objectType pair
func RemoveACLHandle(handle windows.Handle, objectType int32, sid *windows.SID) error {
	var oldAcl windows.Handle
	var secDesc windows.Handle

	if err := api.GetSecurityInfo(
		handle,
		objectType,
		api.DACL_SECURITY_INFORMATION,
		nil,
		nil,
		&oldAcl,
		nil,
		&secDesc,
	); err != nil {
		return err
	}
	defer windows.LocalFree(secDesc)

	oldEAs, err := api.GetExplicitEntriesFromAcl(oldAcl)
	if err != nil {
		return err
	}

	newEAs := make([]api.ExplicitAccess, 0, len(oldEAs))
	for _, ea := range oldEAs {
		if ea.Trustee.TrusteeForm == api.TRUSTEE_IS_SID {
			trusteeSid := (*windows.SID)(unsafe.Pointer(ea.Trustee.Name))
			if windows.EqualSid(trusteeSid, sid) {
				continue
			}
		}
		newEAs = append(newEAs, ea)
	}

	var acl windows.Handle
	if err := api.SetEntriesInAcl(
		newEAs,
		0,
		&acl,
	); err != nil {
		return err
	}
	defer windows.LocalFree(acl)

	return api.SetSecurityInfo(
		handle,
		objectType,
		api.DACL_SECURITY_INFORMATION|api.UNPROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		0,
	)
}
