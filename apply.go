//+build windows

package acl

import (
	"github.com/jazzy-crane/go-acl/api"
	"golang.org/x/sys/windows"
)

// Apply the provided access control entries to a file. If the replace
// parameter is true, existing entries will be overwritten. If the inherit
// parameter is true, the file will inherit ACEs from its parent.
func Apply(name string, replace, inherit bool, entries ...api.ExplicitAccess) error {
	var oldAcl windows.Handle
	if !replace {
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
	}
	var acl windows.Handle
	if err := api.SetEntriesInAcl(
		entries,
		oldAcl,
		&acl,
	); err != nil {
		return err
	}
	defer windows.LocalFree(acl)
	var secInfo uint32
	if !inherit {
		secInfo = api.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		secInfo = api.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	return api.SetNamedSecurityInfo(
		name,
		api.SE_FILE_OBJECT,
		api.DACL_SECURITY_INFORMATION|secInfo,
		nil,
		nil,
		acl,
		0,
	)
}

// ApplyHandle the provided access control entries to a handle and objectType pair.
// If the replace parameter is true, existing entries will be overwritten.
// If the inherit parameter is true, the object will inherit ACEs from its parent.
func ApplyHandle(handle windows.Handle, objectType int32, replace, inherit bool, entries ...api.ExplicitAccess) error {
	var oldAcl windows.Handle
	if !replace {
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
	}
	var acl windows.Handle
	if err := api.SetEntriesInAcl(
		entries,
		oldAcl,
		&acl,
	); err != nil {
		return err
	}
	defer windows.LocalFree(acl)
	var secInfo uint32
	if !inherit {
		secInfo = api.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		secInfo = api.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	return api.SetSecurityInfo(
		handle,
		objectType,
		api.DACL_SECURITY_INFORMATION|secInfo,
		nil,
		nil,
		acl,
		0,
	)
}
