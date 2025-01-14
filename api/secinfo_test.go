//+build windows

package api

import (
	"golang.org/x/sys/windows"

	"io/ioutil"
	"os"
	"testing"
)

func TestGetNamedSecurityInfo(t *testing.T) {
	f, err := ioutil.TempFile(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()
	var (
		secDesc windows.Handle
	)
	if err = GetNamedSecurityInfo(
		f.Name(),
		SE_FILE_OBJECT,
		0,
		nil,
		nil,
		nil,
		nil,
		&secDesc,
	); err != nil {
		t.Fatal(err)
	}
	defer windows.LocalFree(secDesc)
}

func TestSetNamedSecurityInfo(t *testing.T) {
	f, err := ioutil.TempFile(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()
	if err = SetNamedSecurityInfo(
		f.Name(),
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION,
		nil,
		nil,
		0,
		0,
	); err != nil {
		t.Fatal(err)
	}
}

func TestGetSecurityInfo(t *testing.T) {
	f, err := ioutil.TempFile(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()
	var secDesc windows.Handle

	if err = GetSecurityInfo(
		windows.Handle(f.Fd()),
		SE_FILE_OBJECT,
		0,
		nil,
		nil,
		nil,
		nil,
		&secDesc,
	); err != nil {
		t.Fatal(err)
	}
	defer windows.LocalFree(secDesc)
}

func TestSetSecurityInfo(t *testing.T) {
	f, err := ioutil.TempFile(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	fName16, err := windows.UTF16PtrFromString(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	fHandle, err := windows.CreateFile(fName16, windows.GENERIC_ALL, 0, nil, windows.OPEN_EXISTING, 0, windows.InvalidHandle)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(fHandle)

	if err = SetSecurityInfo(
		fHandle,
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION,
		nil,
		nil,
		0,
		0,
	); err != nil {
		t.Fatal(err)
	}
}
