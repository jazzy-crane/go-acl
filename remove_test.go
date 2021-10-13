//+build windows

package acl

import (
	"golang.org/x/sys/windows"

	"io/ioutil"
	"os"
	"testing"
)

func TestRemove(t *testing.T) {
	tokUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := tokUser.User.Sid

	f, err := ioutil.TempFile(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	if err := Apply(
		f.Name(),
		false,
		true,
		DenySid(windows.GENERIC_ALL, sid),
	); err != nil {
		t.Fatal(err)
	}

	r, err := os.Open(f.Name())
	if err == nil {
		r.Close()
		t.Fatal("current user able to access file after deny")
	}

	if err := RemoveACL(f.Name(), sid); err != nil {
		t.Fatal(err)
	}

	r, err = os.Open(f.Name())
	if err != nil {
		r.Close()
		t.Fatal("current user not able to access file after deny removed")
	}
}
