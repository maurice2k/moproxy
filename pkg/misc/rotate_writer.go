// Copyright 2019-2021 Moritz Fain
// Moritz Fain <moritz@fain.io>

package misc

import (
	"os"
	"sync"
	"sync/atomic"
)

type rotateWriter struct {
	file       atomic.Value
	filename   string
	flags      int
	permission os.FileMode
	lock       sync.Mutex
}

func NewRotateWriter(filename string, flags int, permission os.FileMode) (rw *rotateWriter, err error) {
	rw = &rotateWriter{
		filename:   filename,
		flags:      flags,
		permission: permission,
	}
	err = rw.Rotate()  // open/create file
	if err != nil {
		return nil, err
	}
	return
}

func (rw *rotateWriter) Write(b []byte) (n int, err error) {
	return rw.file.Load().(*os.File).Write(b)
}

func (rw *rotateWriter) Rotate() error {
	rw.lock.Lock()
	defer rw.lock.Unlock()

	oldFh := rw.file.Load()

	newFh, err := os.OpenFile(rw.filename, rw.flags, rw.permission)
	if err != nil {
		return err
	}
	rw.file.Store(newFh)

	if oldFh != nil {
		oldFh.(*os.File).Close()
	}
	return nil
}

func (rw *rotateWriter) Close() error {
	rw.lock.Lock()
	defer rw.lock.Unlock()

	oldFh := rw.file.Load()
	if oldFh != nil {
		return oldFh.(*os.File).Close()
	}
	rw.file.Store(nil)
	return nil
}
