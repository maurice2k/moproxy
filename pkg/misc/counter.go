package misc

import (
	"io"
	"sync/atomic"
)

// CountReader counts bytes read from io.Reader
type CountReader struct {
	io.Reader
	count uint64
}

func NewCountReader(r io.Reader) *CountReader {
	return &CountReader{
		Reader: r,
	}
}

func (cr *CountReader) Read(buf []byte) (int, error) {
	n, err := cr.Reader.Read(buf)
	atomic.AddUint64(&cr.count, uint64(n))
	return n, err
}

func (cr *CountReader) GetCount() uint64 {
	return atomic.LoadUint64(&cr.count)
}

func (cr *CountReader) GetCountAndReset() uint64 {
	return atomic.SwapUint64(&cr.count, 0)
}

// CountWriter counts bytes written to io.Writer
type CountWriter struct {
	io.Writer
	count uint64
}

func NewCountWriter(w io.Writer) *CountWriter {
	return &CountWriter{
		Writer: w,
	}
}

func (cw *CountWriter) Write(buf []byte) (int, error) {
	n, err := cw.Writer.Write(buf)
	atomic.AddUint64(&cw.count, uint64(n))
	return n, err
}

func (cw *CountWriter) GetCount() uint64 {
	return atomic.LoadUint64(&cw.count)
}

func (cw *CountWriter) GetCountAndReset() uint64 {
	return atomic.SwapUint64(&cw.count, 0)
}
