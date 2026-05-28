package app

import "os"

type installErrorStatter struct {
	err error
}

func (s installErrorStatter) Stat() (os.FileInfo, error) {
	return nil, s.err
}
