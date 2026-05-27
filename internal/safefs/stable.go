package safefs

import "os"

// FileInfoStatter is implemented by opened files that can report current file
// metadata for time-of-check/time-of-use validation.
type FileInfoStatter interface {
	Stat() (os.FileInfo, error)
}

// Sentinel checks that an opened or re-statted file still matches a previous
// file identity observed before opening.
type Sentinel struct {
	Previous     os.FileInfo
	Path         string
	StatError    func(path string) error
	ChangedError func(path string) error
}

func (s Sentinel) CheckOpened(opened FileInfoStatter) error {
	current, err := opened.Stat()
	if err != nil {
		if s.StatError != nil {
			return s.StatError(s.Path)
		}
		return err
	}
	return s.CheckCurrent(current)
}

func (s Sentinel) CheckCurrent(current os.FileInfo) error {
	if os.SameFile(s.Previous, current) {
		return nil
	}
	if s.ChangedError != nil {
		return s.ChangedError(s.Path)
	}
	return nil
}
