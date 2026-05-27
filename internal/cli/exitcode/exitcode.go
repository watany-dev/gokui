package exitcode

// Code is a process exit code used by gokui commands.
type Code int

const (
	OK       Code = 0
	Error    Code = 1
	Rejected Code = 2
)

func (c Code) Int() int {
	return int(c)
}
