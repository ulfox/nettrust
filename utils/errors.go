package utils

import (
	"fmt"
	"runtime"
	"strconv"

	"github.com/pkg/errors"
)

var (
	ErrSameAddr               string = "listen address can not be the same as forward address"
	WarnOnExitFlush           string = "on exit flush table is enabled. Please set this to false if you wish to deny traffic to all if NetTrust is not running"
	WarnOnExitFlushAuthorized string = "on exit NetTrust will not flush the authorized hosts list"
)

// WrapErr for creating errors and wrapping them along
// with callers info
func WrapErr(e interface{}, p ...interface{}) error {
	if e == nil {
		return nil
	}

	var err error

	switch e := e.(type) {
	case string:
		err = fmt.Errorf(e, p...)
	case error:
		err = e
	}

	pc, _, no, ok := runtime.Caller(1)
	details := runtime.FuncForPC(pc)
	if ok && details != nil {
		return errors.Wrap(err, fmt.Sprintf("%s#%s\n", details.Name(), strconv.Itoa(no)))
	}

	return err
}
