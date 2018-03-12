package engine

import (
	"fmt"
	"log/syslog"

	"github.com/golang/glog"
)

// logLevel is the severity of the log message.
type logLevel int

const (
	logLevelInfo logLevel = iota
	logLevelError
)

var syslogger *syslog.Writer

func init() {
	var err error
	syslogger, err = syslog.New(syslog.LOG_AUTH|syslog.LOG_WARNING, "opa-pam")
	if err != nil {
		log(logLevelError, "syslog writer could not be initiated: %v", err)
	}
}

// log writes all logs to syslog, and log levels logLevelError and up to
// both syslog and the standard logger.
func log(lvl logLevel, format string, args ...interface{}) {
	if syslogger != nil {
		msg := fmt.Sprintf(format, args...)
		switch lvl {
		case logLevelInfo:
			syslogger.Info(msg)
		case logLevelError:
			syslogger.Err(msg)
		}
	}

	if lvl > logLevelInfo {
		glog.Errorf(format, args...)
	}
}
