package log

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"strconv"

	"github.com/metacubex/mihomo/common/observable"

	log "github.com/sirupsen/logrus"
)

var (
	logCh  = make(chan Event)
	source = observable.NewObservable[Event](logCh)
	level  = INFO
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:             true,
		TimestampFormat:           "2006-01-02T15:04:05.000000000Z07:00",
		EnvironmentOverrideColors: true,
	})
}

type Event struct {
	LogLevel LogLevel
	Payload  string
}

func (e *Event) Type() string {
	return e.LogLevel.String()
}

func Infoln(format string, v ...any) {
	if INFO < level { // Meta-Improve
		return
	}
	_, file, line, _ := runtime.Caller(1)                              // Meta-Improve
	location := " " + path.Base(file) + ":" + strconv.Itoa(line) + " " // Meta-Improve
	event := newLog(INFO, location+fmt.Sprintf(format, v...))          // Meta-Improve
	logCh <- event
	print(event)
}

func Warnln(format string, v ...any) {
	if WARNING < level { // Meta-Improve
		return
	}
	_, file, line, _ := runtime.Caller(1)                              // Meta-Improve
	location := " " + path.Base(file) + ":" + strconv.Itoa(line) + " " // Meta-Improve
	event := newLog(WARNING, location+fmt.Sprintf(format, v...))       // Meta-Improve
	logCh <- event
	print(event)
}

func Errorln(format string, v ...any) {
	if ERROR < level { // Meta-Improve
		return
	}
	_, file, line, _ := runtime.Caller(1)                              // Meta-Improve
	location := " " + path.Base(file) + ":" + strconv.Itoa(line) + " " // Meta-Improve
	event := newLog(ERROR, location+fmt.Sprintf(format, v...))         // Meta-Improve
	logCh <- event
	print(event)
}

func Debugln(format string, v ...any) {
	if DEBUG < level { // Meta-Improve
		return
	}
	_, file, line, _ := runtime.Caller(1)                              // Meta-Improve
	location := " " + path.Base(file) + ":" + strconv.Itoa(line) + " " // Meta-Improve
	event := newLog(DEBUG, location+fmt.Sprintf(format, v...))         // Meta-Improve
	logCh <- event
	print(event)
}

func Fatalln(format string, v ...any) {
	_, file, line, _ := runtime.Caller(1)                              // Meta-Improve
	location := " " + path.Base(file) + ":" + strconv.Itoa(line) + " " // Meta-Improve
	log.Fatalf(location + fmt.Sprintf(format, v...))                   // Meta-Improve
}

func Subscribe() observable.Subscription[Event] {
	sub, _ := source.Subscribe()
	return sub
}

func UnSubscribe(sub observable.Subscription[Event]) {
	source.UnSubscribe(sub)
}

func Level() LogLevel {
	return level
}

func SetLevel(newLevel LogLevel) {
	level = newLevel
}

func print(data Event) {
	if data.LogLevel < level {
		return
	}

	switch data.LogLevel {
	case INFO:
		log.Infoln(data.Payload)
	case WARNING:
		log.Warnln(data.Payload)
	case ERROR:
		log.Errorln(data.Payload)
	case DEBUG:
		log.Debugln(data.Payload)
	}
}

func newLog(logLevel LogLevel, format string, v ...any) Event {
	return Event{
		LogLevel: logLevel,
		Payload:  fmt.Sprintf(format, v...),
	}
}
