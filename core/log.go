package core

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/fatih/color"
)

const (
	FATAL     = 5
	ERROR     = 4
	WARN      = 3
	IMPORTANT = 2
	INFO      = 1
	DEBUG     = 0
)

var LogColors = map[int]*color.Color{
	FATAL:     color.New(color.FgRed).Add(color.Bold),
	ERROR:     color.New(color.FgRed),
	WARN:      color.New(color.FgYellow),
	IMPORTANT: color.New(color.Bold),
}

var (
	debugColor   = color.New(color.FgYellow).SprintFunc()
	successColor = color.New(color.FgGreen).SprintFunc()
)

type Logger struct {
	sync.Mutex

	DebugLog *os.File
	silent   bool
	debug    bool
}

func (l *Logger) SetSilent(s bool) {
	l.silent = s
}

func (l *Logger) SetDebug(d bool) {
	l.debug = d
}

func (l *Logger) SetDebugLog(path string) {
	var err error

	l.DebugLog, err = os.Create(path)
	if err != nil {
		l.DebugLog = nil
	}
}

func (l *Logger) CloseDebugLog() {
	if l.DebugLog != nil {
		l.DebugLog.Close()
	}
}

func (l *Logger) Log(level int, format string, args ...interface{}) {
	l.Lock()
	defer l.Unlock()

	if level == DEBUG {
		if l.DebugLog != nil {
			msg := fmt.Sprintf(format, args...)
			l.DebugLog.WriteString(msg)
		}
		return
	}
	if level < ERROR && l.silent {
		return
	}

	if c, ok := LogColors[level]; ok {
		c.Printf(format, args...)
	} else {
		fmt.Printf(format, args...)
	}

	if level == FATAL {
		os.Exit(1)
	}
}

func (l *Logger) Fatal(format string, args ...interface{}) {
	l.Log(FATAL, format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.Log(ERROR, format, args...)
}

func (l *Logger) Warn(format string, args ...interface{}) {
	l.Log(WARN, format, args...)
}

func (l *Logger) Important(format string, args ...interface{}) {
	l.Log(IMPORTANT, format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	if l.silent {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if strings.Contains(msg, "screenshot successful") && l.isTerminal() {
		msg = successColor(msg)
	}
	fmt.Fprint(l.getInfoWriter(), msg)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.silent || !l.debug {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if l.DebugLog != nil {
		l.DebugLog.WriteString(msg)
	}
	if l.isTerminal() {
		msg = debugColor(msg)
	}
	fmt.Fprint(os.Stdout, msg)
}

func (l *Logger) isTerminal() bool {
	return true // Placeholder implementation. You might want to implement this method based on your actual requirements.
}

func (l *Logger) getDebugWriter() *os.File {
	return l.DebugLog
}

func (l *Logger) getInfoWriter() *os.File {
	return os.Stdout
}
