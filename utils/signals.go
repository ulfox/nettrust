package utils

import (
	"os"
	"os/signal"
	"syscall"
)

// OSSignalHandler for storing a signal
type OSSignalHandler struct {
	Signal chan os.Signal
}

// NewOSSignal for creating a new signal
func NewOSSignal() OSSignalHandler {
	osSig := OSSignalHandler{}

	osSig.Signal = make(chan os.Signal, 2)
	signal.Notify(
		osSig.Signal,
		syscall.SIGINT,
		syscall.SIGTERM,
		os.Interrupt,
	)

	return osSig
}

// Wait for waiting for an OS signal
func (s *OSSignalHandler) Wait() {
	<-s.Signal
}

// Close channel
func (s *OSSignalHandler) Close() {
	close(s.Signal)
}
