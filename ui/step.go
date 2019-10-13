package ui

import (
	"time"

	"fyne.io/fyne/widget"
)

var (
	doResume    = false
	continueBtn *widget.Button
	stepEnabled = true
	isPaused    = false
)

func pause() {
	isPaused = true
	for {
		if doResume {
			doResume = false
			isPaused = false
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// NewStepperButton returns a new stepper button
func NewStepperButton(text string) *widget.Button {
	continueBtn = widget.NewButton(text, func() {
		doResume = true
	})
	continueBtn.Disable()
	return continueBtn
}

// Step pauses before executing the inner procedure
func Step(proc func()) {
	if !stepEnabled {
		proc()
		return
	}
	continueBtn.Enable()
	pause()
	continueBtn.Disable()
	proc()
}

// SetStepMode sets the current stepping mode
func SetStepMode(isStep bool) {
	stepEnabled = isStep
	if !stepEnabled && isPaused {
		doResume = true
	}
	continueBtn.Disable()
}
