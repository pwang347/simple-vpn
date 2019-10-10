package ui

import (
	"fyne.io/fyne"
	"fyne.io/fyne/widget"
)

var (
	statusLabel *widget.Label
)

// DisplayError displays the error on the status label
func DisplayError(err error) {
	statusLabel.SetText(err.Error())
}

// DisplayMessage displays the error on the status label
func DisplayMessage(str string) {
	statusLabel.SetText(str)
}

// SetStatusLabel sets the status label
func SetStatusLabel(label *widget.Label) {
	statusLabel = label
}

// NewBoldedLabel creates a new bolded label
func NewBoldedLabel(text string) *widget.Label {
	return widget.NewLabelWithStyle(text, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
}

// NewButton creates a new button
func NewButton(label string, handler func(), isDisabled bool) (btn *widget.Button) {
	btn = widget.NewButton(label, handler)
	if isDisabled {
		btn.Disable()
	}
	return
}

// NewEntry creates a new entry
func NewEntry(text string, placeholder string, isReadOnly bool) (entry *widget.Entry) {
	entry = widget.NewEntry()
	entry.SetText(text)
	entry.SetPlaceHolder(placeholder)
	entry.SetReadOnly(isReadOnly)
	return
}

// NewMultiLineEntry creates a new entry
func NewMultiLineEntry(text string, placeholder string, isReadOnly bool) (entry *widget.Entry) {
	entry = widget.NewMultiLineEntry()
	entry.SetText(text)
	entry.SetPlaceHolder(placeholder)
	entry.SetReadOnly(isReadOnly)
	return
}
