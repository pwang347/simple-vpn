package ui

import (
	"fyne.io/fyne"
	"fyne.io/fyne/widget"
)

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

// NewCheck creates a new check
func NewCheck(text string, handler func(bool), isChecked bool) (check *widget.Check) {
	check = widget.NewCheck(text, func(bool) {})
	check.SetChecked(isChecked)
	check.OnChanged = handler
	return
}

// NewIcon creates a new icon
func NewIcon(res fyne.Resource, size fyne.Size) (icon *widget.Icon) {
	icon = widget.NewIcon(res)
	icon.Resize(size)
	return
}
