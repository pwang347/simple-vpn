package ui

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"fyne.io/fyne"
	"fyne.io/fyne/layout"
	"fyne.io/fyne/theme"
	"fyne.io/fyne/widget"
)

const (
	iconSize = 50

	// WrapNumWords is number of words in sentence
	WrapNumWords = 10

	// WrapWordLength is number of characters in a line
	WrapWordLength = 40

	// BinaryMaxLength is max characters to show for a binary string before truncation
	BinaryMaxLength = 40
)

var (
	content     *widget.Box
	statusLabel *widget.Label
)

// FormatBinary returns formatted text for a byte array
func FormatBinary(b []byte) (result string) {
	result = fmt.Sprintf("% x", b)
	if len(result) > BinaryMaxLength {
		result = result[:BinaryMaxLength] + "..."
	}
	return
}

// WordWrap wraps a single string by a length
func WordWrap(s string, limit int) string {
	r := regexp.MustCompile("(.{" + strconv.Itoa(limit) + "})")
	return r.ReplaceAllString(s, "$1\n")
}

// SentenceWrap wraps a sentence by the row length and number of words
func SentenceWrap(s string, limit int, wordLimit int) string {

	if strings.TrimSpace(s) == "" {
		return s
	}

	words := strings.Fields(s)
	if len(words) <= limit {
		return WordWrap(s, wordLimit)
	}

	currentLen := 0
	wordWrapCounter := 0
	var strBuilder strings.Builder
	var rowStrBuilder strings.Builder
	for _, word := range words {
		currentLen += len(word)
		if rowStrBuilder.Len() > 0 {
			rowStrBuilder.WriteString(" ")
		}
		rowStrBuilder.WriteString(word)
		if wordWrapCounter != 0 && wordWrapCounter%limit == 0 || currentLen > wordLimit {
			strBuilder.WriteString(rowStrBuilder.String())
			strBuilder.WriteString("\n")
			rowStrBuilder.Reset()
			currentLen = 0
		}
		wordWrapCounter++
	}
	strBuilder.WriteString(rowStrBuilder.String())
	return strBuilder.String()
}

// StringWrap returns a wrapped string
func StringWrap(s string, sentenceLimit int, wordLimit int) string {
	var strBuilder strings.Builder
	sentences := strings.Split(s, "\n")
	if len(sentences) == 1 {
		return SentenceWrap(s, sentenceLimit, wordLimit)
	}
	for i, sentence := range sentences {
		if i != 0 {
			strBuilder.WriteString("\n")
		}
		strBuilder.WriteString(SentenceWrap(sentence, sentenceLimit, wordLimit))
	}
	return strBuilder.String()
}

// Log appends a new info log item to the log content
func Log(text string) {
	wrappedText := StringWrap(text, WrapNumWords, WrapWordLength)
	content.Prepend(widget.NewHBox(fyne.NewContainerWithLayout(layout.NewFixedGridLayout(fyne.NewSize(iconSize, iconSize)),
		widget.NewIcon(theme.InfoIcon())), NewMultiLineEntry(wrappedText, "", true)))
}

// LogE appends a new error log item to the log content
func LogE(err error) {
	wrappedText := StringWrap("EXCEPTION:\n"+err.Error(), WrapNumWords, WrapWordLength)
	content.Prepend(widget.NewHBox(fyne.NewContainerWithLayout(layout.NewFixedGridLayout(fyne.NewSize(iconSize, iconSize)),
		widget.NewIcon(theme.WarningIcon())), NewMultiLineEntry(wrappedText, "", true)))
}

// LogO appends a new info outbound item to the log content
func LogO(text string) {
	wrappedText := StringWrap(text, WrapNumWords, WrapWordLength)
	content.Prepend(widget.NewHBox(fyne.NewContainerWithLayout(layout.NewFixedGridLayout(fyne.NewSize(iconSize, iconSize)),
		widget.NewIcon(theme.NavigateNextIcon())), NewMultiLineEntry(wrappedText, "", true)))
}

// LogI appends a new info inbound log item to the log content
func LogI(text string) {
	wrappedText := StringWrap(text, WrapNumWords, WrapWordLength)
	content.Prepend(widget.NewHBox(fyne.NewContainerWithLayout(layout.NewFixedGridLayout(fyne.NewSize(iconSize, iconSize)),
		widget.NewIcon(theme.NavigateBackIcon())), NewMultiLineEntry(wrappedText, "", true)))
}

// LogS appends a new success log item to the log content
func LogS(text string) {
	wrappedText := StringWrap(text, WrapNumWords, WrapWordLength)
	content.Prepend(widget.NewHBox(fyne.NewContainerWithLayout(layout.NewFixedGridLayout(fyne.NewSize(iconSize, iconSize)),
		widget.NewIcon(theme.ConfirmIcon())), NewMultiLineEntry(wrappedText, "", true)))
}

// NewScrollingLogContainer creates a new scrolling log container
func NewScrollingLogContainer() (scroll *widget.ScrollContainer) {
	content = widget.NewVBox()
	scroll = widget.NewScrollContainer(
		content,
	)
	return
}

// DisplayErrorStatus displays the error on the status label
func DisplayErrorStatus(err error) {
	if statusLabel == nil {
		return
	}
	statusLabel.SetText(err.Error())
}

// DisplayMessageStatus displays the error on the status label
func DisplayMessageStatus(str string) {
	if statusLabel == nil {
		return
	}
	statusLabel.SetText(str)
}

// NewStatusLabel creates a new status label
func NewStatusLabel() (label *widget.Label) {
	label = widget.NewLabel("")
	statusLabel = label
	return
}
