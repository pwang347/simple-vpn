package ui

import (
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

	// MaxLogEntries is the max number of log entries
	MaxLogEntries = 30
)

var (
	content     *widget.Box
	statusLabel *widget.Label
	numLogItems = 0
)

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
	if len(words) == 1 {
		return WordWrap(s, wordLimit)
	}

	currentLen := 0
	var strBuilder strings.Builder
	var rowStrBuilder strings.Builder
	for _, word := range words {
		if rowStrBuilder.Len() > 0 {
			rowStrBuilder.WriteString(" ")
		}
		if len(word) > wordLimit {
			word = WordWrap(word, wordLimit)
			wordSegments := strings.Split(word, "\n")
			lastWord := wordSegments[len(wordSegments)-1]
			strBuilder.WriteString(rowStrBuilder.String())
			strBuilder.WriteString("\n")
			rowStrBuilder.Reset()
			strBuilder.WriteString(word)
			currentLen = len(lastWord)
		} else {
			currentLen += len(word)
			rowStrBuilder.WriteString(word)
		}
		if currentLen > wordLimit {
			strBuilder.WriteString(rowStrBuilder.String())
			strBuilder.WriteString("\n")
			rowStrBuilder.Reset()
			currentLen = 0
		}
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

func log(text string, icon *widget.Icon) {
	numLogItems++
	content.Prepend(widget.NewHBox(fyne.NewContainerWithLayout(
		layout.NewFixedGridLayout(fyne.NewSize(iconSize, iconSize)), icon),
		widget.NewVBox(NewBoldedLabel("Event #"+strconv.Itoa(numLogItems)), NewMultiLineEntry(text, "", true))))
	if len(content.Children) > MaxLogEntries {
		content.Children = content.Children[:len(content.Children)-1]
	}
}

// Log appends a new info log item to the log content
func Log(text string) {
	wrappedText := StringWrap(text, WrapNumWords, WrapWordLength)
	log(wrappedText, widget.NewIcon(theme.InfoIcon()))
}

// LogE appends a new error log item to the log content
func LogE(err error) {
	wrappedText := StringWrap("EXCEPTION:\n"+err.Error(), WrapNumWords, WrapWordLength)
	log(wrappedText, widget.NewIcon(theme.WarningIcon()))
}

// LogO appends a new info outbound item to the log content
func LogO(text string) {
	wrappedText := StringWrap(text, WrapNumWords, WrapWordLength)
	log(wrappedText, widget.NewIcon(theme.NavigateNextIcon()))
}

// LogI appends a new info inbound log item to the log content
func LogI(text string) {
	wrappedText := StringWrap(text, WrapNumWords, WrapWordLength)
	log(wrappedText, widget.NewIcon(theme.NavigateBackIcon()))
}

// LogS appends a new success log item to the log content
func LogS(text string) {
	wrappedText := StringWrap(text, WrapNumWords, WrapWordLength)
	log(wrappedText, widget.NewIcon(theme.ConfirmIcon()))
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
