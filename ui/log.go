package ui

import (
	"regexp"
	"strconv"
	"strings"
	"sync"

	"fyne.io/fyne/widget"
)

const (
	iconSize = 50

	// MaxWordLength is max number of characters in a word before truncation
	MaxWordLength = 256

	// WrapWordLength is number of characters in a line
	WrapWordLength = 40

	// MaxLogEntries is the max number of log entries
	MaxLogEntries = 30
)

var (
	content     *widget.Box
	numLogItems = 0
	mutex       sync.Mutex
)

func truncateString(str string, num int) string {
	bnoden := str
	if len(str) > num {
		if num > 3 {
			num -= 3
		}
		bnoden = str[0:num] + "..."
	}
	return bnoden
}

// WordWrap wraps a single string by a length
func WordWrap(s string, limit int) string {
	s = truncateString(s, MaxWordLength)
	r := regexp.MustCompile("(.{" + strconv.Itoa(limit) + "})")
	return r.ReplaceAllString(s, "$1\n")
}

// SentenceWrap wraps a sentence by the row length and number of words
func SentenceWrap(s string, wordLimit int) string {

	if strings.TrimSpace(s) == "" {
		return s
	}

	words := strings.Fields(s)
	if len(words) == 1 {
		return strings.TrimSpace(WordWrap(s, wordLimit))
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
	return strings.TrimSpace(strBuilder.String())
}

// StringWrap returns a wrapped string
func StringWrap(s string, wordLimit int) string {
	mutex.Lock()
	defer mutex.Unlock()
	var strBuilder strings.Builder
	sentences := strings.Split(s, "\n")
	if len(sentences) == 1 {
		return SentenceWrap(s, wordLimit)
	}
	for _, sentence := range sentences {
		if strings.TrimSpace(sentence) == "" {
			continue
		}
		if strBuilder.Len() != 0 {
			strBuilder.WriteString("\n")
		}
		strBuilder.WriteString(SentenceWrap(sentence, wordLimit))
	}
	return strBuilder.String()
}

func log(text string, ty string) {
	mutex.Lock()
	defer mutex.Unlock()
	numLogItems++
	content.Prepend(widget.NewLabel(text))
	content.Prepend(NewBoldedLabel("Event #" + strconv.Itoa(numLogItems) + " [" + ty + "]"))
	if len(content.Children) > MaxLogEntries*2 {
		content.Children = content.Children[:len(content.Children)-1]
	}
}

// Log appends a new info log item to the log content
func Log(text string) {
	wrappedText := StringWrap(text, WrapWordLength)
	log(wrappedText, "INFO")
}

// LogE appends a new error log item to the log content
func LogE(err error) {
	wrappedText := StringWrap(err.Error(), WrapWordLength)
	log(wrappedText, "EXCEPTION")
}

// LogO appends a new info outbound item to the log content
func LogO(text string) {
	wrappedText := StringWrap(text, WrapWordLength)
	log(wrappedText, "OUTBOUND")
}

// LogI appends a new info inbound log item to the log content
func LogI(text string) {
	wrappedText := StringWrap(text, WrapWordLength)
	log(wrappedText, "INBOUND")
}

// LogS appends a new success log item to the log content
func LogS(text string) {
	wrappedText := StringWrap(text, WrapWordLength)
	log(wrappedText, "SUCCESS")
}

// NewScrollingLogContainer creates a new scrolling log container
func NewScrollingLogContainer() (scroll *widget.ScrollContainer) {
	content = widget.NewVBox()
	scroll = widget.NewScrollContainer(
		content,
	)
	return
}
