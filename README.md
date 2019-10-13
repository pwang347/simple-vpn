## Getting Started

Clone repo to $GOPATH with `go get github.com/pwang347/simple-vpn`

Install dependencies with `go get fyne.io/fyne`

Run with `go run app.go`

Build executable with `go build`

## For embedded application icon
Install fyne CLI
1. `go get fyne.io/fyne/cmd/fyne`
2. `cd $GOPATH/src/fyne.io/fyne/cmd/fyne && go build`
3. Add `$GOPATH/bin` to $PATH 

Then run the package tool and build the application `os=(windows, darwin, linux)`
```
go build
fyne package -os windows -icon icon/ubc.png
go build
```
