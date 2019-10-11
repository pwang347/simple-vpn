## Getting Started

Clone repo to $GOPATH with `go get github.com/Gordon-Yeh/simple-vpn`

Install dependencies with `go get fyne.io/fyne`

Run with `go run app.go`

Build executable with `go build app.go`
(You don't have to build everytime)

## For icons
Install fyne CLI
1. `go get fyne.io/fyne/cmd/fyne`
2. `cd $GOPATH/src/fyne.io/fyne/cmd/fyne && go build`
3. Add `$GOPATH/bin` to $PATH 

Build the application (windows, darwin, linux)
```
fyne package -os windows -icon myapp.png
go build
```
