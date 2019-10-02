package main

import (
	"fyne.io/fyne/app"
	"fyne.io/fyne/widget"
	"github.com/Gordon-Yeh/simple-vpn/client"
	"github.com/Gordon-Yeh/simple-vpn/server"
)

func main() {
	app := app.New()
	w := app.NewWindow("CPEN 442 | VPN")

	initLayout := widget.NewVBox(
		widget.NewLabel("Select application role:"),
		widget.NewButton("Client", func() {
			client.Start(w, app)
		}),
		widget.NewButton("Server", func() {
			server.Start(w, app)
		}),
	)

	w.SetContent(initLayout)
	w.ShowAndRun()
}
