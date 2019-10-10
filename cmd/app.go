package main

import (
	"fyne.io/fyne"
	"fyne.io/fyne/app"
	"fyne.io/fyne/layout"
	"fyne.io/fyne/theme"
	"fyne.io/fyne/widget"
	"github.com/Gordon-Yeh/simple-vpn/client"
	"github.com/Gordon-Yeh/simple-vpn/crypto"
	"github.com/Gordon-Yeh/simple-vpn/server"
)

func main() {
	crypto.Init()

	app := app.New()
	w := app.NewWindow("CPEN 442 | VPN")
	app.Settings().SetTheme(theme.LightTheme())

	initLayout := fyne.NewContainerWithLayout(layout.NewCenterLayout(),
		widget.NewVBox(
			widget.NewLabel("Select application role:"),
			widget.NewButton("Client", func() {
				client.Start(w, app)
			}),
			widget.NewButton("Server", func() {
				server.Start(w, app)
			}),
		),
	)

	w.SetContent(initLayout)
	// w.SetFixedSize(true)
	w.Resize(fyne.NewSize(640, 400))
	w.CenterOnScreen()
	w.ShowAndRun()
}
