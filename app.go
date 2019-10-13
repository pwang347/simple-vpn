package main

import (
	"fyne.io/fyne"
	"fyne.io/fyne/app"
	"fyne.io/fyne/layout"
	"fyne.io/fyne/theme"
	"fyne.io/fyne/widget"
	"github.com/pwang347/simple-vpn/client"
	"github.com/pwang347/simple-vpn/crypto"
	"github.com/pwang347/simple-vpn/icon"
	"github.com/pwang347/simple-vpn/server"
)

func main() {
	crypto.Init()

	app := app.New()
	w := app.NewWindow("CPEN 442 | VPN")
	w.SetIcon(icon.IconBitmap)
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
	w.Resize(fyne.NewSize(640, 400))
	w.CenterOnScreen()
	w.ShowAndRun()
}
