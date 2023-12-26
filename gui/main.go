package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/aead/ecdh"
	"github.com/devgenie/miniature/internal/miniature"
	yaml "gopkg.in/yaml.v2"
)

type UserResponse struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

func main() {
	a := app.New()
	w := a.NewWindow("Miniature VPN")

	serverAddresslabel := widget.NewLabel("Server Address")
	serverAddress := widget.NewEntry()
	serverAddress.SetPlaceHolder("192.0.0.2 or xyz.com")

	usernameLabel := widget.NewLabel("Username")
	username := widget.NewEntry()
	username.SetPlaceHolder("Username")

	passwordLabel := widget.NewLabel("Password")
	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Password")

	connectButton := widget.NewButton("Connect", nil)
	connectButtonLayout := container.New(layout.NewGridLayout(3), layout.NewSpacer(), connectButton, layout.NewSpacer())

	authArea := container.New(layout.NewFormLayout(),
		serverAddresslabel,
		serverAddress,
		usernameLabel,
		username,
		passwordLabel,
		password)

	w.SetContent(container.New(layout.NewVBoxLayout(),
		authArea,
		connectButtonLayout))
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(400, 80))

	connectButton.OnTapped = func() {
		serverAddress.Disable()
		password.Disable()
		loadingLabel := widget.NewLabel("Authenticating")
		loadingBar := widget.NewProgressBarInfinite()
		cancelButton := widget.NewButton("Cancel", nil)
		popup := widget.NewModalPopUp(container.NewVBox(loadingLabel, loadingBar, cancelButton), w.Canvas())
		popup.Resize(fyne.NewSize(200, 100))
		popup.Show()
		cancelButton.OnTapped = func() {
			popup.Hide()
			serverAddress.Enable()
			password.Enable()
		}
		connectClient(serverAddress.Text, username.Text, password.Text)
	}

	w.SetPadded(true)
	w.CenterOnScreen()
	w.ShowAndRun()
}

func connectClient(serverAddress, username, password string) error {
	client := &http.Client{}
	gob.Register(ecdh.Point{})
	serverAddr := fmt.Sprintf("http://%s:8080/client/auth", serverAddress)
	reqBody := &miniature.User{
		Username: username,
		Password: password,
	}
	payloadBuf := new(bytes.Buffer)
	json.NewEncoder(payloadBuf).Encode(reqBody)
	fmt.Println(payloadBuf)
	req, err := http.NewRequest("POST", serverAddr, payloadBuf)
	if err != nil {
		fmt.Print(err.Error())
		return err
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Print(err.Error())
		return err
	}

	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Print(err.Error())
		return err
	}
	var clientResponse miniature.ClientResponse
	json.Unmarshal(bodyBytes, &clientResponse)
	clientConfig := new(miniature.ClientConfig)
	err = yaml.Unmarshal(clientResponse.Cert, clientConfig)
	if err != nil {
		log.Fatal(err)
		return err
	}
	vpnClient := new(miniature.Client)
	clientConfig.ServerAddress = serverAddress
	err = vpnClient.Run(*clientConfig)
	if err != nil {
		log.Fatal(err)
		return err
	}
	return nil
}
