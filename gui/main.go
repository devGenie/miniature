package main

import (
	"bytes"
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
	"github.com/devgenie/miniature/internal/miniature"
	yaml "gopkg.in/yaml.v2"
)

type User struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type UserResponse struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

func main() {
	a := app.New()
	w := a.NewWindow("Miniature VPN")

	serverAddresslabel := widget.NewLabel("Server Address:")
	serverAddress := widget.NewEntry()
	serverAddress.SetPlaceHolder("192.0.0.2 or http://xyz.com")

	accessTokenLabel := widget.NewLabel("Access token:")
	accessToken := widget.NewEntry()
	accessToken.SetPlaceHolder("Access token")

	connectButton := widget.NewButton("Connect", nil)

	authArea := container.New(layout.NewFormLayout(),
		serverAddresslabel,
		serverAddress,
		accessTokenLabel,
		accessToken)
	w.SetContent(container.New(layout.NewVBoxLayout(),
		authArea,
		connectButton))
	w.Resize(fyne.NewSize(500, 80))

	connectButton.OnTapped = func() {
		serverAddress.Disable()
		accessToken.Disable()
		loadingLabel := widget.NewLabel("connecting ...")
		cancelButton := widget.NewButton("Cancel", nil)
		popup := widget.NewModalPopUp(container.NewVBox(loadingLabel, cancelButton), w.Canvas())
		popup.Show()
		cancelButton.OnTapped = func() {
			popup.Hide()
		}
		connectClient(serverAddress.Text, accessToken.Text)
	}
	w.ShowAndRun()
}

func connectClient(serverAddress, accessToken string) error {
	client := &http.Client{}
	serverAddr := fmt.Sprintf("http://%s:8080/client/auth", serverAddress)
	reqBody := &User{
		Name:     "abc",
		Password: accessToken,
	}
	payloadBuf := new(bytes.Buffer)
	json.NewEncoder(payloadBuf).Encode(reqBody)

	req, err := http.NewRequest("POST", serverAddr, payloadBuf)
	if err != nil {
		fmt.Print(err.Error())
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Print(err.Error())
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Print(err.Error())
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
	clientConfig.ServerAddress = "localhost"
	err = vpnClient.Run(*clientConfig)
	if err != nil {
		log.Fatal(err)
		return err
	}
	return nil
}
