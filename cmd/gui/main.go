package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/devgenie/miniature/internal/miniature"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

func main() {
	if err := ui.Init(); err != nil {
		log.Fatal("Failed to initialize UI:", err)
	}
	defer ui.Close()
	termWidth, termHeight := ui.TerminalDimensions()
	title := widgets.NewParagraph()
	title.Text = "Welcome to Miniatureby DevGenie, press q to quit"
	title.TextStyle.Modifier = ui.ModifierBold
	title.WrapText = true
	title.TextStyle.Fg = ui.ColorGreen
	title.BorderStyle.Fg = ui.ColorCyan
	title.PaddingBottom = 1
	title.PaddingTop = 1
	title.PaddingRight = 1
	title.PaddingLeft = 1


	systemStats := widgets.NewList()
	systemStats.BorderStyle.Fg = ui.ColorCyan
	systemStats.Title = "System"
	systemStats.TitleStyle.Fg = ui.ColorGreen

	peerStats := widgets.NewList()
	peerStats.BorderStyle.Fg = ui.ColorCyan
	peerStats.Title = "Peers"
	peerStats.TitleStyle.Fg = ui.ColorGreen

	networkStats := widgets.NewList()
	networkStats.BorderStyle.Fg = ui.ColorCyan
	networkStats.Title = "Network"
	networkStats.TitleStyle.Fg = ui.ColorGreen

	networkData := widgets.NewSparkline()
	networkData.Title = "Peers connected: 0"
	networkData.LineColor = ui.ColorCyan
	networkData.Data = make([]float64, 1)
	networkData.TitleStyle.Modifier = ui.ModifierBold
	networkData.TitleStyle.Fg = ui.ColorGreen

	sparklineGroup := widgets.NewSparklineGroup(networkData)

	grid := ui.NewGrid()
	grid.SetRect(0, 0, termWidth, termHeight)

	grid.Set(
		ui.NewRow(0.4/6,title),
		ui.NewRow(5.6/6,
			ui.NewCol(1.0/4,
				ui.NewRow(2.0/6,systemStats),
				ui.NewRow(2.0/6,peerStats),
				ui.NewRow(2.0/6,networkStats),
			),
			ui.NewCol(3.0/4, sparklineGroup),
		),
	)

	ui.Render(grid)
	tickerCount := 1
	uiEvents := ui.PollEvents()
	ticker := time.NewTicker(time.Second).C
	for {
		select {
		case e := <-uiEvents:
			switch e.ID {
			case "q", "<C-c>":
				return
			case "<Resize>":
				payload := e.Payload.(ui.Resize)
				grid.SetRect(0, 0, payload.Width, payload.Height)
				ui.Clear()
				ui.Render(grid)

			}
		case <-ticker:
			usageStats := callStats()
			generalStatsRows := []string{fmt.Sprintf("Available: %d", usageStats.AvailableSlots),
										fmt.Sprintf("Total: %d", usageStats.AvailableSlots),
										fmt.Sprintf("Connected: %d", usageStats.Peers),
										fmt.Sprintf("Bytes in: %d", usageStats.ConnectionsIn),
										fmt.Sprintf("Bytes out: %d", usageStats.ConnectionsOut),
									}
			
			systemStatsRows := []string{fmt.Sprintf("Running time: %s", usageStats.TimeElapsed),
			}
			networkData.Data = append(networkData.Data, float64(usageStats.Peers))
			peerStats.Rows = generalStatsRows
			systemStats.Rows = systemStatsRows
			ui.Render(grid)
			tickerCount++
			networkData.Title = fmt.Sprintf("Peers Connected: %d %s", tickerCount, termWidth)
		}
	}
}

func callStats() miniature.Stats {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://localhost:8080/stats", nil)
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
	var responseObject miniature.Stats
	json.Unmarshal(bodyBytes, &responseObject)
	return responseObject
}