package main

import (
	"encoding/json"
	"fmt"
	"io"
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
	title.Text = "Welcome to Miniature by DevGenie, press q to quit. Total runtime: n/a"
	title.TextStyle.Modifier = ui.ModifierBold
	title.WrapText = true
	title.TextStyle.Fg = ui.ColorGreen
	title.BorderStyle.Fg = ui.ColorCyan
	title.PaddingBottom = 1
	title.PaddingTop = 1
	title.PaddingRight = 1
	title.PaddingLeft = 1

	info := widgets.NewList()
	info.BorderStyle.Fg = ui.ColorCyan
	info.Title = "Info"
	info.TitleStyle.Fg = ui.ColorGreen

	networkDataIn := widgets.NewSparkline()
	networkDataIn.Title = "Bytes in"
	networkDataIn.Data = make([]float64, 0)
	networkDataIn.LineColor = ui.ColorGreen
	networkDataIn.TitleStyle.Modifier = ui.ModifierBold
	networkDataIn.TitleStyle.Fg = ui.ColorGreen

	networkDataOut := widgets.NewSparkline()
	networkDataOut.Title = "Bytes out"
	networkDataOut.Data = make([]float64, 0)
	networkDataOut.LineColor = ui.ColorCyan
	networkDataOut.TitleStyle.Modifier = ui.ModifierBold
	networkDataOut.TitleStyle.Fg = ui.ColorCyan

	sparklineGroup := widgets.NewSparklineGroup(networkDataIn, networkDataOut)
	sparklineGroup.Title = "Network stats"

	grid := ui.NewGrid()
	grid.SetRect(0, 0, termWidth, termHeight)

	grid.Set(
		ui.NewRow(0.4/6, title),
		ui.NewRow(5.6/6,
			ui.NewCol(1.0/4,
				ui.NewRow(2.0/6, info),
			),
			ui.NewCol(3.0/4, sparklineGroup),
		),
	)

	ui.Render(grid)
	lastConnIn := new(int)
	lastConnOut := new(int)
	*lastConnIn = 0
	*lastConnOut = 0
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
			title.Text = fmt.Sprintf("Welcome to Miniature by DevGenie, press q to quit. Total runtime: %s", usageStats.TimeElapsed)
			generalStatsRows := []string{
				fmt.Sprintf("Available connections: %d", usageStats.AvailableSlots),
				fmt.Sprintf("Peers connected: %d", usageStats.Peers),
				fmt.Sprintf("Total bytes in: %d", usageStats.ConnectionsIn),
				fmt.Sprintf("Total bytes out: %d", usageStats.ConnectionsOut),
			}

			networkDataIn.Data = append(networkDataIn.Data, float64(usageStats.ConnectionsIn))
			networkDataOut.Data = append(networkDataOut.Data, float64(usageStats.ConnectionsOut))
			info.Rows = generalStatsRows
			ui.Render(grid)
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
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Print(err.Error())
	}
	var responseObject miniature.Stats
	json.Unmarshal(bodyBytes, &responseObject)
	return responseObject
}
