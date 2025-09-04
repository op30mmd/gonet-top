//go:build windows
// +build windows

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mitchellh/go-ps"
)

// --- ETW and Data Structures ---

const networkProviderGUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"

const (
	opcodeTCPSend    = 10
	opcodeTCPReceive = 11
	opcodeUDPSend    = 42
	opcodeUDPReceive = 43
)

type ProcessNetStats struct {
	PID       uint32
	SentBytes uint64
	RecvBytes uint64
}

var statsMap = struct {
	sync.RWMutex
	m map[uint32]*ProcessNetStats
}{m: make(map[uint32]*ProcessNetStats)}

var pidNameCache = struct {
	sync.RWMutex
	m map[uint32]string
}{m: make(map[uint32]string)}

// --- Bubble Tea Model ---

// ProcessDisplayInfo holds the calculated and formatted data for one process.
type ProcessDisplayInfo struct {
	PID       uint32
	ProcessName string
	SendSpeed string
	RecvSpeed string
}

// statsUpdatedMsg is the message sent when new stats are ready.
type statsUpdatedMsg []ProcessDisplayInfo

type model struct {
	processes []ProcessDisplayInfo
}

func initialModel() model {
	return model{}
}

func (m model) Init() tea.Cmd {
	go startEtwConsumer()
	go startProcessNameWatcher()
	return tick()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}
	case statsUpdatedMsg:
		m.processes = msg
		return m, tick() // Schedule the next tick
	}
	return m, nil
}

func (m model) View() string {
	doc := "gonet-top - Network Usage by Process\n\n"

	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("212")).
		Padding(0, 1)

	cellStyle := lipgloss.NewStyle().Padding(0, 1)

	headers := []string{"PID", "Process Name", "Send Speed", "Recv Speed"}
	headerRow := lipgloss.JoinHorizontal(
		lipgloss.Left,
		headerStyle.Copy().Width(10).Render(headers[0]),
		headerStyle.Copy().Width(30).Render(headers[1]),
		headerStyle.Copy().Width(15).Render(headers[2]),
		headerStyle.Copy().Width(15).Render(headers[3]),
	)

	doc += headerRow + "\n"

	for _, p := range m.processes {
		pidStr := fmt.Sprintf("%d", p.PID)
		row := lipgloss.JoinHorizontal(
			lipgloss.Left,
			cellStyle.Copy().Width(10).Render(pidStr),
			cellStyle.Copy().Width(30).Render(p.ProcessName),
			cellStyle.Copy().Width(15).Render(p.SendSpeed),
			cellStyle.Copy().Width(15).Render(p.RecvSpeed),
		)
		doc += row + "\n"
	}

	doc += "\n\nPress 'q' or 'ctrl+c' to quit."
	return doc
}

// --- Ticker and Data Calculation ---

func tick() tea.Cmd {
	return tea.Tick(time.Second*1, func(t time.Time) tea.Msg {
		return calculateRates()
	})
}

func calculateRates() statsUpdatedMsg {
	statsMap.Lock()
	tempStats := make(map[uint32]*ProcessNetStats, len(statsMap.m))
	for pid, stats := range statsMap.m {
		tempStats[pid] = &ProcessNetStats{
			PID:       stats.PID,
			SentBytes: stats.SentBytes,
			RecvBytes: stats.RecvBytes,
		}
		stats.SentBytes = 0
		stats.RecvBytes = 0
	}
	statsMap.Unlock()

	pidNameCache.RLock()
	defer pidNameCache.RUnlock()

	var displayInfos []ProcessDisplayInfo
	for pid, stats := range tempStats {
		name, ok := pidNameCache.m[pid]
		if !ok {
			name = "N/A"
		}
		displayInfos = append(displayInfos, ProcessDisplayInfo{
			PID:       stats.PID,
			ProcessName: name,
			SendSpeed: formatSpeed(stats.SentBytes),
			RecvSpeed: formatSpeed(stats.RecvBytes),
		})
	}

	return statsUpdatedMsg(displayInfos)
}

func formatSpeed(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B/s", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB/s",
		float64(bytes)/float64(div), "KMGTPE"[exp])
}

// --- Process Name Discovery ---

func getProcessNames() (map[uint32]string, error) {
	processes, err := ps.Processes()
	if err != nil {
		return nil, err
	}

	pidMap := make(map[uint32]string, len(processes))
	for _, p := range processes {
		pidMap[uint32(p.Pid())] = p.Executable()
	}
	return pidMap, nil
}

func startProcessNameWatcher() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C
		names, err := getProcessNames()
		if err != nil {
			// Log the error but continue; we don't want to crash the app.
			log.Printf("Error getting process names: %v", err)
			continue
		}
		pidNameCache.Lock()
		pidNameCache.m = names
		pidNameCache.Unlock()
	}
}


// --- Main and ETW Logic ---

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
}

func startEtwConsumer() {
	s := etw.NewRealTimeSession("gonet-top-session")
	defer s.Stop()

	if err := s.EnableProvider(etw.MustParseProvider(networkProviderGUID)); err != nil {
		log.Printf("Failed to enable provider: %s", err)
		return
	}

	c := etw.NewRealTimeConsumer(context.Background())
	defer c.Stop()

	c.FromSessions(s)

	go func() {
		for e := range c.Events {
			opcode := e.System.Opcode.Value
			isSend := opcode == opcodeTCPSend || opcode == opcodeUDPSend
			isRecv := opcode == opcodeTCPReceive || opcode == opcodeUDPReceive

			if !isSend && !isRecv {
				continue
			}

			pidStr, pidOk := e.EventData["PID"].(string)
			sizeStr, sizeOk := e.EventData["size"].(string)

			if !pidOk || !sizeOk {
				continue
			}

			pid64, err := strconv.ParseUint(pidStr, 10, 32)
			if err != nil {
				continue
			}
			pid := uint32(pid64)

			size, err := strconv.ParseUint(sizeStr, 10, 64)
			if err != nil {
				continue
			}

			statsMap.Lock()
			stats, ok := statsMap.m[pid]
			if !ok {
				stats = &ProcessNetStats{PID: pid}
				statsMap.m[pid] = stats
			}

			if isSend {
				stats.SentBytes += size
			} else if isRecv {
				stats.RecvBytes += size
			}
			statsMap.Unlock()
		}
	}()

	if err := c.Start(); err != nil {
		log.Printf("Error starting consumer: %s", err)
	}
}
