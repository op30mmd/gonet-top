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

// --- Bubble Tea Model (Temporarily Unused) ---

type ProcessDisplayInfo struct {
	PID         uint32
	ProcessName string
	SendSpeed   string
	RecvSpeed   string
}

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
	// ... (code is unused for now)
	return m, nil
}

func (m model) View() string {
	// ... (code is unused for now)
	return ""
}

// --- Ticker and Data Calculation ---

func tick() tea.Cmd {
	return tea.Tick(time.Second*1, func(t time.Time) tea.Msg {
		return calculateRates()
	})
}

func calculateRates() statsUpdatedMsg {
	statsMap.Lock()
	currentStats := statsMap.m
	statsMap.m = make(map[uint32]*ProcessNetStats)
	statsMap.Unlock()

	pidNameCache.RLock()
	defer pidNameCache.RUnlock()

	var displayInfos []ProcessDisplayInfo
	for pid, stats := range currentStats {
		name, ok := pidNameCache.m[pid]
		if !ok {
			name = "N/A"
		}
		displayInfos = append(displayInfos, ProcessDisplayInfo{
			PID:         stats.PID,
			ProcessName: name,
			SendSpeed:   formatSpeed(stats.SentBytes),
			RecvSpeed:   formatSpeed(stats.RecvBytes),
		})
	}
	// Also log the calculated rates to the console for debugging
	log.Printf("Calculated stats for %d processes.", len(displayInfos))

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
	log.Println("Application starting...")

	// Start the background processes
	go startEtwConsumer()
	go startProcessNameWatcher()

	// For debugging, we'll just sleep and let the background tasks run.
	// We'll also log the stats periodically.
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for i := 0; i < 7; i++ { // Run for ~14 seconds
		<-ticker.C
		calculateRates() // This will now log the number of processes it found
	}

	log.Println("Application finished.")
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
