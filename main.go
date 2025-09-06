//go:build windows
// +build windows

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mitchellh/go-ps"
)

// --- Admin Check ---

func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

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
	LastSent  uint64
	LastRecv  uint64
	UpdatedAt time.Time
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

type ProcessDisplayInfo struct {
	PID         uint32
	ProcessName string
	SendSpeed   string
	RecvSpeed   string
	TotalSent   uint64
	TotalRecv   uint64
}

type statsUpdatedMsg []ProcessDisplayInfo

type model struct {
	processes []ProcessDisplayInfo
	lastUpdate time.Time
}

func initialModel() model {
	return model{
		lastUpdate: time.Now(),
	}
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
		m.lastUpdate = time.Now()
		return m, tick()
	}
	return m, nil
}

func (m model) View() string {
	doc := "gonet-top - Network Usage by Process\n"
	doc += fmt.Sprintf("Last updated: %s\n", m.lastUpdate.Format("15:04:05"))
	doc += fmt.Sprintf("Active processes: %d\n\n", len(m.processes))
	
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212")).Padding(0, 1)
	cellStyle := lipgloss.NewStyle().Padding(0, 1)
	
	headers := []string{"PID", "Process Name", "Send Rate", "Recv Rate", "Total Sent", "Total Recv"}
	headerRow := lipgloss.JoinHorizontal(lipgloss.Left,
		headerStyle.Copy().Width(8).Render(headers[0]),
		headerStyle.Copy().Width(20).Render(headers[1]),
		headerStyle.Copy().Width(12).Render(headers[2]),
		headerStyle.Copy().Width(12).Render(headers[3]),
		headerStyle.Copy().Width(12).Render(headers[4]),
		headerStyle.Copy().Width(12).Render(headers[5]),
	)
	doc += headerRow + "\n"
	
	if len(m.processes) == 0 {
		doc += "No network activity detected yet...\n"
		doc += "Try browsing the web or downloading a file to see data.\n"
	} else {
		for _, p := range m.processes {
			pidStr := fmt.Sprintf("%d", p.PID)
			row := lipgloss.JoinHorizontal(lipgloss.Left,
				cellStyle.Copy().Width(8).Render(pidStr),
				cellStyle.Copy().Width(20).Render(truncateString(p.ProcessName, 18)),
				cellStyle.Copy().Width(12).Render(p.SendSpeed),
				cellStyle.Copy().Width(12).Render(p.RecvSpeed),
				cellStyle.Copy().Width(12).Render(formatBytes(p.TotalSent)),
				cellStyle.Copy().Width(12).Render(formatBytes(p.TotalRecv)),
			)
			doc += row + "\n"
		}
	}
	
	doc += "\n\nPress 'q' or 'ctrl+c' to quit."
	return doc
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// --- Ticker and Data Calculation ---

func tick() tea.Cmd {
	return tea.Tick(time.Second*2, func(t time.Time) tea.Msg {
		return calculateRates()
	})
}

func calculateRates() statsUpdatedMsg {
	now := time.Now()
	
	statsMap.Lock()
	currentStats := make(map[uint32]*ProcessNetStats)
	for pid, stats := range statsMap.m {
		// Copy the stats to avoid data races
		currentStats[pid] = &ProcessNetStats{
			PID:       stats.PID,
			SentBytes: stats.SentBytes,
			RecvBytes: stats.RecvBytes,
			LastSent:  stats.LastSent,
			LastRecv:  stats.LastRecv,
			UpdatedAt: stats.UpdatedAt,
		}
	}
	statsMap.Unlock()
	
	pidNameCache.RLock()
	defer pidNameCache.RUnlock()
	
	var displayInfos []ProcessDisplayInfo
	
	for pid, stats := range currentStats {
		// Skip processes with no activity
		if stats.SentBytes == 0 && stats.RecvBytes == 0 {
			continue
		}
		
		// Calculate rates based on time difference
		timeDiff := now.Sub(stats.UpdatedAt).Seconds()
		if timeDiff <= 0 {
			timeDiff = 1
		}
		
		sendRate := float64(stats.SentBytes-stats.LastSent) / timeDiff
		recvRate := float64(stats.RecvBytes-stats.LastRecv) / timeDiff
		
		// Update last values for next calculation
		statsMap.Lock()
		if s, exists := statsMap.m[pid]; exists {
			s.LastSent = stats.SentBytes
			s.LastRecv = stats.RecvBytes
			s.UpdatedAt = now
		}
		statsMap.Unlock()
		
		name, ok := pidNameCache.m[pid]
		if !ok {
			name = fmt.Sprintf("PID-%d", pid)
		}
		
		displayInfos = append(displayInfos, ProcessDisplayInfo{
			PID:         pid,
			ProcessName: name,
			SendSpeed:   formatSpeed(uint64(sendRate)),
			RecvSpeed:   formatSpeed(uint64(recvRate)),
			TotalSent:   stats.SentBytes,
			TotalRecv:   stats.RecvBytes,
		})
	}
	
	// Sort by total bytes (sent + received) descending
	sort.Slice(displayInfos, func(i, j int) bool {
		totalI := displayInfos[i].TotalSent + displayInfos[i].TotalRecv
		totalJ := displayInfos[j].TotalSent + displayInfos[j].TotalRecv
		return totalI > totalJ
	})
	
	// Limit to top 20 processes to avoid clutter
	if len(displayInfos) > 20 {
		displayInfos = displayInfos[:20]
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
	return fmt.Sprintf("%.1f %cB/s", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// --- Debug Functions ---

func showDebugStats() {
	statsMap.RLock()
	defer statsMap.RUnlock()
	
	pidNameCache.RLock()
	defer pidNameCache.RUnlock()
	
	fmt.Println("\n=== Current Network Stats ===")
	fmt.Printf("Tracked processes: %d\n", len(statsMap.m))
	
	if len(statsMap.m) == 0 {
		fmt.Println("No network activity detected")
		return
	}
	
	for pid, stats := range statsMap.m {
		name, ok := pidNameCache.m[pid]
		if !ok {
			name = fmt.Sprintf("PID-%d", pid)
		}
		
		fmt.Printf("PID %d (%s): Sent=%s, Recv=%s\n", 
			pid, name, 
			formatBytes(stats.SentBytes), 
			formatBytes(stats.RecvBytes))
	}
	fmt.Println("=============================")
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
	update := func() {
		names, err := getProcessNames()
		if err != nil {
			log.Printf("Error getting process names: %v", err)
			return
		}
		pidNameCache.Lock()
		pidNameCache.m = names
		pidNameCache.Unlock()
		log.Printf("Updated process names cache with %d processes", len(names))
	}
	
	update() // Initial update
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		<-ticker.C
		update()
	}
}

// --- Main and ETW Logic ---

func main() {
	// Setup logging to a file for debugging in CI.
	logFile, err := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	
	log.Println("Starting gonet-top...")

	if !isAdmin() {
		log.Println("Error: Administrator privileges are required.")
		fmt.Println("Error: Administrator privileges are required.")
		fmt.Println("Please restart the application from a terminal with 'Run as administrator'.")
		return
	}
	
	log.Println("Admin check passed")

	// Setup TUI output to a different file for CI testing.
	tuiLogFile, err := os.OpenFile("tui.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("Failed to open TUI log file: %v", err)
	}
	defer tuiLogFile.Close()

	log.Println("Starting Bubble Tea program...")
	p := tea.NewProgram(initialModel(), tea.WithOutput(tuiLogFile), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatalf("Alas, there's been an error: %v", err)
	}
}

func startEtwConsumer() {
	log.Println("Starting ETW consumer...")
	
	s := etw.NewRealTimeSession("gonet-top-session")
	defer s.Stop()
	
	if err := s.EnableProvider(etw.MustParseProvider(networkProviderGUID)); err != nil {
		log.Printf("Failed to enable provider: %s", err)
		return
	}
	
	log.Println("ETW provider enabled successfully")
	
	c := etw.NewRealTimeConsumer(context.Background())
	defer c.Stop()
	
	c.FromSessions(s)
	
	// Start event processing goroutine
	go func() {
		eventCount := 0
		log.Println("Starting to process ETW events...")
		
		for e := range c.Events {
			eventCount++
			if eventCount%100 == 0 {
				log.Printf("Processed %d events", eventCount)
			}
			
			opcode := e.System.Opcode.Value
			isSend := opcode == opcodeTCPSend || opcode == opcodeUDPSend
			isRecv := opcode == opcodeTCPReceive || opcode == opcodeUDPReceive
			
			if !isSend && !isRecv {
				continue
			}
			
			// Try different field names for PID
			var pid uint32
			var pidOk bool
			
			if p, ok := e.EventData["PID"].(uint32); ok {
				pid, pidOk = p, true
			} else if p, ok := e.EventData["ProcessId"].(uint32); ok {
				pid, pidOk = p, true
			} else if p, ok := e.EventData["pid"].(uint32); ok {
				pid, pidOk = p, true
			}
			
			// Try different field names for size
			var size32 uint32
			var sizeOk bool
			
			if s, ok := e.EventData["size"].(uint32); ok {
				size32, sizeOk = s, true
			} else if s, ok := e.EventData["Size"].(uint32); ok {
				size32, sizeOk = s, true
			} else if s, ok := e.EventData["DataLength"].(uint32); ok {
				size32, sizeOk = s, true
			} else if s, ok := e.EventData["Length"].(uint32); ok {
				size32, sizeOk = s, true
			}
			
			if !pidOk || !sizeOk {
				if eventCount <= 10 {
					log.Printf("Event data fields: %+v", e.EventData)
				}
				continue
			}
			
			if eventCount <= 5 {
				log.Printf("Processing event: PID=%d, Size=%d, Opcode=%d, IsSend=%t", pid, size32, opcode, isSend)
			}
			
			size := uint64(size32)
			
			statsMap.Lock()
			stats, ok := statsMap.m[pid]
			if !ok {
				stats = &ProcessNetStats{
					PID:       pid,
					UpdatedAt: time.Now(),
				}
				statsMap.m[pid] = stats
			}
			
			if isSend {
				stats.SentBytes += size
			} else if isRecv {
				stats.RecvBytes += size
			}
			stats.UpdatedAt = time.Now()
			statsMap.Unlock()
		}
		
		log.Println("ETW event processing stopped")
	}()
	
	// Start the consumer
	if err := c.Start(); err != nil {
		log.Printf("Error starting consumer: %s", err)
	} else {
		log.Println("ETW consumer started successfully")
	}
}
