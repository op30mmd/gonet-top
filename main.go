//go:build windows
// +build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
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

// Try multiple network providers
var networkProviders = []string{
	"{7DD42A49-5329-4832-8DFD-43D979153A88}", // Microsoft-Windows-Kernel-Network
	"{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}", // Microsoft-Windows-TCPIP
	"{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}", // Microsoft-Windows-WinINet
}

const (
	// TCP opcodes
	opcodeTCPSend    = 10
	opcodeTCPReceive = 11
	opcodeTCPConnect = 12
	opcodeTCPDisconnect = 13
	
	// UDP opcodes  
	opcodeUDPSend    = 42
	opcodeUDPReceive = 43
	
	// Alternative opcodes that might be used
	opcodeNetworkSend = 26
	opcodeNetworkRecv = 27
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
	// Command line flags
	debugMode := flag.Bool("debug", false, "Enable debug mode (logs to console instead of running TUI)")
	flag.Parse()
	
	// Check if we're in CI environment
	isCI := os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != ""
	
	// Setup logging
	var logFile *os.File
	var err error
	
	if isCI {
		// In CI, log to file for debugging
		logFile, err = os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
			os.Exit(1)
		}
		defer logFile.Close()
		log.SetOutput(logFile)
	} else if *debugMode {
		// In debug mode, log to both console and file
		logFile, err = os.OpenFile("debug.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open debug log file: %v\n", err)
			os.Exit(1)
		}
		defer logFile.Close()
		log.SetOutput(os.Stdout) // Log to console in debug mode
	} else {
		// In normal environment, log to stderr so it's visible if needed
		log.SetOutput(os.Stderr)
	}
	
	log.Println("Starting gonet-top...")

	if !isAdmin() {
		log.Println("Error: Administrator privileges are required.")
		fmt.Println("Error: Administrator privileges are required.")
		fmt.Println("Please restart the application from a terminal with 'Run as administrator'.")
		return
	}
	
	log.Println("Admin check passed")

	if *debugMode {
		fmt.Println("Debug mode enabled - ETW events will be logged to console")
		fmt.Println("Press Ctrl+C to exit")
		
		// In debug mode, just run the ETW consumer and log events
		go startEtwConsumer()
		go startProcessNameWatcher()
		
		// Keep the program running and periodically show stats
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				showDebugStats()
			}
		}
	}

	var p *tea.Program
	
	if isCI {
		// In CI, output TUI to file for testing
		tuiLogFile, err := os.OpenFile("tui.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
		if err != nil {
			log.Fatalf("Failed to open TUI log file: %v", err)
		}
		defer tuiLogFile.Close()
		log.Println("Starting Bubble Tea program (CI mode)...")
		p = tea.NewProgram(initialModel(), tea.WithOutput(tuiLogFile), tea.WithAltScreen())
	} else {
		// In normal environment, use standard terminal
		fmt.Println("Starting gonet-top... (Run with -debug flag to see ETW logs)")
		time.Sleep(2 * time.Second) // Give user time to read the message
		log.Println("Starting Bubble Tea program (interactive mode)...")
		p = tea.NewProgram(initialModel(), tea.WithAltScreen())
	}
	
	if _, err := p.Run(); err != nil {
		log.Fatalf("Alas, there's been an error: %v", err)
	}
}

func startEtwConsumer() {
	log.Println("Starting ETW consumer...")
	
	s := etw.NewRealTimeSession("gonet-top-session")
	defer s.Stop()
	
	// Try enabling multiple providers
	providersEnabled := 0
	for i, providerGUID := range networkProviders {
		if err := s.EnableProvider(etw.MustParseProvider(providerGUID)); err != nil {
			log.Printf("Failed to enable provider %d (%s): %s", i+1, providerGUID, err)
		} else {
			log.Printf("Successfully enabled provider %d (%s)", i+1, providerGUID)
			providersEnabled++
		}
	}
	
	if providersEnabled == 0 {
		log.Printf("Failed to enable any ETW providers!")
		return
	}
	
	log.Printf("Enabled %d out of %d ETW providers", providersEnabled, len(networkProviders))
	
	c := etw.NewRealTimeConsumer(context.Background())
	defer c.Stop()
	
	c.FromSessions(s)
	
	// Start event processing goroutine
	go func() {
		eventCount := 0
		unknownOpcodes := make(map[uint8]int)
		fieldNames := make(map[string]int)
		
		log.Println("Starting to process ETW events...")
		
		for e := range c.Events {
			eventCount++
			
			// Log first few events completely for debugging
			if eventCount <= 20 {
				log.Printf("Event #%d - Provider: %s, Opcode: %d, EventData: %+v", 
					eventCount, e.System.Provider.Guid, e.System.Opcode.Value, e.EventData)
			}
			
			// Track all field names we see
			for fieldName := range e.EventData {
				fieldNames[fieldName]++
			}
			
			// Log field names summary every 100 events
			if eventCount%100 == 0 {
				log.Printf("Processed %d events. Field names seen: %+v", eventCount, fieldNames)
			}
			
			opcode := e.System.Opcode.Value
			
			// Track unknown opcodes
			unknownOpcodes[opcode]++
			if eventCount%100 == 0 {
				log.Printf("Opcode frequency: %+v", unknownOpcodes)
			}
			
			// Check for network-related opcodes (be more permissive)
			isSend := opcode == opcodeTCPSend || opcode == opcodeUDPSend || opcode == opcodeNetworkSend
			isRecv := opcode == opcodeTCPReceive || opcode == opcodeUDPReceive || opcode == opcodeNetworkRecv
			
			// Also try to detect based on event data field names
			if !isSend && !isRecv {
				// Look for common network-related field patterns
				hasNetworkFields := false
				for fieldName := range e.EventData {
					lowerField := strings.ToLower(fieldName)
					if strings.Contains(lowerField, "size") || 
					   strings.Contains(lowerField, "length") || 
					   strings.Contains(lowerField, "bytes") ||
					   strings.Contains(lowerField, "data") {
						hasNetworkFields = true
						break
					}
				}
				
				if hasNetworkFields {
					// Assume it's network traffic, try to determine direction from field names or opcode
					if opcode%2 == 0 {
						isSend = true
					} else {
						isRecv = true
					}
				}
			}
			
			if !isSend && !isRecv {
				continue
			}
			
			// Try multiple field names for PID
			var pid uint32
			var pidOk bool
			
			for _, pidField := range []string{"PID", "ProcessId", "pid", "ProcessID", "Pid"} {
				if p, ok := e.EventData[pidField]; ok {
					switch v := p.(type) {
					case uint32:
						pid, pidOk = v, true
					case int32:
						pid, pidOk = uint32(v), true
					case uint64:
						pid, pidOk = uint32(v), true
					case int64:
						pid, pidOk = uint32(v), true
					}
					if pidOk {
						break
					}
				}
			}
			
			// Try multiple field names for size
			var size64 uint64
			var sizeOk bool
			
			for _, sizeField := range []string{"size", "Size", "DataLength", "Length", "ByteCount", "Bytes", "PacketSize"} {
				if s, ok := e.EventData[sizeField]; ok {
					switch v := s.(type) {
					case uint32:
						size64, sizeOk = uint64(v), true
					case int32:
						size64, sizeOk = uint64(v), true
					case uint64:
						size64, sizeOk = v, true
					case int64:
						size64, sizeOk = uint64(v), true
					}
					if sizeOk {
						break
					}
				}
			}
			
			if !pidOk || !sizeOk {
				if eventCount <= 50 {
					log.Printf("Missing fields - PID found: %t, Size found: %t", pidOk, sizeOk)
				}
				continue
			}
			
			if eventCount <= 10 {
				log.Printf("Processing network event: PID=%d, Size=%d, Opcode=%d, IsSend=%t", 
					pid, size64, opcode, isSend)
			}
			
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
				stats.SentBytes += size64
			} else if isRecv {
				stats.RecvBytes += size64
			}
			stats.UpdatedAt = time.Now()
			statsMap.Unlock()
		}
		
		log.Printf("ETW event processing stopped after %d events", eventCount)
	}()
	
	// Start the consumer
	if err := c.Start(); err != nil {
		log.Printf("Error starting consumer: %s", err)
	} else {
		log.Println("ETW consumer started successfully")
	}
}
