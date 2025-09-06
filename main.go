//go:build windows
// +build windows

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"syscall"
	"time"
	"unsafe"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mitchellh/go-ps"
)

// --- Windows API declarations ---

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")

	procGetProcessMemoryInfo = kernel32.NewProc("K32GetProcessMemoryInfo")
	procGetTcpTable2         = iphlpapi.NewProc("GetTcpTable2")
	procGetUdpTable          = iphlpapi.NewProc("GetUdpTable")
)

// TCP_TABLE_OWNER_PID_ALL constant
const TCP_TABLE_OWNER_PID_ALL = 5
const UDP_TABLE_OWNER_PID = 1

// MIB_TCPROW2 structure
type MIB_TCPROW2 struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
	OffloadState uint32
}

type MIB_TCPTABLE2 struct {
	NumEntries uint32
	Table      [1]MIB_TCPROW2
}

// MIB_UDPROW_OWNER_PID structure
type MIB_UDPROW_OWNER_PID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

type MIB_UDPTABLE_OWNER_PID struct {
	NumEntries uint32
	Table      [1]MIB_UDPROW_OWNER_PID
}

// --- Admin Check ---

func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

// --- Data Structures ---

type ProcessNetStats struct {
	PID         uint32
	ProcessName string
	TCPConns    uint32
	UDPConns    uint32
	LastUpdate  time.Time
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
	TCPConns    uint32
	UDPConns    uint32
	TotalConns  uint32
}

type statsUpdatedMsg []ProcessDisplayInfo

type model struct {
	processes  []ProcessDisplayInfo
	lastUpdate time.Time
}

func initialModel() model {
	return model{
		lastUpdate: time.Now(),
	}
}

func (m model) Init() tea.Cmd {
	go startNetworkMonitor()
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
	doc := "gonet-top - Network Connections by Process\n"
	doc += fmt.Sprintf("Last updated: %s\n", m.lastUpdate.Format("15:04:05"))
	doc += fmt.Sprintf("Active processes: %d\n\n", len(m.processes))

	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212")).Padding(0, 1)
	cellStyle := lipgloss.NewStyle().Padding(0, 1)

	headers := []string{"PID", "Process Name", "TCP Conns", "UDP Conns", "Total"}
	headerRow := lipgloss.JoinHorizontal(lipgloss.Left,
		headerStyle.Copy().Width(8).Render(headers[0]),
		headerStyle.Copy().Width(25).Render(headers[1]),
		headerStyle.Copy().Width(12).Render(headers[2]),
		headerStyle.Copy().Width(12).Render(headers[3]),
		headerStyle.Copy().Width(12).Render(headers[4]),
	)
	doc += headerRow + "\n"

	if len(m.processes) == 0 {
		doc += "No network connections detected...\n"
		doc += "Try browsing the web or starting network applications.\n"
	} else {
		for _, p := range m.processes {
			row := lipgloss.JoinHorizontal(lipgloss.Left,
				cellStyle.Copy().Width(8).Render(fmt.Sprintf("%d", p.PID)),
				cellStyle.Copy().Width(25).Render(truncateString(p.ProcessName, 23)),
				cellStyle.Copy().Width(12).Render(fmt.Sprintf("%d", p.TCPConns)),
				cellStyle.Copy().Width(12).Render(fmt.Sprintf("%d", p.UDPConns)),
				cellStyle.Copy().Width(12).Render(fmt.Sprintf("%d", p.TotalConns)),
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

// --- Ticker ---

func tick() tea.Cmd {
	return tea.Tick(time.Second*3, func(t time.Time) tea.Msg {
		return getNetworkStats()
	})
}

// --- Network Connection Monitoring ---

func getTcpConnections() (map[uint32]uint32, error) {
	connections := make(map[uint32]uint32)

	// Get buffer size
	var bufSize uint32
	ret, _, _ := procGetTcpTable2.Call(0, uintptr(unsafe.Pointer(&bufSize)), 0, TCP_TABLE_OWNER_PID_ALL)

	if ret != 122 { // ERROR_INSUFFICIENT_BUFFER
		return nil, fmt.Errorf("failed to get TCP table size: %d", ret)
	}

	// Allocate buffer
	buf := make([]byte, bufSize)
	ret, _, _ = procGetTcpTable2.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufSize)),
		0,
		TCP_TABLE_OWNER_PID_ALL,
	)

	if ret != 0 {
		return nil, fmt.Errorf("failed to get TCP table: %d", ret)
	}

	// Parse table
	table := (*MIB_TCPTABLE2)(unsafe.Pointer(&buf[0]))
	tableSlice := (*[1024 * 1024]MIB_TCPROW2)(unsafe.Pointer(&table.Table[0]))[:table.NumEntries:table.NumEntries]

	for _, row := range tableSlice {
		connections[row.OwningPid]++
	}

	return connections, nil
}

func getUdpConnections() (map[uint32]uint32, error) {
	connections := make(map[uint32]uint32)

	// Get buffer size
	var bufSize uint32
	ret, _, _ := procGetUdpTable.Call(0, uintptr(unsafe.Pointer(&bufSize)), 0, UDP_TABLE_OWNER_PID)

	if ret != 122 { // ERROR_INSUFFICIENT_BUFFER
		return nil, fmt.Errorf("failed to get UDP table size: %d", ret)
	}

	// Allocate buffer
	buf := make([]byte, bufSize)
	ret, _, _ = procGetUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufSize)),
		0,
		UDP_TABLE_OWNER_PID,
	)

	if ret != 0 {
		return nil, fmt.Errorf("failed to get UDP table: %d", ret)
	}

	// Parse table
	table := (*MIB_UDPTABLE_OWNER_PID)(unsafe.Pointer(&buf[0]))
	tableSlice := (*[1024 * 1024]MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&table.Table[0]))[:table.NumEntries:table.NumEntries]

	for _, row := range tableSlice {
		connections[row.OwningPid]++
	}

	return connections, nil
}

func getNetworkStats() statsUpdatedMsg {
	tcpConns, err := getTcpConnections()
	if err != nil {
		log.Printf("Error getting TCP connections: %v", err)
		tcpConns = make(map[uint32]uint32)
	}

	udpConns, err := getUdpConnections()
	if err != nil {
		log.Printf("Error getting UDP connections: %v", err)
		udpConns = make(map[uint32]uint32)
	}

	// Combine all PIDs
	allPids := make(map[uint32]bool)
	for pid := range tcpConns {
		allPids[pid] = true
	}
	for pid := range udpConns {
		allPids[pid] = true
	}

	pidNameCache.RLock()
	defer pidNameCache.RUnlock()

	var displayInfos []ProcessDisplayInfo

	for pid := range allPids {
		tcpCount := tcpConns[pid]
		udpCount := udpConns[pid]
		totalCount := tcpCount + udpCount

		// Skip processes with no connections
		if totalCount == 0 {
			continue
		}

		name, ok := pidNameCache.m[pid]
		if !ok {
			name = fmt.Sprintf("PID-%d", pid)
		}

		displayInfos = append(displayInfos, ProcessDisplayInfo{
			PID:         pid,
			ProcessName: name,
			TCPConns:    tcpCount,
			UDPConns:    udpCount,
			TotalConns:  totalCount,
		})
	}

	// Sort by total connections descending
	sort.Slice(displayInfos, func(i, j int) bool {
		return displayInfos[i].TotalConns > displayInfos[j].TotalConns
	})

	// Limit to top 20 processes
	if len(displayInfos) > 20 {
		displayInfos = displayInfos[:20]
	}

	return statsUpdatedMsg(displayInfos)
}

// --- Debug Functions ---

func showDebugStats() {
	tcpConns, err := getTcpConnections()
	if err != nil {
		fmt.Printf("Error getting TCP connections: %v\n", err)
		return
	}

	udpConns, err := getUdpConnections()
	if err != nil {
		fmt.Printf("Error getting UDP connections: %v\n", err)
		return
	}

	pidNameCache.RLock()
	defer pidNameCache.RUnlock()

	fmt.Println("\n=== Current Network Connections ===")

	// Combine all PIDs
	allPids := make(map[uint32]bool)
	for pid := range tcpConns {
		allPids[pid] = true
	}
	for pid := range udpConns {
		allPids[pid] = true
	}

	if len(allPids) == 0 {
		fmt.Println("No network connections detected")
		return
	}

	for pid := range allPids {
		name, ok := pidNameCache.m[pid]
		if !ok {
			name = fmt.Sprintf("PID-%d", pid)
		}

		tcpCount := tcpConns[pid]
		udpCount := udpConns[pid]
		fmt.Printf("PID %d (%s): TCP=%d, UDP=%d, Total=%d\n",
			pid, name, tcpCount, udpCount, tcpCount+udpCount)
	}
	fmt.Println("===================================")
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

func startNetworkMonitor() {
	log.Println("Starting network connection monitor...")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C
		// The actual monitoring happens in getNetworkStats()
		// which is called by the tick() function
	}
}

// --- Main ---

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
		// In debug mode, log to console
		log.SetOutput(os.Stdout)
	} else {
		// In normal environment, log to stderr
		log.SetOutput(os.Stderr)
	}

	log.Println("Starting gonet-top (Performance Counter version)...")

	if !isAdmin() {
		log.Println("Note: Some network information may be limited without administrator privileges.")
		fmt.Println("Note: Running without administrator privileges.")
		fmt.Println("Some network information may be limited. For full functionality, run as administrator.")
	} else {
		log.Println("Admin check passed")
	}

	if *debugMode {
		fmt.Println("Debug mode enabled - Network connections will be logged to console")
		fmt.Println("Press Ctrl+C to exit")

		// In debug mode, just show network stats periodically
		go startProcessNameWatcher()

		ticker := time.NewTicker(3 * time.Second)
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
		fmt.Println("Starting gonet-top... (Run with -debug flag to see connection logs)")
		time.Sleep(2 * time.Second)
		log.Println("Starting Bubble Tea program (interactive mode)...")
		p = tea.NewProgram(initialModel(), tea.WithAltScreen())
	}

	if _, err := p.Run(); err != nil {
		log.Fatalf("Error running program: %v", err)
	}
}
