//go:build windows
// +build windows

package main

import (
	"context"
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

var previousStats = make(map[uint32]ProcessNetStats)
var previousStatsLock sync.RWMutex

var pidNameCache = struct {
	sync.RWMutex
	m map[uint32]string
}{m: make(map[uint32]string)}

// --- Bubble Tea Model ---

const (
	colPID = iota
	colName
	colSend
	colRecv
	colTotal
)

const displayLimit = 25 // Limit the number of processes shown

type ProcessDisplayInfo struct {
	PID         uint32
	ProcessName string
	SendSpeed   string
	RecvSpeed   string
	TotalBytes  uint64
	SendBps     uint64
	RecvBps     uint64
}

type statsUpdatedMsg []ProcessDisplayInfo

type model struct {
	processes  []ProcessDisplayInfo
	sortColumn int
	sortAsc    bool
	noData     bool
}

func initialModel() model {
	return model{
		sortColumn: colTotal, // Default to sorting by total activity
		sortAsc:    false,    // Descending
		noData:     true,
	}
}

func (m model) Init() tea.Cmd {
	go startEtwConsumer()
	go startProcessNameWatcher()
	return tick()
}

func (m *model) setSortColumn(col int) {
	if m.sortColumn == col {
		m.sortAsc = !m.sortAsc
	} else {
		m.sortColumn = col
		if col == colPID || col == colName {
			m.sortAsc = true
		} else {
			m.sortAsc = false
		}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "p":
			m.setSortColumn(colPID)
		case "n":
			m.setSortColumn(colName)
		case "s":
			m.setSortColumn(colSend)
		case "r":
			m.setSortColumn(colRecv)
		case "t":
			m.setSortColumn(colTotal)
		}
	case statsUpdatedMsg:
		m.processes = msg
		m.noData = len(msg) == 0

		// Sort the processes
		sort.Slice(m.processes, func(i, j int) bool {
			p1 := m.processes[i]
			p2 := m.processes[j]
			var less bool
			switch m.sortColumn {
			case colPID:
				less = p1.PID < p2.PID
			case colName:
				less = p1.ProcessName < p2.ProcessName
			case colSend:
				less = p1.SendBps < p2.SendBps
			case colRecv:
				less = p1.RecvBps < p2.RecvBps
			case colTotal:
				less = p1.TotalBytes < p2.TotalBytes
			}
			if !m.sortAsc {
				return !less
			}
			return less
		})

		// Limit the number of processes shown
		if len(m.processes) > displayLimit {
			m.processes = m.processes[:displayLimit]
		}

		return m, tick()
	}
	return m, nil
}

func (m model) View() string {
	var b strings.Builder
	b.WriteString("gonet-top - Real-time network usage by process\n\n")

	if m.noData {
		b.WriteString("Waiting for network activity...")
		return b.String()
	}

	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212")).Padding(0, 1)
	renderHeader := func(name string, col int) string {
		if m.sortColumn == col {
			if m.sortAsc {
				name += " ▴"
			} else {
				name += " ▾"
			}
		}
		return headerStyle.Render(name)
	}

	headers := []string{"PID", "Process Name", "Send Speed", "Recv Speed", "Total"}
	headerRow := lipgloss.JoinHorizontal(lipgloss.Left,
		lipgloss.NewStyle().Width(10).Render(renderHeader(headers[0], colPID)),
		lipgloss.NewStyle().Width(25).Render(renderHeader(headers[1], colName)),
		lipgloss.NewStyle().Width(15).Render(renderHeader(headers[2], colSend)),
		lipgloss.NewStyle().Width(15).Render(renderHeader(headers[3], colRecv)),
		lipgloss.NewStyle().Width(15).Render(renderHeader(headers[4], colTotal)),
	)
	b.WriteString(headerRow + "\n")

	cellStyle := lipgloss.NewStyle().Padding(0, 1)
	for _, p := range m.processes {
		pidStr := fmt.Sprintf("%d", p.PID)
		totalStr := formatBytes(p.TotalBytes)
		row := lipgloss.JoinHorizontal(lipgloss.Left,
			cellStyle.Copy().Width(10).Render(pidStr),
			cellStyle.Copy().Width(25).Render(p.ProcessName),
			cellStyle.Copy().Width(15).Render(p.SendSpeed),
			cellStyle.Copy().Width(15).Render(p.RecvSpeed),
			cellStyle.Copy().Width(15).Render(totalStr),
		)
		b.WriteString(row + "\n")
	}

	helpText := "\n  Sort by: (p)id (n)ame (s)end (r)ecv (t)otal | (q)uit"
	b.WriteString(helpText)

	return b.String()
}

// --- Ticker and Data Calculation ---

func tick() tea.Cmd {
	return tea.Tick(time.Second*1, func(t time.Time) tea.Msg {
		return calculateRates()
	})
}

func calculateRates() statsUpdatedMsg {
	var displayInfos []ProcessDisplayInfo
	statsMap.RLock()
	currentStats := make(map[uint32]ProcessNetStats, len(statsMap.m))
	for pid, stats := range statsMap.m {
		currentStats[pid] = *stats
	}
	statsMap.RUnlock()
	pidNameCache.RLock()
	defer pidNameCache.RUnlock()
	previousStatsLock.Lock()
	defer previousStatsLock.Unlock()

	for pid, current := range currentStats {
		prev, ok := previousStats[pid]
		if !ok {
			prev = ProcessNetStats{PID: pid}
		}
		sendBps := current.SentBytes - prev.SentBytes
		recvBps := current.RecvBytes - prev.RecvBytes
		name, nameOk := pidNameCache.m[pid]
		if !nameOk {
			name = "N/A"
		}
		displayInfos = append(displayInfos, ProcessDisplayInfo{
			PID:         pid,
			ProcessName: name,
			SendSpeed:   formatSpeed(sendBps),
			RecvSpeed:   formatSpeed(recvBps),
			SendBps:     sendBps,
			RecvBps:     recvBps,
			TotalBytes:  current.SentBytes + current.RecvBytes,
		})
	}
	previousStats = currentStats
	return statsUpdatedMsg(displayInfos)
}

func formatSpeed(bytes uint64) string {
	return formatBytes(bytes) + "/s"
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
	return fmt.Sprintf("%.2f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
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
	}
	update()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		<-ticker.C
		update()
	}
}

// --- Main and ETW Logic ---

func main() {
	logFile, err := os.OpenFile("app.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		os.Exit(1)
	}
	log.SetOutput(logFile)
	if !isAdmin() {
		log.Println("Error: Administrator privileges are required.")
		fmt.Println("Error: Administrator privileges are required.")
		fmt.Println("Please restart the application from a terminal with 'Run as administrator'.")
		return
	}
	tuiLogFile, err := os.OpenFile("tui.log", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatalf("Failed to open TUI log file: %v", err)
	}
	defer tuiLogFile.Close()
	p := tea.NewProgram(&model{}, tea.WithOutput(tuiLogFile), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatalf("Alas, there's been an error: %v", err)
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
			log.Printf("Received event with Opcode: %d", e.System.Opcode.Value)
			opcode := e.System.Opcode.Value
			isSend := opcode == opcodeTCPSend || opcode == opcodeUDPSend
			isRecv := opcode == opcodeTCPReceive || opcode == opcodeUDPReceive
			if !isSend && !isRecv {
				continue
			}
			pid := e.System.Execution.ProcessID
			if pid == 0 {
				continue
			}
			var size uint64
			sizeVal, ok := e.GetProperty("size")
			if !ok {
				sizeVal, ok = e.GetProperty("datalen")
			}
			if !ok {
				log.Printf("Skipping event, no size field found.")
				continue
			}
			switch s := sizeVal.(type) {
			case uint16:
				size = uint64(s)
			case uint32:
				size = uint64(s)
			case uint64:
				size = s
			default:
				log.Printf("Skipping event, unsupported type for size: %T", s)
				continue
			}
			log.Printf("Successfully parsed event for PID %d with size %d", pid, size)
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
