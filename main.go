//go:build windows
// +build windows
package main
import (
    "flag"
    "fmt"
    "log"
    "os"
    "sort"
    "strconv"
    "strings"
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
    procGetProcessIoCounters = kernel32.NewProc("GetProcessIoCounters")
)
// TCP_TABLE_OWNER_PID_ALL constant
const TCP_TABLE_OWNER_PID_ALL = 5
const UDP_TABLE_OWNER_PID = 1
// TCP connection states
var tcpStates = map[uint32]string{
    1:  "CLOSED",
    2:  "LISTEN",
    3:  "SYN_SENT",
    4:  "SYN_RCVD",
    5:  "ESTABLISHED",
    6:  "FIN_WAIT1",
    7:  "FIN_WAIT2",
    8:  "CLOSE_WAIT",
    9:  "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB",
}
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
// IO_COUNTERS structure for I/O statistics
type IO_COUNTERS struct {
    ReadOperationCount  uint64
    WriteOperationCount uint64
    OtherOperationCount uint64
    ReadTransferCount   uint64
    WriteTransferCount  uint64
    OtherTransferCount  uint64
}
// --- Enhanced Data Structures ---
type NetworkConnection struct {
    Protocol    string
    LocalAddr   string
    LocalPort   uint16
    RemoteAddr  string
    RemotePort  uint16
    State       string
    PID         uint32
}
type ProcessNetDetails struct {
    PID                uint32
    ProcessName        string
    TCPConns           uint32
    UDPConns           uint32
    ListenPorts        []uint16
    EstablishedConns   uint32
    RemoteHosts        map[string]uint32 // IP -> count
    TopRemoteHost      string
    TopRemoteHostConns uint32
    BytesSent          uint64
    BytesReceived      uint64
    LastUpdate         time.Time
    Connections        []NetworkConnection
    // For tracking rates
    PrevBytesSent      uint64
    PrevBytesReceived  uint64
    PrevUpdate         time.Time
    UploadRate         float64 // bytes per second
    DownloadRate       float64 // bytes per second
}
// --- Admin Check ---
func isAdmin() bool {
    _, err := os.Open("\\\\.\\PHYSICALDRIVE0")
    return err == nil
}
var statsMap = struct {
    sync.RWMutex
    m map[uint32]*ProcessNetDetails
}{m: make(map[uint32]*ProcessNetDetails)}
var pidNameCache = struct {
    sync.RWMutex
    m map[uint32]string
}{m: make(map[uint32]string)}
// --- Enhanced Bubble Tea Model ---
type ProcessDisplayInfo struct {
    PID                uint32
    ProcessName        string
    TCPConns           uint32
    UDPConns           uint32
    TotalConns         uint32
    ListenPortsStr     string
    EstablishedConns   uint32
    TopRemoteHost      string
    TopRemoteHostConns uint32
    UploadRate         string // Formatted string
    DownloadRate       string // Formatted string
    TotalBytesSent     uint64
    TotalBytesReceived uint64
    Connections        []NetworkConnection
    UploadRateValue    float64 // For sorting
    DownloadRateValue  float64 // For sorting
}
type statsUpdatedMsg struct {
    processes []ProcessDisplayInfo
    sortBy    int
}
type model struct {
    processes   []ProcessDisplayInfo
    lastUpdate  time.Time
    selectedIdx int
    showDetails bool
    viewMode    int // 0: summary, 1: detailed, 2: connections view
    sortBy      int // 0: total connections, 1: upload rate, 2: download rate
}
func initialModel() model {
    return model{
        lastUpdate:  time.Now(),
        selectedIdx: 0,
        showDetails: false,
        viewMode:    0,
        sortBy:      0,
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
        case "up", "k":
            if m.selectedIdx > 0 {
                m.selectedIdx--
            }
        case "down", "j":
            if m.selectedIdx < len(m.processes)-1 {
                m.selectedIdx++
            }
        case "enter", " ":
            m.showDetails = !m.showDetails
        case "tab":
            m.viewMode = (m.viewMode + 1) % 3
        case "d":
            m.showDetails = !m.showDetails
        case "s":
            m.sortBy = (m.sortBy + 1) % 3
        }
    case statsUpdatedMsg:
        oldSelected := m.selectedIdx
        m.processes = msg.processes
        m.lastUpdate = time.Now()
        // Keep selection in bounds
        if oldSelected >= len(m.processes) && len(m.processes) > 0 {
            m.selectedIdx = len(m.processes) - 1
        } else if len(m.processes) == 0 {
            m.selectedIdx = 0
        } else {
            m.selectedIdx = oldSelected
        }
        return m, tick()
    }
    return m, nil
}
func (m model) View() string {
    var doc strings.Builder
    
    // Header - keep it simple
    doc.WriteString(fmt.Sprintf("gonet-top - Enhanced Network Monitor | Mode: %s | Sort: %s\n", m.getViewModeName(), m.getSortModeName()))
    doc.WriteString(fmt.Sprintf("Last updated: %s | Active processes: %d | Selected: %d\n\n", 
        m.lastUpdate.Format("15:04:05"), len(m.processes), m.selectedIdx+1))
    // Controls
    doc.WriteString("Controls: ↑/↓=navigate, Enter/d=details, Tab=view mode, s=sort, q=quit\n\n")
    if len(m.processes) == 0 {
        doc.WriteString("No network connections detected...\n")
        doc.WriteString("Try browsing the web or starting network applications.\n")
        return doc.String()
    }
    switch m.viewMode {
    case 0:
        return doc.String() + m.renderSummaryView()
    case 1:
        return doc.String() + m.renderDetailedView()
    case 2:
        return doc.String() + m.renderConnectionsView()
    default:
        return doc.String() + m.renderSummaryView()
    }
}
func (m model) getViewModeName() string {
    switch m.viewMode {
    case 0:
        return "Summary"
    case 1:
        return "Detailed"
    case 2:
        return "Connections"
    default:
        return "Unknown"
    }
}
func (m model) getSortModeName() string {
    switch m.sortBy {
    case 0:
        return "Connections"
    case 1:
        return "Upload"
    case 2:
        return "Download"
    default:
        return "Unknown"
    }
}
func (m model) renderSummaryView() string {
    var doc strings.Builder
    
    headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212")).Padding(0, 1)
    cellStyle := lipgloss.NewStyle().Padding(0, 1)
    selectedStyle := lipgloss.NewStyle().Background(lipgloss.Color("240")).Foreground(lipgloss.Color("15")).Padding(0, 1)
    headers := []string{"PID", "Process Name", "TCP", "UDP", "Total", "Upload", "Download"}
    headerRow := lipgloss.JoinHorizontal(lipgloss.Left,
        headerStyle.Copy().Width(8).Render(headers[0]),
        headerStyle.Copy().Width(16).Render(headers[1]),
        headerStyle.Copy().Width(6).Render(headers[2]),
        headerStyle.Copy().Width(6).Render(headers[3]),
        headerStyle.Copy().Width(6).Render(headers[4]),
        headerStyle.Copy().Width(10).Render(headers[5]),
        headerStyle.Copy().Width(10).Render(headers[6]),
    )
    doc.WriteString(headerRow + "\n")
    for i, p := range m.processes {
        style := cellStyle
        if i == m.selectedIdx {
            style = selectedStyle
        }
        row := lipgloss.JoinHorizontal(lipgloss.Left,
            style.Copy().Width(8).Render(fmt.Sprintf("%d", p.PID)),
            style.Copy().Width(16).Render(truncateString(p.ProcessName, 14)),
            style.Copy().Width(6).Render(fmt.Sprintf("%d", p.TCPConns)),
            style.Copy().Width(6).Render(fmt.Sprintf("%d", p.UDPConns)),
            style.Copy().Width(6).Render(fmt.Sprintf("%d", p.TotalConns)),
            style.Copy().Width(10).Render(p.UploadRate),
            style.Copy().Width(10).Render(p.DownloadRate),
        )
        doc.WriteString(row + "\n")
    }
    return doc.String()
}
func (m model) renderDetailedView() string {
    var doc strings.Builder
    
    headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212")).Padding(0, 1)
    cellStyle := lipgloss.NewStyle().Padding(0, 1)
    selectedStyle := lipgloss.NewStyle().Background(lipgloss.Color("240")).Foreground(lipgloss.Color("15")).Padding(0, 1)
    headers := []string{"PID", "Process", "TCP", "UDP", "EST", "Up/s", "Down/s"}
    headerRow := lipgloss.JoinHorizontal(lipgloss.Left,
        headerStyle.Copy().Width(8).Render(headers[0]),
        headerStyle.Copy().Width(12).Render(headers[1]),
        headerStyle.Copy().Width(5).Render(headers[2]),
        headerStyle.Copy().Width(5).Render(headers[3]),
        headerStyle.Copy().Width(5).Render(headers[4]),
        headerStyle.Copy().Width(10).Render(headers[5]),
        headerStyle.Copy().Width(10).Render(headers[6]),
    )
    doc.WriteString(headerRow + "\n")
    for i, p := range m.processes {
        style := cellStyle
        if i == m.selectedIdx {
            style = selectedStyle
        }
        row := lipgloss.JoinHorizontal(lipgloss.Left,
            style.Copy().Width(8).Render(fmt.Sprintf("%d", p.PID)),
            style.Copy().Width(12).Render(truncateString(p.ProcessName, 10)),
            style.Copy().Width(5).Render(fmt.Sprintf("%d", p.TCPConns)),
            style.Copy().Width(5).Render(fmt.Sprintf("%d", p.UDPConns)),
            style.Copy().Width(5).Render(fmt.Sprintf("%d", p.EstablishedConns)),
            style.Copy().Width(10).Render(p.UploadRate),
            style.Copy().Width(10).Render(p.DownloadRate),
        )
        doc.WriteString(row + "\n")
    }
    // Show details for selected process
    if m.showDetails && m.selectedIdx < len(m.processes) {
        selected := m.processes[m.selectedIdx]
        doc.WriteString("\n")
        detailStyle := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1).MarginTop(1)
        
        var details strings.Builder
        details.WriteString(fmt.Sprintf("Process Details: %s (PID %d)\n", selected.ProcessName, selected.PID))
        details.WriteString(fmt.Sprintf("TCP Connections: %d | UDP Connections: %d\n", selected.TCPConns, selected.UDPConns))
        details.WriteString(fmt.Sprintf("Established Connections: %d\n", selected.EstablishedConns))
        details.WriteString(fmt.Sprintf("Upload Rate: %s/s | Download Rate: %s/s\n", selected.UploadRate, selected.DownloadRate))
        details.WriteString(fmt.Sprintf("Total Bytes Sent: %s | Total Bytes Received: %s\n", 
            formatBytes(selected.TotalBytesSent), formatBytes(selected.TotalBytesReceived)))
        details.WriteString(fmt.Sprintf("Listen Ports: %s\n", selected.ListenPortsStr))
        if selected.TopRemoteHost != "" {
            details.WriteString(fmt.Sprintf("Top Remote Host: %s (%d connections)\n", selected.TopRemoteHost, selected.TopRemoteHostConns))
        }
        
        doc.WriteString(detailStyle.Render(details.String()))
    }
    return doc.String()
}
func (m model) renderConnectionsView() string {
    var doc strings.Builder
    
    if m.selectedIdx >= len(m.processes) {
        doc.WriteString("No process selected\n")
        return doc.String()
    }
    selected := m.processes[m.selectedIdx]
    
    titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
    doc.WriteString(titleStyle.Render(fmt.Sprintf("Active Connections for %s (PID %d)", selected.ProcessName, selected.PID)))
    doc.WriteString("\n\n")
    doc.WriteString(fmt.Sprintf("Upload: %s/s | Download: %s/s\n", selected.UploadRate, selected.DownloadRate))
    doc.WriteString(fmt.Sprintf("Total Sent: %s | Total Received: %s\n\n", 
        formatBytes(selected.TotalBytesSent), formatBytes(selected.TotalBytesReceived)))
    
    if len(selected.Connections) == 0 {
        doc.WriteString("No active connections found for this process.\n")
        return doc.String()
    }
    headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212")).Padding(0, 1)
    cellStyle := lipgloss.NewStyle().Padding(0, 1)
    headers := []string{"Protocol", "Local Address", "Remote Address", "State"}
    headerRow := lipgloss.JoinHorizontal(lipgloss.Left,
        headerStyle.Copy().Width(8).Render(headers[0]),
        headerStyle.Copy().Width(22).Render(headers[1]),
        headerStyle.Copy().Width(22).Render(headers[2]),
        headerStyle.Copy().Width(12).Render(headers[3]),
    )
    doc.WriteString(headerRow + "\n")
    for _, conn := range selected.Connections {
        localAddr := fmt.Sprintf("%s:%d", conn.LocalAddr, conn.LocalPort)
        remoteAddr := fmt.Sprintf("%s:%d", conn.RemoteAddr, conn.RemotePort)
        if conn.Protocol == "UDP" {
            remoteAddr = "*:*"
        }
        row := lipgloss.JoinHorizontal(lipgloss.Left,
            cellStyle.Copy().Width(8).Render(conn.Protocol),
            cellStyle.Copy().Width(22).Render(truncateString(localAddr, 20)),
            cellStyle.Copy().Width(22).Render(truncateString(remoteAddr, 20)),
            cellStyle.Copy().Width(12).Render(conn.State),
        )
        doc.WriteString(row + "\n")
    }
    return doc.String()
}
func truncateString(s string, maxLen int) string {
    if len(s) <= maxLen {
        return s
    }
    return s[:maxLen-3] + "..."
}
// Format bytes to human-readable string
func formatBytes(bytes uint64) string {
    const unit = 1024
    if bytes < unit {
        return fmt.Sprintf("%d B", bytes)
    }
    div, exp := uint64(unit), 0
    for n := bytes / unit; n >= unit; n /= unit {
        div *= unit
        exp++
    }
    return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
// Format bytes per second to human-readable string
func formatBytesPerSecond(bytesPerSec float64) string {
    if bytesPerSec < 1024 {
        return fmt.Sprintf("%.0f B", bytesPerSec)
    } else if bytesPerSec < 1024*1024 {
        return fmt.Sprintf("%.1f K", bytesPerSec/1024)
    } else if bytesPerSec < 1024*1024*1024 {
        return fmt.Sprintf("%.1f M", bytesPerSec/(1024*1024))
    } else {
        return fmt.Sprintf("%.1f G", bytesPerSec/(1024*1024*1024))
    }
}
// --- Ticker ---
func tick() tea.Cmd {
    return tea.Tick(time.Second*2, func(t time.Time) tea.Msg {
        // We need to get the current sort mode from the model
        // Since we can't access it directly, we'll pass 0 for now
        // and handle sorting in the Update method
        return getEnhancedNetworkStats(0)
    })
}
// --- Get Process I/O Counters ---
func getProcessIoCounters(pid uint32) (IO_COUNTERS, error) {
    var ioCounters IO_COUNTERS
    
    // Open the process
    handle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, pid)
    if err != nil {
        return ioCounters, err
    }
    defer syscall.CloseHandle(handle)
    
    // Get I/O counters
    ret, _, _ := procGetProcessIoCounters.Call(uintptr(handle), uintptr(unsafe.Pointer(&ioCounters)))
    if ret == 0 {
        return ioCounters, fmt.Errorf("GetProcessIoCounters failed")
    }
    
    return ioCounters, nil
}
// --- Enhanced Network Connection Monitoring ---
func getTcpConnections() (map[uint32]*ProcessNetDetails, []NetworkConnection, error) {
    processMap := make(map[uint32]*ProcessNetDetails)
    var allConnections []NetworkConnection
    // Get buffer size
    var bufSize uint32
    ret, _, _ := procGetTcpTable2.Call(0, uintptr(unsafe.Pointer(&bufSize)), 0, TCP_TABLE_OWNER_PID_ALL)
    if ret != 122 { // ERROR_INSUFFICIENT_BUFFER
        return nil, nil, fmt.Errorf("failed to get TCP table size: %d", ret)
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
        return nil, nil, fmt.Errorf("failed to get TCP table: %d", ret)
    }
    // Parse table
    table := (*MIB_TCPTABLE2)(unsafe.Pointer(&buf[0]))
    tableSlice := (*[1024 * 1024]MIB_TCPROW2)(unsafe.Pointer(&table.Table[0]))[:table.NumEntries:table.NumEntries]
    for _, row := range tableSlice {
        pid := row.OwningPid
        
        if processMap[pid] == nil {
            processMap[pid] = &ProcessNetDetails{
                PID:         pid,
                RemoteHosts: make(map[string]uint32),
                Connections: make([]NetworkConnection, 0),
            }
        }
        processMap[pid].TCPConns++
        // Convert addresses
        localIP := ipFromUint32(row.LocalAddr)
        remoteIP := ipFromUint32(row.RemoteAddr)
        localPort := portFromUint32(row.LocalPort)
        remotePort := portFromUint32(row.RemotePort)
        state, ok := tcpStates[row.State]
        if !ok {
            state = fmt.Sprintf("UNKNOWN(%d)", row.State)
        }
        // Count established connections
        if row.State == 5 { // ESTABLISHED
            processMap[pid].EstablishedConns++
            if remoteIP != "0.0.0.0" {
                processMap[pid].RemoteHosts[remoteIP]++
            }
        }
        // Count listening ports
        if row.State == 2 { // LISTEN
            processMap[pid].ListenPorts = append(processMap[pid].ListenPorts, localPort)
        }
        // Create connection record
        conn := NetworkConnection{
            Protocol:   "TCP",
            LocalAddr:  localIP,
            LocalPort:  localPort,
            RemoteAddr: remoteIP,
            RemotePort: remotePort,
            State:      state,
            PID:        pid,
        }
        processMap[pid].Connections = append(processMap[pid].Connections, conn)
        allConnections = append(allConnections, conn)
    }
    return processMap, allConnections, nil
}
func getUdpConnections() (map[uint32]*ProcessNetDetails, []NetworkConnection, error) {
    processMap := make(map[uint32]*ProcessNetDetails)
    var allConnections []NetworkConnection
    // Get buffer size
    var bufSize uint32
    ret, _, _ := procGetUdpTable.Call(0, uintptr(unsafe.Pointer(&bufSize)), 0, UDP_TABLE_OWNER_PID)
    if ret != 122 { // ERROR_INSUFFICIENT_BUFFER
        return nil, nil, fmt.Errorf("failed to get UDP table size: %d", ret)
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
        return nil, nil, fmt.Errorf("failed to get UDP table: %d", ret)
    }
    // Parse table
    table := (*MIB_UDPTABLE_OWNER_PID)(unsafe.Pointer(&buf[0]))
    tableSlice := (*[1024 * 1024]MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&table.Table[0]))[:table.NumEntries:table.NumEntries]
    for _, row := range tableSlice {
        pid := row.OwningPid
        
        if processMap[pid] == nil {
            processMap[pid] = &ProcessNetDetails{
                PID:         pid,
                RemoteHosts: make(map[string]uint32),
                Connections: make([]NetworkConnection, 0),
            }
        }
        processMap[pid].UDPConns++
        // Convert addresses
        localIP := ipFromUint32(row.LocalAddr)
        localPort := portFromUint32(row.LocalPort)
        // UDP listening port
        processMap[pid].ListenPorts = append(processMap[pid].ListenPorts, localPort)
        // Create connection record
        conn := NetworkConnection{
            Protocol:   "UDP",
            LocalAddr:  localIP,
            LocalPort:  localPort,
            RemoteAddr: "*",
            RemotePort: 0,
            State:      "LISTEN",
            PID:        pid,
        }
        processMap[pid].Connections = append(processMap[pid].Connections, conn)
        allConnections = append(allConnections, conn)
    }
    return processMap, allConnections, nil
}
func ipFromUint32(addr uint32) string {
    return fmt.Sprintf("%d.%d.%d.%d",
        addr&0xFF,
        (addr>>8)&0xFF,
        (addr>>16)&0xFF,
        (addr>>24)&0xFF)
}
func portFromUint32(port uint32) uint16 {
    return uint16((port&0xFF)<<8 | (port>>8)&0xFF)
}
func getEnhancedNetworkStats(sortBy int) statsUpdatedMsg {
    tcpProcessMap, _, err := getTcpConnections()
    if err != nil {
        log.Printf("Error getting TCP connections: %v", err)
        tcpProcessMap = make(map[uint32]*ProcessNetDetails)
    }
    udpProcessMap, _, err := getUdpConnections()
    if err != nil {
        log.Printf("Error getting UDP connections: %v", err)
        udpProcessMap = make(map[uint32]*ProcessNetDetails)
    }
    // Combine all PIDs
    allPids := make(map[uint32]bool)
    for pid := range tcpProcessMap {
        allPids[pid] = true
    }
    for pid := range udpProcessMap {
        allPids[pid] = true
    }
    pidNameCache.RLock()
    defer pidNameCache.RUnlock()
    var displayInfos []ProcessDisplayInfo
    now := time.Now()
    
    // Get previous stats for rate calculation
    statsMap.RLock()
    for pid := range allPids {
        var details ProcessNetDetails
        var connections []NetworkConnection
        
        // Merge TCP and UDP data
        if tcpData, ok := tcpProcessMap[pid]; ok {
            details = *tcpData
            connections = append(connections, tcpData.Connections...)
        }
        if udpData, ok := udpProcessMap[pid]; ok {
            details.UDPConns = udpData.UDPConns
            details.ListenPorts = append(details.ListenPorts, udpData.ListenPorts...)
            connections = append(connections, udpData.Connections...)
        }
        
        totalCount := details.TCPConns + details.UDPConns
        // Skip processes with no connections
        if totalCount == 0 {
            continue
        }
        
        name, ok := pidNameCache.m[pid]
        if !ok {
            name = fmt.Sprintf("PID-%d", pid)
        }
        
        // Find top remote host
        var topRemoteHost string
        var topRemoteHostConns uint32
        for ip, count := range details.RemoteHosts {
            if count > topRemoteHostConns {
                topRemoteHost = ip
                topRemoteHostConns = count
            }
        }
        
        // Format listening ports
        listenPortsStr := formatPorts(details.ListenPorts)
        
        // Get I/O counters for this process
        ioCounters, err := getProcessIoCounters(pid)
        if err != nil {
            log.Printf("Error getting I/O counters for PID %d: %v", pid, err)
        }
        
        // Calculate rates if we have previous data
        var uploadRate, downloadRate float64
        if prevDetails, ok := statsMap.m[pid]; ok {
            timeDiff := now.Sub(prevDetails.PrevUpdate).Seconds()
            if timeDiff > 0 {
                uploadRate = float64(ioCounters.WriteTransferCount-prevDetails.PrevBytesSent) / timeDiff
                downloadRate = float64(ioCounters.ReadTransferCount-prevDetails.PrevBytesReceived) / timeDiff
            }
        }
        
        displayInfos = append(displayInfos, ProcessDisplayInfo{
            PID:                pid,
            ProcessName:        name,
            TCPConns:           details.TCPConns,
            UDPConns:           details.UDPConns,
            TotalConns:         totalCount,
            ListenPortsStr:     listenPortsStr,
            EstablishedConns:   details.EstablishedConns,
            TopRemoteHost:      topRemoteHost,
            TopRemoteHostConns: topRemoteHostConns,
            UploadRate:         formatBytesPerSecond(uploadRate),
            DownloadRate:       formatBytesPerSecond(downloadRate),
            TotalBytesSent:     ioCounters.WriteTransferCount,
            TotalBytesReceived: ioCounters.ReadTransferCount,
            Connections:        connections,
            UploadRateValue:    uploadRate,
            DownloadRateValue:  downloadRate,
        })
        
        // Update the stats map with current values for next calculation
        details.BytesSent = ioCounters.WriteTransferCount
        details.BytesReceived = ioCounters.ReadTransferCount
        details.PrevBytesSent = ioCounters.WriteTransferCount
        details.PrevBytesReceived = ioCounters.ReadTransferCount
        details.PrevUpdate = now
        details.LastUpdate = now
        details.UploadRate = uploadRate
        details.DownloadRate = downloadRate
        
        statsMap.m[pid] = &details
    }
    statsMap.RUnlock()
    
    // Sort based on current sort mode
    switch sortBy {
    case 1: // Sort by upload rate
        sort.Slice(displayInfos, func(i, j int) bool {
            return displayInfos[i].UploadRateValue > displayInfos[j].UploadRateValue
        })
    case 2: // Sort by download rate
        sort.Slice(displayInfos, func(i, j int) bool {
            return displayInfos[i].DownloadRateValue > displayInfos[j].DownloadRateValue
        })
    default: // Sort by total connections
        sort.Slice(displayInfos, func(i, j int) bool {
            return displayInfos[i].TotalConns > displayInfos[j].TotalConns
        })
    }
    
    // Limit to top 50 processes to avoid overwhelming display
    if len(displayInfos) > 50 {
        displayInfos = displayInfos[:50]
    }
    
    return statsUpdatedMsg{
        processes: displayInfos,
        sortBy:    sortBy,
    }
}
func formatPorts(ports []uint16) string {
    if len(ports) == 0 {
        return "-"
    }
    // Remove duplicates and sort
    portMap := make(map[uint16]bool)
    for _, port := range ports {
        portMap[port] = true
    }
    var uniquePorts []uint16
    for port := range portMap {
        uniquePorts = append(uniquePorts, port)
    }
    sort.Slice(uniquePorts, func(i, j int) bool {
        return uniquePorts[i] < uniquePorts[j]
    })
    // Format as string, limit to prevent overflow
    var portStrs []string
    maxPorts := 5 // Show max 5 ports
    for i, port := range uniquePorts {
        if i >= maxPorts {
            portStrs = append(portStrs, "...")
            break
        }
        portStrs = append(portStrs, strconv.Itoa(int(port)))
    }
    return strings.Join(portStrs, ",")
}
// --- Debug Functions ---
func showDebugStats() {
    tcpProcessMap, _, err := getTcpConnections()
    if err != nil {
        fmt.Printf("Error getting TCP connections: %v\n", err)
        return
    }
    udpProcessMap, _, err := getUdpConnections()
    if err != nil {
        fmt.Printf("Error getting UDP connections: %v\n", err)
        return
    }
    pidNameCache.RLock()
    defer pidNameCache.RUnlock()
    fmt.Println("\n=== Enhanced Network Connections ===")
    // Combine all PIDs
    allPids := make(map[uint32]bool)
    for pid := range tcpProcessMap {
        allPids[pid] = true
    }
    for pid := range udpProcessMap {
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
        var tcpCount, udpCount, establishedCount uint32
        var listenPorts []uint16
        var topRemote string
        var topRemoteCount uint32
        
        if tcpData, ok := tcpProcessMap[pid]; ok {
            tcpCount = tcpData.TCPConns
            establishedCount = tcpData.EstablishedConns
            listenPorts = append(listenPorts, tcpData.ListenPorts...)
            
            for ip, count := range tcpData.RemoteHosts {
                if count > topRemoteCount {
                    topRemote = ip
                    topRemoteCount = count
                }
            }
        }
        
        if udpData, ok := udpProcessMap[pid]; ok {
            udpCount = udpData.UDPConns
            listenPorts = append(listenPorts, udpData.ListenPorts...)
        }
        
        // Get I/O counters
        ioCounters, err := getProcessIoCounters(pid)
        var uploadStr, downloadStr string
        if err == nil {
            uploadStr = formatBytes(ioCounters.WriteTransferCount)
            downloadStr = formatBytes(ioCounters.ReadTransferCount)
        } else {
            uploadStr = "N/A"
            downloadStr = "N/A"
        }
        
        fmt.Printf("PID %d (%s):\n", pid, name)
        fmt.Printf("  TCP=%d, UDP=%d, Established=%d\n", tcpCount, udpCount, establishedCount)
        fmt.Printf("  Upload: %s, Download: %s\n", uploadStr, downloadStr)
        fmt.Printf("  Listen ports: %s\n", formatPorts(listenPorts))
        if topRemote != "" {
            fmt.Printf("  Top remote: %s (%d conns)\n", topRemote, topRemoteCount)
        }
        fmt.Println()
    }
    fmt.Println("=====================================")
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
    log.Println("Starting enhanced network connection monitor...")
    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()
    for {
        <-ticker.C
        // The actual monitoring happens in getEnhancedNetworkStats()
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
    log.Println("Starting gonet-top (Enhanced version)...")
    if !isAdmin() {
        log.Println("Note: Some network information may be limited without administrator privileges.")
        fmt.Println("Note: Running without administrator privileges.")
        fmt.Println("Some network information may be limited. For full functionality, run as administrator.")
    } else {
        log.Println("Admin check passed")
    }
    if *debugMode {
        fmt.Println("Enhanced Debug mode enabled - Detailed network connections will be logged to console")
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
        log.Println("Starting Enhanced Bubble Tea program (CI mode)...")
        p = tea.NewProgram(initialModel(), tea.WithOutput(tuiLogFile), tea.WithAltScreen())
    } else {
        // In normal environment, use standard terminal
        fmt.Println("Starting enhanced gonet-top...")
        fmt.Println("Features:")
        fmt.Println("- Summary view: Basic connection counts and network I/O rates")
        fmt.Println("- Detailed view: Shows established connections and top remote hosts")
        fmt.Println("- Connections view: Lists all active connections for selected process")
        fmt.Println("- Press 's' to change sorting method (connections, upload, download)")
        fmt.Println("- Use Tab to switch between views, Arrow keys to navigate")
        fmt.Println("- Press Enter or 'd' to toggle process details")
        fmt.Println("\nStarting in 3 seconds...")
        time.Sleep(3 * time.Second)
        log.Println("Starting Enhanced Bubble Tea program (interactive mode)...")
        p = tea.NewProgram(initialModel(), tea.WithAltScreen())
    }
    if _, err := p.Run(); err != nil {
        log.Fatalf("Error running program: %v", err)
    }
}
