package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ==========================================
// Server URL is read from the AGENT_SERVER_URL environment variable.
func agentEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var ServerBaseURL = agentEnv("AGENT_SERVER_URL", "http://127.0.0.1:8000/api/v1/agents")
const PollInterval = 3 * time.Second
// ==========================================

const (
	TH32CS_SNAPPROCESS        = 0x00000002
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ           = 0x0010
)

type PROCESSENTRY32W struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [260]uint16
}

type PROCESS_MEMORY_COUNTERS struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

type MemoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

type RegisterPayload struct {
	Hostname     string `json:"hostname"`
	OSName       string `json:"os_name"`
	OSVersion    string `json:"os_version"`
	Architecture string `json:"architecture"`
	AgentVersion string `json:"agent_version"`
	IPAddress    string `json:"ip_address"`
	LoggedInUser string `json:"logged_in_user"`
}

type ProcessInfo struct {
	PID           int     `json:"pid"`
	Name          string  `json:"name"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	Status        string  `json:"status"`
}

type MetricsPayload struct {
	AgentID      string        `json:"agent_id"`
	LoggedInUser string        `json:"logged_in_user"`
	CPUPercent   float64       `json:"cpu_percent"`
	RAMPercent   float64       `json:"ram_percent"`
	RAMUsedGB    float64       `json:"ram_used_gb"`
	RAMTotalGB   float64       `json:"ram_total_gb"`
	DiskPercent  float64       `json:"disk_percent"`
	DiskUsedGB   float64       `json:"disk_used_gb"`
	DiskTotalGB  float64       `json:"disk_total_gb"`
	BytesSent    float64       `json:"bytes_sent"`
	BytesRecv    float64       `json:"bytes_recv"`
	PacketsSent  int           `json:"packets_sent"`
	PacketsRecv  int           `json:"packets_recv"`
	TopProcesses []ProcessInfo `json:"top_processes"`
}

type ServerResponse struct {
	AgentID         string `json:"agent_id"`
	MachineStatus   string `json:"machine_status"`
	PendingCommands []struct {
		CommandID int                    `json:"command_id"`
		Type      string                 `json:"type"`
		Payload   map[string]interface{} `json:"payload"`
	} `json:"pending_commands"`
}

type ProcTimeRecord struct {
	TotalTime int64
	Timestamp time.Time
}

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	psapi                        = syscall.NewLazyDLL("psapi.dll")
	procGlobalMemoryStatus        = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemTimes            = kernel32.NewProc("GetSystemTimes")
	procGetDiskFreeSpace          = kernel32.NewProc("GetDiskFreeSpaceExW")
	procCreateToolhelp32Snapshot  = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW           = kernel32.NewProc("Process32FirstW")
	procProcess32NextW            = kernel32.NewProc("Process32NextW")
	procOpenProcess               = kernel32.NewProc("OpenProcess")
	procGetProcessMemoryInfo      = psapi.NewProc("GetProcessMemoryInfo")
	procGetProcessTimes           = kernel32.NewProc("GetProcessTimes")

	prevIdleTime   int64
	prevKernelTime int64
	prevUserTime   int64
	procTimeCache  = make(map[uint32]ProcTimeRecord)
)

func fileTimeToNano(ft syscall.Filetime) int64 {
	return int64(ft.HighDateTime)<<32 + int64(ft.LowDateTime)
}

func getWinCPUUsage() float64 {
	var idleTime, kernelTime, userTime syscall.Filetime
	r, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idleTime)),
		uintptr(unsafe.Pointer(&kernelTime)),
		uintptr(unsafe.Pointer(&userTime)),
	)
	if r == 0 {
		return 0.0
	}

	idle := fileTimeToNano(idleTime)
	kernel := fileTimeToNano(kernelTime)
	user := fileTimeToNano(userTime)

	if prevIdleTime == 0 {
		prevIdleTime = idle
		prevKernelTime = kernel
		prevUserTime = user
		return 0.0
	}

	idleDelta := idle - prevIdleTime
	totalDelta := (kernel - prevKernelTime) + (user - prevUserTime)

	prevIdleTime = idle
	prevKernelTime = kernel
	prevUserTime = user

	if totalDelta <= 0 {
		return 0.0
	}

	cpuPercent := (1.0 - (float64(idleDelta) / float64(totalDelta))) * 100.0
	if cpuPercent < 0 {
		cpuPercent = 0
	}
	if cpuPercent > 100 {
		cpuPercent = 100
	}
	return float64(int(cpuPercent*10)) / 10
}

func getWinMemory() (float64, float64, float64, uint64) {
	var mem MemoryStatusEx
	mem.Length = uint32(unsafe.Sizeof(mem))
	r, _, _ := procGlobalMemoryStatus.Call(uintptr(unsafe.Pointer(&mem)))
	if r == 0 {
		return 0, 0, 0, 1
	}

	totalGB := float64(mem.TotalPhys) / (1024 * 1024 * 1024)
	availGB := float64(mem.AvailPhys) / (1024 * 1024 * 1024)
	usedGB := totalGB - availGB
	percent := (usedGB / totalGB) * 100.0

	return float64(int(percent*10)) / 10, float64(int(usedGB*100)) / 100, float64(int(totalGB*100)) / 100, mem.TotalPhys
}

func getWinDisk() (float64, float64, float64) {
	drivePtr, _ := syscall.UTF16PtrFromString("C:\\")
	var freeBytes, totalBytes, totalFreeBytes int64
	r, _, _ := procGetDiskFreeSpace.Call(
		uintptr(unsafe.Pointer(drivePtr)),
		uintptr(unsafe.Pointer(&freeBytes)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)
	if r == 0 {
		return 0, 0, 0
	}

	totalGB := float64(totalBytes) / (1024 * 1024 * 1024)
	freeGB := float64(freeBytes) / (1024 * 1024 * 1024)
	usedGB := totalGB - freeGB
	percent := (usedGB / totalGB) * 100.0

	return float64(int(percent*10)) / 10, float64(int(usedGB*100)) / 100, float64(int(totalGB*100)) / 100
}

func getProcessCPUAndRAM(pid uint32, totalPhysMem uint64, numCPU int) (float64, float64) {
	hProc, _, _ := procOpenProcess.Call(
		uintptr(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ),
		uintptr(0),
		uintptr(pid),
	)
	if hProc == 0 {
		return 0.0, 0.1
	}
	defer syscall.CloseHandle(syscall.Handle(hProc))

	// 1. RAM Measurement
	var memCounters PROCESS_MEMORY_COUNTERS
	memCounters.CB = uint32(unsafe.Sizeof(memCounters))
	var memPct float64 = 0.1
	rMem, _, _ := procGetProcessMemoryInfo.Call(
		hProc,
		uintptr(unsafe.Pointer(&memCounters)),
		uintptr(memCounters.CB),
	)
	if rMem != 0 && totalPhysMem > 0 {
		memPct = (float64(memCounters.WorkingSetSize) / float64(totalPhysMem)) * 100.0
		memPct = float64(int(memPct*10)) / 10
	}

	// 2. Real Windows Task Manager Process CPU calculation
	var creationTime, exitTime, kernelTime, userTime syscall.Filetime
	var cpuPct float64 = 0.0
	rTimes, _, _ := procGetProcessTimes.Call(
		hProc,
		uintptr(unsafe.Pointer(&creationTime)),
		uintptr(unsafe.Pointer(&exitTime)),
		uintptr(unsafe.Pointer(&kernelTime)),
		uintptr(unsafe.Pointer(&userTime)),
	)

	if rTimes != 0 {
		totalProcTime := fileTimeToNano(kernelTime) + fileTimeToNano(userTime)
		now := time.Now()

		if prev, exists := procTimeCache[pid]; exists {
			procDelta := totalProcTime - prev.TotalTime
			timeDelta := now.Sub(prev.Timestamp).Nanoseconds() / 100 // 100ns units

			if timeDelta > 0 && numCPU > 0 {
				raw := (float64(procDelta) / float64(timeDelta*int64(numCPU))) * 100.0
				if raw > 0.0 {
					cpuPct = float64(int(raw*10)) / 10
					if cpuPct > 100.0 {
						cpuPct = 100.0
					}
				}
			}
		}
		procTimeCache[pid] = ProcTimeRecord{TotalTime: totalProcTime, Timestamp: now}
	}

	return cpuPct, memPct
}

func getWinRealtimeProcesses(totalPhysMem uint64) []ProcessInfo {
	handle, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPPROCESS), uintptr(0))
	if handle == uintptr(syscall.InvalidHandle) {
		return []ProcessInfo{}
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	var entry PROCESSENTRY32W
	entry.Size = uint32(unsafe.Sizeof(entry))
	numCPU := runtime.NumCPU()

	var procs []ProcessInfo
	r, _, _ := procProcess32FirstW.Call(handle, uintptr(unsafe.Pointer(&entry)))

	for r != 0 {
		pid := uint32(entry.ProcessID)
		if pid > 4 {
			name := syscall.UTF16ToString(entry.ExeFile[:])
			cpuPct, memPct := getProcessCPUAndRAM(pid, totalPhysMem, numCPU)

			status := "running"
			if cpuPct > 20.0 {
				status = "HIGH_CPU"
			} else if memPct > 10.0 {
				status = "HIGH_RAM"
			}

			procs = append(procs, ProcessInfo{
				PID:           int(pid),
				Name:          name,
				CPUPercent:    cpuPct,
				MemoryPercent: memPct,
				Status:        status,
			})
		}
		r, _, _ = procProcess32NextW.Call(handle, uintptr(unsafe.Pointer(&entry)))
	}

	// Sort dynamically by CPU usage first, then RAM
	sort.Slice(procs, func(i, j int) bool {
		if procs[i].CPUPercent != procs[j].CPUPercent {
			return procs[i].CPUPercent > procs[j].CPUPercent
		}
		return procs[i].MemoryPercent > procs[j].MemoryPercent
	})

	if len(procs) > 50 {
		return procs[:50]
	}
	return procs
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func getActiveUser() string {
	u, err := user.Current()
	if err == nil && u.Username != "" {
		parts := strings.Split(u.Username, "\\")
		return parts[len(parts)-1]
	}
	return os.Getenv("USERNAME")
}

func executeCommand(client *http.Client, agentID string, cmdID int, cmdType string, payload map[string]interface{}) {
	var output string
	status := "COMPLETED"

	if cmdType == "EXECUTE_SHELL" {
		cmdStr, _ := payload["command_str"].(string)
		out, err := exec.Command("powershell", "-NoProfile", "-Command", cmdStr).CombinedOutput()
		if err != nil {
			status = "FAILED"
			output = fmt.Sprintf("Error: %v\n%s", err, string(out))
		} else {
			output = string(out)
			if strings.TrimSpace(output) == "" {
				output = "Command executed successfully (no stdout returned)."
			}
		}
	} else if cmdType == "KILL_PROCESS" {
		pidFloat, _ := payload["pid"].(float64)
		pid := int(pidFloat)
		err := exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", pid)).Run()
		if err != nil {
			status = "FAILED"
			output = fmt.Sprintf("Failed to kill PID %d: %v", pid, err)
		} else {
			output = fmt.Sprintf("Successfully killed Process Tree for PID %d", pid)
		}
	} else if cmdType == "REBOOT_SYSTEM" {
		exec.Command("shutdown", "/r", "/t", "10", "/c", "Remote Reboot via AI-ITMonitor").Run()
		output = "Reboot scheduled in 10 seconds."
	}

	resultBody, _ := json.Marshal(map[string]interface{}{
		"agent_id":   agentID,
		"command_id": cmdID,
		"status":     status,
		"output":     output,
	})
	client.Post(ServerBaseURL+"/command-result", "application/json", bytes.NewBuffer(resultBody))
}

func main() {
	fmt.Println("==================================================")
	fmt.Println(" AI-ITMonitor Enterprise Go Agent (TaskMgr Sync) ")
	fmt.Println(" Platform: Windows Kernel Precision Engine       ")
	fmt.Printf(" Server Target: %s\n", ServerBaseURL)
	fmt.Printf(" Active User:   %s\n", getActiveUser())
	fmt.Println("==================================================")

	client := &http.Client{Timeout: 5 * time.Second}
	hostname, _ := os.Hostname()
	ip := getLocalIP()
	activeUser := getActiveUser()

	regPayload := RegisterPayload{
		Hostname:     hostname,
		OSName:       "Windows",
		OSVersion:    "10/11",
		Architecture: runtime.GOARCH,
		AgentVersion: "3.5.0-taskmgr-sync",
		IPAddress:    ip,
		LoggedInUser: activeUser,
	}

	data, _ := json.Marshal(regPayload)
	resp, err := client.Post(ServerBaseURL+"/register", "application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Printf("[-] Failed to register: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var regResp ServerResponse
	json.NewDecoder(resp.Body).Decode(&regResp)
	agentID := regResp.AgentID
	fmt.Printf("[+] Agent Registered! ID: %s\n", agentID)

	// Prime initial process times in memory
	_, _, _, totalPhysInit := getWinMemory()
	getWinRealtimeProcesses(totalPhysInit)
	time.Sleep(1 * time.Second)

	for {
		cpu := getWinCPUUsage()
		ramPct, ramUsed, ramTotal, totalPhys := getWinMemory()
		diskPct, diskUsed, diskTotal := getWinDisk()
		procs := getWinRealtimeProcesses(totalPhys)

		metrics := MetricsPayload{
			AgentID:      agentID,
			LoggedInUser: activeUser,
			CPUPercent:   cpu,
			RAMPercent:   ramPct,
			RAMUsedGB:    ramUsed,
			RAMTotalGB:   ramTotal,
			DiskPercent:  diskPct,
			DiskUsedGB:   diskUsed,
			DiskTotalGB:  diskTotal,
			TopProcesses: procs,
		}

		mBody, _ := json.Marshal(metrics)
		postResp, err := client.Post(ServerBaseURL+"/metrics", "application/json", bytes.NewBuffer(mBody))
		if err == nil {
			var sResp ServerResponse
			json.NewDecoder(postResp.Body).Decode(&sResp)
			postResp.Body.Close()

			for _, cmd := range sResp.PendingCommands {
				executeCommand(client, agentID, cmd.CommandID, cmd.Type, cmd.Payload)
			}
			topName := "None"
			topCPU := 0.0
			topRAM := 0.0
			if len(procs) > 0 {
				topName = procs[0].Name
				topCPU = procs[0].CPUPercent
				topRAM = procs[0].MemoryPercent
			}
			fmt.Printf("[Live Stream] Global CPU: %.1f%% | RAM: %.1f%% | Top: %s (CPU: %.1f%%, RAM: %.1f%%) | User: %s\n", cpu, ramPct, topName, topCPU, topRAM, activeUser)
		} else {
			fmt.Printf("[!] Transmission error: %v\n", err)
		}

		time.Sleep(PollInterval)
	}
}
