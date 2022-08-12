# goAssembly
Based on the Execute Assembly implementation from [https://github.com/BishopFox/sliver](https://github.com/BishopFox/sliver).  
This is a proof of concept, attempting to execute the assembly in the current process vs the current fork and run method.

```
Usage:
  -filePath string
        Path to the Assembly file
  -args string
        Args to pass to the assembly
  -inline bool
        Execute Assembly in current process
  -process string
        Process to inject into (default "notepad.exe")
  -help
        Show help
```
