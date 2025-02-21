# ETWShellcodeLoader - Shellcode Loader Utilizing ETW Events  

**ETWShellcodeLoader** is a proof-of-concept shellcode loader that leverages **Event Tracing for Windows (ETW)** to deliver and execute payloads. This method uses ETW events as a transport mechanism to deliver shellcode dynamically. By embedding the payload inside an ETW event.  

This approach allows the shellcode to be sent from a separate process and executed in memory without writing to disk. The project contains both a **split execution binaries** (sender/receiver) and a **single execution binary**.  At the time of creation, **ETWShellcodeLoader** successfully bypasses Windows Defender.

## **Usage**
This repository includes three separate programs:  

- **Sender** - Fetches, decrypts, and transmits shellcode via an ETW event.  
- **Receiver** - Listens for ETW events, extracts the shellcode, executes it in memory, and cleans up traces.  
- **ETWShellcodeLoader** - A single executable version that combines both sender and receiver functionalities.  

### **Option 1: Split Execution**
1. Open ETWShellcodeLoader.sln in Visual Studio and build the projects.
2. Run Receiver.exe as  to start listening.
3. Run Sender.exe to send the shellcode event.
4. The receiver will then extract and execute the shellcode.

### **Option 2: Single Executable**
1. Open ETWShellcodeLoader.sln in Visual Studio and build the projects.
2. Run ETWShellcodeLoader.exe.

**Note:** Make sure to replace "shellcode-hosting.com" and "/shellcode.txt" with your actual HTTP server and resource path.

## **Limitations**  
- The use of ETW sessions for event transmission requires administrative permissions. This is a known limitation and reduces the practicality of this technique.  
- This project was created as a **proof-of-concept** to explore unconventional shellcode storing & execution methods.  

## **Disclaimer**
This project is for **educational and research purposes only**. Any unauthorized use of this tool for malicious purposes is strictly prohibited. The author is not responsible for any misuse.

## **License**
This project is licensed under the **MIT License**.
