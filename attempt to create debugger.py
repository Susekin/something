from ctypes import *

WORD = c_ushort
DWORD = c_ulong
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
HANDLE = c_void_p
LPCWSTR = c_wchar
LPWSTR = c_wchar
PVOID     = c_void_p
LPVOID    = c_void_p
UINT_PTR  = c_ulong
LONG = c_long
BYTE = c_ubyte



DEBUG_PROCESS = 0x00000001
NEW_CONSOLE = 0x00000010
CREATE_UNICODE_ENVIRONMENT = 0x00000400
PROCESS_ALL_ACCESS = 0x001F0FFF
INFINITE  = 0xFFFFFFFF
DBG_CONTINUE = 0x00010002
TH32CS_SNAPTHREAD   = 0x00000004
THREAD_ALL_ACCESS   = 0x001F03FF

CONTEXT_FULL                   = 0x00010007
CONTEXT_DEBUG_REGISTERS        = 0x00010010

EXCEPTION_ACCESS_VIOLATION     = 0xC0000005
EXCEPTION_BREAKPOINT           = 0x80000003
EXCEPTION_GUARD_PAGE           = 0x80000001
EXCEPTION_SINGLE_STEP          = 0x80000004


class STARTUPINFO(Structure):
    __slots__ = '__weakref__'
    _fields_=[
        ("cb", DWORD),
        ("lpReserved", LPTSTR),
        ("lpDesktop", LPTSTR),
        ("lpTitle", LPTSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]

class PROCESS_INFORMATION(Structure):
    __slots__ = '__weakref__'
    _fields_=[
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]   

class EXCEPTION_RECORD(Structure):
    pass
    
EXCEPTION_RECORD._fields_ = [
        ("ExceptionCode",        DWORD),
        ("ExceptionFlags",       DWORD),
        ("ExceptionRecord",      POINTER(EXCEPTION_RECORD)),
        ("ExceptionAddress",     PVOID),
        ("NumberParameters",     DWORD),
        ("ExceptionInformation", UINT_PTR * 15),
        ]

class _EXCEPTION_RECORD(Structure):
    _fields_ = [
        ("ExceptionCode",        DWORD),
        ("ExceptionFlags",       DWORD),
        ("ExceptionRecord",      POINTER(EXCEPTION_RECORD)),
        ("ExceptionAddress",     PVOID),
        ("NumberParameters",     DWORD),
        ("ExceptionInformation", UINT_PTR * 15),
        ]

# Exceptions
class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord",    EXCEPTION_RECORD),
        ("dwFirstChance",      DWORD),
        ]

# it populates this union appropriately
class DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception",         EXCEPTION_DEBUG_INFO),
#        ("CreateThread",      CREATE_THREAD_DEBUG_INFO),
#        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
#        ("ExitThread",        EXIT_THREAD_DEBUG_INFO),
#        ("ExitProcess",       EXIT_PROCESS_DEBUG_INFO),
#        ("LoadDll",           LOAD_DLL_DEBUG_INFO),
#        ("UnloadDll",         UNLOAD_DLL_DEBUG_INFO),
#        ("DebugString",       OUTPUT_DEBUG_STRING_INFO),
#        ("RipInfo",           RIP_INFO),
        ]   

# DEBUG_EVENT describes a debugging event
# that the debugger has trapped
class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId",      DWORD),
        ("dwThreadId",       DWORD),
        ("u",                DEBUG_EVENT_UNION),
        ]

class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize",             DWORD),
        ("cntUsage",           DWORD),
        ("th32ThreadID",       DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri",          LONG),
        ("tpDeltaPri",         LONG),
        ("dwFlags",            DWORD),
    ]

class FLOATING_SAVE_AREA(Structure):
    _fields_ = [

        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
    ]

class CONTEXT(Structure):
    _fields_ = [

        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
    ]

  
kernel32 = windll.kernel32

# process_info = PROCESS_INFORMATION()

# startupinfo = STARTUPINFO()
# startupinfo.dwFlags = 0x1
# startupinfo.wShowWindow = 0x0
# startupinfo.cb = sizeof(startupinfo)

# if kernel32.CreateProcessW(
#     "C:\\WINDOWS\\system32\\calc.exe",
#     None,
#     None,
#     None,
#     0,
#     DEBUG_PROCESS|CREATE_UNICODE_ENVIRONMENT,
#     None,
#     None,
#     byref(startupinfo),
#     byref(process_info)):
#         print (process_info.dwProcessId)
# else: 
#     print(kernel32.GetLastError() + "!!!")    


# h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,process_info.dwProcessId)
# ##print (kernel32.GetProcessId(h_process))

# max_path_len = 260
# name_buffer = (c_char * max_path_len)()
# windll.psapi.GetProcessImageFileNameA(h_process,name_buffer,max_path_len)
# print (name_buffer.value)

#############################################

# arr = c_ulong * 256
# lpidProcess= arr()
# cb = sizeof(lpidProcess)
# cbNeeded = c_ulong()

# windll.psapi.EnumProcesses(byref(lpidProcess),
#                         cb,
#                         byref(cbNeeded))

# for i in lpidProcess:
#     print(i)



pid = 7320

h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,int(pid))

kernel32.DebugActiveProcess(int(pid))  ## !!!

debug_event = DEBUG_EVENT()

while True:
        kernel32.WaitForDebugEvent(byref(debug_event),INFINITE)
        
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS 
        
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS,None,debug_event.dwThreadId)
        context = kernel32.GetThreadContext(h_thread,byref(context))
        #print ("Event code: %d Thread: %d" %(debug_event.dwDebugEventCode,debug_event.dwThreadId))

        if (debug_event.dwDebugEventCode == 1):
            print ("ExceptionCode: 0x%08x " %debug_event.u.Exception.ExceptionRecord.ExceptionCode)
            print ("ExceptionAddress: 0x%08x " %debug_event.u.Exception.ExceptionRecord.ExceptionAddress)
        
        kernel32.ContinueDebugEvent(debug_event.dwProcessId,debug_event.dwThreadId,DBG_CONTINUE)  
        if (debug_event.dwDebugEventCode == 4):
            break
        
        
         
thread_entry = THREADENTRY32()

snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,int(pid)) ## !!!

thread_entry.dwSize = sizeof(thread_entry)

success = kernel32.Thread32First(snapshot,byref(thread_entry))

thread_list = []
while success:
    if thread_entry.th32OwnerProcessID == pid:
        thread_list.append(thread_entry.th32ThreadID)
    success = kernel32.Thread32Next(snapshot,byref(thread_entry))

kernel32.CloseHandle(snapshot)

#print (thread_list)

for thread in thread_list:
    #print (thread)
    context = CONTEXT()
    context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS 
    h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS,None,thread)
    kernel32.GetThreadContext(h_thread, byref(context))
    # print ("EIP: 0x%08x " %context.Eip)
    # print ("ESP: 0x%08x " %context.Esp)
    # print ("EBP: 0x%08x " %context.Ebp)
    # print ("EAX: 0x%08x " %context.Eax)
    # print ("EBP: 0x%08x " %context.Ebp)
    # print ("ECX: 0x%08x " %context.Ecx)
    # print ("EDX: 0x%08x " %context.Edx)
    # print ("--------------")
    
    kernel32.CloseHandle(h_thread)
    

kernel32.DebugActiveProcessStop(int(pid))
 