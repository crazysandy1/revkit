// Portable base typedefs shared by every library.
typedef unsigned char BYTE; typedef unsigned char UCHAR; typedef unsigned char *PBYTE; typedef unsigned char *LPBYTE; typedef unsigned char BOOLEAN;
typedef char CHAR; typedef char *PCHAR; typedef char *LPSTR; typedef const char *LPCSTR; typedef char *PSTR; typedef const char *PCSTR;
typedef unsigned short WORD; typedef unsigned short USHORT; typedef short SHORT; typedef unsigned short WCHAR;
typedef WCHAR *LPWSTR; typedef const WCHAR *LPCWSTR; typedef WCHAR *PWSTR; typedef const WCHAR *PCWSTR;
typedef unsigned int DWORD; typedef unsigned int UINT; typedef unsigned int ULONG; typedef int LONG; typedef int INT; typedef int BOOL;
typedef int *PBOOL; typedef int *LPBOOL;
typedef unsigned int *LPDWORD; typedef unsigned int *PDWORD; typedef unsigned int *PULONG; typedef int *PLONG; typedef int *LPLONG;
typedef unsigned long long QWORD; typedef unsigned long long ULONGLONG; typedef long long LONGLONG; typedef unsigned long long DWORD64;
typedef unsigned long long ULONG64; typedef long long LONG64; typedef unsigned long long UINT64; typedef long long INT64;
typedef unsigned int UINT32; typedef int INT32; typedef unsigned short UINT16; typedef short INT16; typedef unsigned char UINT8; typedef signed char INT8;
typedef void VOID; typedef void *PVOID; typedef void *LPVOID; typedef const void *LPCVOID; typedef const void *PCVOID;
typedef void *HANDLE; typedef void **PHANDLE; typedef void *HMODULE; typedef void *HINSTANCE; typedef void *HWND; typedef void *HKEY;
typedef void *HDC; typedef void *HMENU; typedef void *HICON; typedef void *HCURSOR; typedef void *HBRUSH; typedef void *HGLOBAL;
typedef void *HLOCAL; typedef void *HRSRC; typedef void *HFILE; typedef void *HBITMAP; typedef void *HFONT; typedef void *HGDIOBJ;
typedef void *HHOOK; typedef void *HEVENT; typedef void *SC_HANDLE;
typedef long HRESULT; typedef unsigned short ATOM; typedef unsigned int LCID; typedef unsigned int LANGID; typedef unsigned int ACCESS_MASK;
typedef unsigned int NTSTATUS; typedef float FLOAT; typedef double DOUBLE;
typedef unsigned long long WPARAM; typedef long long LPARAM; typedef long long LRESULT;
typedef unsigned long long SOCKET; typedef int (*FARPROC)(); typedef int (*PROC)();
typedef unsigned long long *PSIZE_T;
typedef unsigned int mode_t; typedef int pid_t; typedef unsigned int uid_t; typedef unsigned int gid_t; typedef long time_t; typedef long clock_t;
typedef struct _iobuf FILE; typedef unsigned int socklen_t; typedef unsigned int in_addr_t; typedef unsigned short in_port_t;
typedef unsigned long pthread_t; typedef int errno_t; typedef unsigned int useconds_t; typedef long suseconds_t;
typedef char *va_list;
#define NULL 0
#define TRUE 1
#define FALSE 0
