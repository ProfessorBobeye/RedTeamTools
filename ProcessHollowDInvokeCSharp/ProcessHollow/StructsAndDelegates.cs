using System;
using System.Runtime.InteropServices;
using static DeeInvok.SharedData.Native;

namespace ProcessHollow {
	public class StructsAndDelegates {
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate UInt32 ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation,
			UInt32 ProcInfoLen, ref UInt32 retlen);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesRead);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate bool CreateProcess(
		   string lpApplicationName,
		   string lpCommandLine,
		   ref SECURITY_ATTRIBUTES lpProcessAttributes,
		   ref SECURITY_ATTRIBUTES lpThreadAttributes,
		   bool bInheritHandles,
		   CreationFlags dwCreationFlags,
		   IntPtr lpEnvironment,
		   string lpCurrentDirectory,
		   ref STARTUPINFOEX lpStartupInfo,
		   out PROCESS_INFORMATION lpProcessInformation);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate NTSTATUS NtResumeThread(IntPtr ThreadHandle, ref UInt32 SuspendCount);
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct STARTUPINFO {
		public uint cb;
		public IntPtr lpReserved;
		public IntPtr lpDesktop;
		public IntPtr lpTitle;
		public uint dwX;
		public uint dwY;
		public uint dwXSize;
		public uint dwYSize;
		public uint dwXCountChars;
		public uint dwYCountChars;
		public uint dwFillAttributes;
		public uint dwFlags;
		public ushort wShowWindow;
		public ushort cbReserved;
		public IntPtr lpReserved2;
		public IntPtr hStdInput;
		public IntPtr hStdOutput;
		public IntPtr hStdErr;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct PROCESS_INFORMATION {
		public IntPtr hProcess;
		public IntPtr hThread;
		public int dwProcessId;
		public int dwThreadId;
	}


	public struct PROCESS_BASIC_INFORMATION {
		public IntPtr ExitStatus;
		public IntPtr PebBaseAddress;
		public UIntPtr AffinityMask;
		public int BasePriority;
		public UIntPtr UniqueProcessId;
		public UIntPtr InheritedFromUniqueProcessId;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct SECURITY_ATTRIBUTES {
		public int nLength;
		public IntPtr lpSecurityDescriptor;
		public int bInheritHandle;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct STARTUPINFOEX {
		public STARTUPINFO StartupInfo;
		public IntPtr lpAttributeList;
	}

	[Flags]
	public enum CreationFlags : uint {
		START_SUSPENDED = 0x4
	}

	public enum MemoryProtections: uint {
		PAGE_READWRITE = 0x04,
		PAGE_EXECUTE_READ = 0x20,
		PAGE_EXECUTE_READWRITE = 0x40
	}
}
