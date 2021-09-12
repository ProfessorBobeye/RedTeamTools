// Author: Ryan Cobb (@cobbr_io), The Wover (@TheRealWover)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;
using DeeInvok.DynamicInvocation;
using Data = DeeInvok.SharedData;

namespace DeeInvok.DynamicInvocation
{
    /// <summary>
    /// Contains function prototypes and wrapper functions for dynamically invoking NT API Calls.
    /// </summary>
    public class Native
    {
        public static SharedData.Native.NTSTATUS NtCreateThreadEx(
            ref IntPtr threadHandle,
            SharedData.Win32.WinNT.ACCESS_MASK desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended, stackZeroBits,
                sizeOfStack, maximumStackSize, attributeList
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtCreateThreadEx",
                typeof(DELEGATES.NtCreateThreadEx), ref funcargs);

            // Update the modified variables
            threadHandle = (IntPtr)funcargs[0];

            return retValue;
        }

        public static SharedData.Native.NTSTATUS RtlCreateUserThread(
                IntPtr Process,
                IntPtr ThreadSecurityDescriptor,
                bool CreateSuspended,
                IntPtr ZeroBits,
                IntPtr MaximumStackSize,
                IntPtr CommittedStackSize,
                IntPtr StartAddress,
                IntPtr Parameter,
                ref IntPtr Thread,
                IntPtr ClientId)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                Process, ThreadSecurityDescriptor, CreateSuspended, ZeroBits, 
                MaximumStackSize, CommittedStackSize, StartAddress, Parameter,
                Thread, ClientId
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlCreateUserThread",
                typeof(DELEGATES.RtlCreateUserThread), ref funcargs);

            // Update the modified variables
            Thread = (IntPtr)funcargs[8];

            return retValue;
        }

        public static SharedData.Native.NTSTATUS NtCreateSection(
            ref IntPtr SectionHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            ref ulong MaximumSize,
            uint SectionPageProtection,
            uint AllocationAttributes,
            IntPtr FileHandle)
        {

            // Craft an array for the arguments
            object[] funcargs =
            {
                SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtCreateSection", typeof(DELEGATES.NtCreateSection), ref funcargs);
            if (retValue != SharedData.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Unable to create section, " + retValue);
            }

            // Update the modified variables
            SectionHandle = (IntPtr) funcargs[0];
            MaximumSize = (ulong) funcargs[3];

            return retValue;
        }

        public static SharedData.Native.NTSTATUS NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                hProc, baseAddr
            };

            SharedData.Native.NTSTATUS result = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtUnmapViewOfSection",
                typeof(DELEGATES.NtUnmapViewOfSection), ref funcargs);

            return result;
        }

        public static SharedData.Native.NTSTATUS NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            IntPtr SectionOffset,
            ref ulong ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect)
        {

            // Craft an array for the arguments
            object[] funcargs =
            {
                SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType,
                Win32Protect
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtMapViewOfSection", typeof(DELEGATES.NtMapViewOfSection), ref funcargs);
            if (retValue != SharedData.Native.NTSTATUS.Success && retValue != SharedData.Native.NTSTATUS.ImageNotAtBase)
            {
                throw new InvalidOperationException("Unable to map view of section, " + retValue);
            }

            // Update the modified variables.
            BaseAddress = (IntPtr) funcargs[2];
            ViewSize = (ulong) funcargs[6];

            return retValue;
        }

        public static void RtlInitUnicodeString(ref SharedData.Native.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                DestinationString, SourceString
            };

            Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlInitUnicodeString", typeof(DELEGATES.RtlInitUnicodeString), ref funcargs);

            // Update the modified variables
            DestinationString = (SharedData.Native.UNICODE_STRING)funcargs[0];
        }

        public static SharedData.Native.NTSTATUS LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref SharedData.Native.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                PathToFile, dwFlags, ModuleFileName, ModuleHandle
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"LdrLoadDll", typeof(DELEGATES.LdrLoadDll), ref funcargs);

            // Update the modified variables
            ModuleHandle = (IntPtr)funcargs[3];

            return retValue;
        }

        public static void RtlZeroMemory(IntPtr Destination, int Length)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                Destination, Length
            };

            Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlZeroMemory", typeof(DELEGATES.RtlZeroMemory), ref funcargs);
        }

        public static SharedData.Native.NTSTATUS NtQueryInformationProcess(IntPtr hProcess, SharedData.Native.PROCESSINFOCLASS processInfoClass, out IntPtr pProcInfo)
        {
            int processInformationLength;
            UInt32 RetLen = 0;

            switch (processInfoClass)
            {
                case SharedData.Native.PROCESSINFOCLASS.ProcessWow64Information:
                    pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
                    RtlZeroMemory(pProcInfo, IntPtr.Size);
                    processInformationLength = IntPtr.Size;
                    break;
                case SharedData.Native.PROCESSINFOCLASS.ProcessBasicInformation:
                    SharedData.Native.PROCESS_BASIC_INFORMATION PBI = new SharedData.Native.PROCESS_BASIC_INFORMATION();
                    pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(PBI));
                    RtlZeroMemory(pProcInfo, Marshal.SizeOf(PBI));
                    Marshal.StructureToPtr(PBI, pProcInfo, true);
                    processInformationLength = Marshal.SizeOf(PBI);
                    break;
                default:
                    throw new InvalidOperationException($"Invalid ProcessInfoClass: {processInfoClass}");
            }

            object[] funcargs =
            {
                hProcess, processInfoClass, pProcInfo, processInformationLength, RetLen
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtQueryInformationProcess", typeof(DELEGATES.NtQueryInformationProcess), ref funcargs);
            if (retValue != SharedData.Native.NTSTATUS.Success)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            // Update the modified variables
            pProcInfo = (IntPtr)funcargs[2];

            return retValue;
        }

        public static bool NtQueryInformationProcessWow64Information(IntPtr hProcess)
        {
            SharedData.Native.NTSTATUS retValue = NtQueryInformationProcess(hProcess, SharedData.Native.PROCESSINFOCLASS.ProcessWow64Information, out IntPtr pProcInfo);
            if (retValue != SharedData.Native.NTSTATUS.Success)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            if (Marshal.ReadIntPtr(pProcInfo) == IntPtr.Zero)
            {
                return false;
            }
            return true;
        }

        public static SharedData.Native.PROCESS_BASIC_INFORMATION NtQueryInformationProcessBasicInformation(IntPtr hProcess)
        {
            SharedData.Native.NTSTATUS retValue = NtQueryInformationProcess(hProcess, SharedData.Native.PROCESSINFOCLASS.ProcessBasicInformation, out IntPtr pProcInfo);
            if (retValue != SharedData.Native.NTSTATUS.Success)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            return (SharedData.Native.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pProcInfo, typeof(SharedData.Native.PROCESS_BASIC_INFORMATION));
        }

        public static IntPtr NtOpenProcess(UInt32 ProcessId, SharedData.Win32.Kernel32.ProcessAccessFlags DesiredAccess)
        {
            // Create OBJECT_ATTRIBUTES & CLIENT_ID ref's
            IntPtr ProcessHandle = IntPtr.Zero;
            SharedData.Native.OBJECT_ATTRIBUTES oa = new SharedData.Native.OBJECT_ATTRIBUTES();
            SharedData.Native.CLIENT_ID ci = new SharedData.Native.CLIENT_ID();
            ci.UniqueProcess = (IntPtr)ProcessId;

            // Craft an array for the arguments
            object[] funcargs =
            {
                ProcessHandle, DesiredAccess, oa, ci
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtOpenProcess", typeof(DELEGATES.NtOpenProcess), ref funcargs);
            if (retValue != SharedData.Native.NTSTATUS.Success && retValue == SharedData.Native.NTSTATUS.InvalidCid)
            {
                throw new InvalidOperationException("An invalid client ID was specified.");
            }
            if (retValue != SharedData.Native.NTSTATUS.Success)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            // Update the modified variables
            ProcessHandle = (IntPtr)funcargs[0];

            return ProcessHandle;
        }

        public static void NtQueueApcThread(IntPtr ThreadHandle, IntPtr ApcRoutine, IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtQueueApcThread", typeof(DELEGATES.NtQueueApcThread), ref funcargs);
            if (retValue != SharedData.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Unable to queue APC, " + retValue);
            }
        }

        public static IntPtr NtOpenThread(int TID, SharedData.Win32.Kernel32.ThreadAccess DesiredAccess)
        {
            // Create OBJECT_ATTRIBUTES & CLIENT_ID ref's
            IntPtr ThreadHandle = IntPtr.Zero;
            SharedData.Native.OBJECT_ATTRIBUTES oa = new SharedData.Native.OBJECT_ATTRIBUTES();
            SharedData.Native.CLIENT_ID ci = new SharedData.Native.CLIENT_ID();
            ci.UniqueThread = (IntPtr)TID;

            // Craft an array for the arguments
            object[] funcargs =
            {
                ThreadHandle, DesiredAccess, oa, ci
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtOpenThread", typeof(DELEGATES.NtOpenProcess), ref funcargs);
            if (retValue != SharedData.Native.NTSTATUS.Success && retValue == SharedData.Native.NTSTATUS.InvalidCid)
            {
                throw new InvalidOperationException("An invalid client ID was specified.");
            }
            if (retValue != SharedData.Native.NTSTATUS.Success)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            // Update the modified variables
            ThreadHandle = (IntPtr)funcargs[0];

            return ThreadHandle;
        }

        public static IntPtr NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtAllocateVirtualMemory", typeof(DELEGATES.NtAllocateVirtualMemory), ref funcargs);
            if (retValue == SharedData.Native.NTSTATUS.AccessDenied)
            {
                // STATUS_ACCESS_DENIED
                throw new UnauthorizedAccessException("Access is denied.");
            }
            if (retValue == SharedData.Native.NTSTATUS.AlreadyCommitted)
            {
                // STATUS_ALREADY_COMMITTED
                throw new InvalidOperationException("The specified address range is already committed.");
            }
            if (retValue == SharedData.Native.NTSTATUS.CommitmentLimit)
            {
                // STATUS_COMMITMENT_LIMIT
                throw new InvalidOperationException("Your system is low on virtual memory.");
            }
            if (retValue == SharedData.Native.NTSTATUS.ConflictingAddresses)
            {
                // STATUS_CONFLICTING_ADDRESSES
                throw new InvalidOperationException("The specified address range conflicts with the address space.");
            }
            if (retValue == SharedData.Native.NTSTATUS.InsufficientResources)
            {
                // STATUS_INSUFFICIENT_RESOURCES
                throw new InvalidOperationException("Insufficient system resources exist to complete the API call.");
            }
            if (retValue == SharedData.Native.NTSTATUS.InvalidHandle)
            {
                // STATUS_INVALID_HANDLE
                throw new InvalidOperationException("An invalid HANDLE was specified.");
            }
            if (retValue == SharedData.Native.NTSTATUS.InvalidPageProtection)
            {
                // STATUS_INVALID_PAGE_PROTECTION
                throw new InvalidOperationException("The specified page protection was not valid.");
            }
            if (retValue == SharedData.Native.NTSTATUS.NoMemory)
            {
                // STATUS_NO_MEMORY
                throw new InvalidOperationException("Not enough virtual memory or paging file quota is available to complete the specified operation.");
            }
            if (retValue == SharedData.Native.NTSTATUS.ObjectTypeMismatch)
            {
                // STATUS_OBJECT_TYPE_MISMATCH
                throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
            }
            if (retValue != SharedData.Native.NTSTATUS.Success)
            {
                // STATUS_PROCESS_IS_TERMINATING == 0xC000010A
                throw new InvalidOperationException("An attempt was made to duplicate an object handle into or out of an exiting process.");
            }

            BaseAddress = (IntPtr)funcargs[1];
            return BaseAddress;
        }

        public static void NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 FreeType)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                ProcessHandle, BaseAddress, RegionSize, FreeType
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtFreeVirtualMemory", typeof(DELEGATES.NtFreeVirtualMemory), ref funcargs);
            if (retValue == SharedData.Native.NTSTATUS.AccessDenied)
            {
                // STATUS_ACCESS_DENIED
                throw new UnauthorizedAccessException("Access is denied.");
            }
            if (retValue == SharedData.Native.NTSTATUS.InvalidHandle)
            {
                // STATUS_INVALID_HANDLE
                throw new InvalidOperationException("An invalid HANDLE was specified.");
            }
            if (retValue != SharedData.Native.NTSTATUS.Success)
            {
                // STATUS_OBJECT_TYPE_MISMATCH == 0xC0000024
                throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
            }
        }

        public static string GetFilenameFromMemoryPointer(IntPtr hProc, IntPtr pMem)
        {
            // Alloc buffer for result struct
            IntPtr pBase = IntPtr.Zero;
            IntPtr RegionSize = (IntPtr)0x500;
            IntPtr pAlloc = NtAllocateVirtualMemory(hProc, ref pBase, IntPtr.Zero, ref RegionSize, SharedData.Win32.Kernel32.MEM_COMMIT | SharedData.Win32.Kernel32.MEM_RESERVE, SharedData.Win32.WinNT.PAGE_READWRITE);

            // Prepare NtQueryVirtualMemory parameters
            SharedData.Native.MEMORYINFOCLASS memoryInfoClass = SharedData.Native.MEMORYINFOCLASS.MemorySectionName;
            UInt32 MemoryInformationLength = 0x500;
            UInt32 Retlen = 0;

            // Craft an array for the arguments
            object[] funcargs =
            {
                hProc, pMem, memoryInfoClass, pAlloc, MemoryInformationLength, Retlen
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtQueryVirtualMemory", typeof(DELEGATES.NtQueryVirtualMemory), ref funcargs);

            string FilePath = string.Empty;
            if (retValue == SharedData.Native.NTSTATUS.Success)
            {
                SharedData.Native.UNICODE_STRING sn = (SharedData.Native.UNICODE_STRING)Marshal.PtrToStructure(pAlloc, typeof(SharedData.Native.UNICODE_STRING));
                FilePath = Marshal.PtrToStringUni(sn.Buffer);
            }

            // Free allocation
            NtFreeVirtualMemory(hProc, ref pAlloc, ref RegionSize, SharedData.Win32.Kernel32.MEM_RELEASE);
            if (retValue == SharedData.Native.NTSTATUS.AccessDenied)
            {
                // STATUS_ACCESS_DENIED
                throw new UnauthorizedAccessException("Access is denied.");
            }
            if (retValue == SharedData.Native.NTSTATUS.AccessViolation)
            {
                // STATUS_ACCESS_VIOLATION
                throw new InvalidOperationException("The specified base address is an invalid virtual address.");
            }
            if (retValue == SharedData.Native.NTSTATUS.InfoLengthMismatch)
            {
                // STATUS_INFO_LENGTH_MISMATCH
                throw new InvalidOperationException("The MemoryInformation buffer is larger than MemoryInformationLength.");
            }
            if (retValue == SharedData.Native.NTSTATUS.InvalidParameter)
            {
                // STATUS_INVALID_PARAMETER
                throw new InvalidOperationException("The specified base address is outside the range of accessible addresses.");
            }
            return FilePath;
        }

        public static UInt32 NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect)
        {
            // Craft an array for the arguments
            UInt32 OldProtect = 0;
            object[] funcargs =
            {
                ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtProtectVirtualMemory", typeof(DELEGATES.NtProtectVirtualMemory), ref funcargs);
            if (retValue != SharedData.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Failed to change memory protection, " + retValue);
            }

            OldProtect = (UInt32)funcargs[4];
            return OldProtect;
        }

        public static UInt32 NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, UInt32 BufferLength)
        {
            // Craft an array for the arguments
            UInt32 BytesWritten = 0;
            object[] funcargs =
            {
                ProcessHandle, BaseAddress, Buffer, BufferLength, BytesWritten
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtWriteVirtualMemory", typeof(DELEGATES.NtWriteVirtualMemory), ref funcargs);
            if (retValue != SharedData.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Failed to write memory, " + retValue);
            }

            BytesWritten = (UInt32)funcargs[4];
            return BytesWritten;
        }

        public static IntPtr LdrGetProcedureAddress(IntPtr hModule, IntPtr FunctionName, IntPtr Ordinal, ref IntPtr FunctionAddress)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                hModule, FunctionName, Ordinal, FunctionAddress
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"LdrGetProcedureAddress", typeof(DELEGATES.LdrGetProcedureAddress), ref funcargs);
            if (retValue != SharedData.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Failed get procedure address, " + retValue);
            }

            FunctionAddress = (IntPtr)funcargs[3];
            return FunctionAddress;
        }

        public static void RtlGetVersion(ref SharedData.Native.OSVERSIONINFOEX VersionInformation)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                VersionInformation
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlGetVersion", typeof(DELEGATES.RtlGetVersion), ref funcargs);
            if (retValue != SharedData.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Failed get procedure address, " + retValue);
            }

            VersionInformation = (SharedData.Native.OSVERSIONINFOEX)funcargs[0];
        }

        public static UInt32 NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, ref UInt32 NumberOfBytesToRead)
        {
            // Craft an array for the arguments
            UInt32 NumberOfBytesRead = 0;
            object[] funcargs =
            {
                ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtReadVirtualMemory", typeof(DELEGATES.NtReadVirtualMemory), ref funcargs);
            if (retValue != SharedData.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Failed to read memory, " + retValue);
            }

            NumberOfBytesRead = (UInt32)funcargs[4];
            return NumberOfBytesRead;
        }

        public static IntPtr NtOpenFile(ref IntPtr FileHandle, SharedData.Win32.Kernel32.FileAccessFlags DesiredAccess, ref SharedData.Native.OBJECT_ATTRIBUTES ObjAttr, ref SharedData.Native.IO_STATUS_BLOCK IoStatusBlock, SharedData.Win32.Kernel32.FileShareFlags ShareAccess, SharedData.Win32.Kernel32.FileOpenFlags OpenOptions)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                FileHandle, DesiredAccess, ObjAttr, IoStatusBlock, ShareAccess, OpenOptions
            };

            SharedData.Native.NTSTATUS retValue = (SharedData.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtOpenFile", typeof(DELEGATES.NtOpenFile), ref funcargs);
            if (retValue != SharedData.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Failed to open file, " + retValue);
            }


            FileHandle = (IntPtr)funcargs[0];
            return FileHandle;
        }

        /// <summary>
        /// Holds delegates for API calls in the NT Layer.
        /// Must be public so that they may be used with SharpSploit.Execution.DynamicInvoke.Generic.DynamicFunctionInvoke
        /// </summary>
        /// <example>
        /// 
        /// // These delegates may also be used directly.
        ///
        /// // Get a pointer to the NtCreateThreadEx function.
        /// IntPtr pFunction = Execution.DynamicInvoke.Generic.GetLibraryAddress(@"ntdll.dll", "NtCreateThreadEx");
        /// 
        /// //  Create an instance of a NtCreateThreadEx delegate from our function pointer.
        /// DELEGATES.NtCreateThreadEx createThread = (NATIVE_DELEGATES.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(
        ///    pFunction, typeof(NATIVE_DELEGATES.NtCreateThreadEx));
        ///
        /// //  Invoke NtCreateThreadEx using the delegate
        /// createThread(ref threadHandle, Data.Win32.WinNT.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Data.Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL, IntPtr.Zero,
        ///     procHandle, startAddress, IntPtr.Zero, Data.Native.NT_CREATION_FLAGS.HIDE_FROM_DEBUGGER, 0, 0, 0, IntPtr.Zero);
        /// 
        /// </example>
        public struct DELEGATES
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate SharedData.Native.NTSTATUS NtCreateThreadEx(
                out IntPtr threadHandle,
                SharedData.Win32.WinNT.ACCESS_MASK desiredAccess,
                IntPtr objectAttributes,
                IntPtr processHandle,
                IntPtr startAddress,
                IntPtr parameter,
                bool createSuspended,
                int stackZeroBits,
                int sizeOfStack,
                int maximumStackSize,
                IntPtr attributeList);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate SharedData.Native.NTSTATUS RtlCreateUserThread(
                IntPtr Process,
                IntPtr ThreadSecurityDescriptor,
                bool CreateSuspended,
                IntPtr ZeroBits,
                IntPtr MaximumStackSize,
                IntPtr CommittedStackSize,
                IntPtr StartAddress,
                IntPtr Parameter,
                ref IntPtr Thread,
                IntPtr ClientId);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate SharedData.Native.NTSTATUS NtCreateSection(
                ref IntPtr SectionHandle,
                uint DesiredAccess,
                IntPtr ObjectAttributes,
                ref ulong MaximumSize,
                uint SectionPageProtection,
                uint AllocationAttributes,
                IntPtr FileHandle);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate SharedData.Native.NTSTATUS NtUnmapViewOfSection(
                IntPtr hProc,
                IntPtr baseAddr);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate SharedData.Native.NTSTATUS NtMapViewOfSection(
                IntPtr SectionHandle,
                IntPtr ProcessHandle,
                out IntPtr BaseAddress,
                IntPtr ZeroBits,
                IntPtr CommitSize,
                IntPtr SectionOffset,
                out ulong ViewSize,
                uint InheritDisposition,
                uint AllocationType,
                uint Win32Protect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 LdrLoadDll(
                IntPtr PathToFile,
                UInt32 dwFlags,
                ref SharedData.Native.UNICODE_STRING ModuleFileName,
                ref IntPtr ModuleHandle);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlInitUnicodeString(
                ref SharedData.Native.UNICODE_STRING DestinationString,
                [MarshalAs(UnmanagedType.LPWStr)]
                string SourceString);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlZeroMemory(
                IntPtr Destination,
                int length);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtQueryInformationProcess(
                IntPtr processHandle,
                SharedData.Native.PROCESSINFOCLASS processInformationClass,
                IntPtr processInformation,
                int processInformationLength,
                ref UInt32 returnLength);


            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtOpenProcess(
                ref IntPtr ProcessHandle,
                SharedData.Win32.Kernel32.ProcessAccessFlags DesiredAccess,
                ref SharedData.Native.OBJECT_ATTRIBUTES ObjectAttributes,
                ref SharedData.Native.CLIENT_ID ClientId);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtQueueApcThread(
                IntPtr ThreadHandle,
                IntPtr ApcRoutine,
                IntPtr ApcArgument1,
                IntPtr ApcArgument2,
                IntPtr ApcArgument3);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtOpenThread(
                ref IntPtr ThreadHandle,
                SharedData.Win32.Kernel32.ThreadAccess DesiredAccess,
                ref SharedData.Native.OBJECT_ATTRIBUTES ObjectAttributes,
                ref SharedData.Native.CLIENT_ID ClientId);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtAllocateVirtualMemory(
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                IntPtr ZeroBits,
                ref IntPtr RegionSize,
                UInt32 AllocationType,
                UInt32 Protect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtFreeVirtualMemory(
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                ref IntPtr RegionSize,
                UInt32 FreeType);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtQueryVirtualMemory(
                IntPtr ProcessHandle,
                IntPtr BaseAddress,
                SharedData.Native.MEMORYINFOCLASS MemoryInformationClass,
                IntPtr MemoryInformation,
                UInt32 MemoryInformationLength,
                ref UInt32 ReturnLength);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtProtectVirtualMemory(
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                ref IntPtr RegionSize,
                UInt32 NewProtect,
                ref UInt32 OldProtect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtWriteVirtualMemory(
                IntPtr ProcessHandle,
                IntPtr BaseAddress,
                IntPtr Buffer,
                UInt32 BufferLength,
                ref UInt32 BytesWritten);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 RtlUnicodeStringToAnsiString(
                ref SharedData.Native.ANSI_STRING DestinationString,
                ref SharedData.Native.UNICODE_STRING SourceString,
                bool AllocateDestinationString);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 LdrGetProcedureAddress(
                IntPtr hModule,
                IntPtr FunctionName,
                IntPtr Ordinal,
                ref IntPtr FunctionAddress);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 RtlGetVersion(
                ref SharedData.Native.OSVERSIONINFOEX VersionInformation);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtReadVirtualMemory(
                IntPtr ProcessHandle,
                IntPtr BaseAddress,
                IntPtr Buffer,
                UInt32 NumberOfBytesToRead,
                ref UInt32 NumberOfBytesRead);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtOpenFile(
                ref IntPtr FileHandle,
                SharedData.Win32.Kernel32.FileAccessFlags DesiredAccess,
                ref SharedData.Native.OBJECT_ATTRIBUTES ObjAttr,
                ref SharedData.Native.IO_STATUS_BLOCK IoStatusBlock,
                SharedData.Win32.Kernel32.FileShareFlags ShareAccess,
                SharedData.Win32.Kernel32.FileOpenFlags OpenOptions);
        }
    }
}
