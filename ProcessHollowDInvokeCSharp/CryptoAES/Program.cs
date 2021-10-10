//Taken from https://www.codeproject.com/Articles/769741/Csharp-AES-bits-Encryption-Library-with-Salt

using System.Security.Cryptography;
using System.IO;
using System.Text;
using System;

namespace CryptoAES {
    public class Program {

        static void Main(string[] args) {
            string currentBinary = AppDomain.CurrentDomain.FriendlyName;

            if (args.Length != 2) {
                Console.WriteLine($"Usage: {currentBinary} <inFile> <outFile>");
                Console.WriteLine($"Usage: {currentBinary} 'C:\\Temp\\loader.bin' 'C:\\Temp\\encryptedLoader.bin'");
                Environment.Exit(0);
            }
            string inFile = args[0];
            string outFile = args[1];

            byte[] shellcode = File.ReadAllBytes(inFile);

            byte[] passwordBytes = Encoding.UTF8.GetBytes("fishfish");
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
            byte[] bytesEncrypted = AES_Encrypt(shellcode, passwordBytes);
            File.WriteAllBytes(outFile, bytesEncrypted);

            StringBuilder encryptedShellcode = new StringBuilder();
            encryptedShellcode.Append("byte[] shellcode = new byte[");
            encryptedShellcode.Append(bytesEncrypted.Length);
            encryptedShellcode.Append("] { ");
            for (int i = 0; i < bytesEncrypted.Length; i++) {
                encryptedShellcode.Append("0x");
                encryptedShellcode.AppendFormat("{0:x2}", bytesEncrypted[i]);
                if (i < bytesEncrypted.Length - 1) {
                    encryptedShellcode.Append(", ");
                }

            }
            encryptedShellcode.Append(" };");
			Console.WriteLine("Encrypted shellcode: ");
            Console.WriteLine(encryptedShellcode.ToString());
            Console.WriteLine("");
            Console.WriteLine("");
        }

        public static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes) {
            byte[] encryptedBytes = null;

            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream()) {
                using (RijndaelManaged AES = new RijndaelManaged()) {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write)) {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
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