namespace PSSecureTransferLib
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.RegularExpressions;

    public class FileNameEncoder
    {
        public FileNameEncoder(bool allowExtension, bool ignorePathSeparatorChars)
        {
            List<char> invalidFileNameChars = new List<char>(Path.GetInvalidFileNameChars());
            if (ignorePathSeparatorChars)
            {
                if (invalidFileNameChars.Contains(Path.DirectorySeparatorChar))
                    invalidFileNameChars.Remove(Path.DirectorySeparatorChar);

                if (invalidFileNameChars.Contains(Path.AltDirectorySeparatorChar))
                    invalidFileNameChars.Remove(Path.AltDirectorySeparatorChar);
            }

            if (!invalidFileNameChars.Contains('_'))
                invalidFileNameChars.Add('_');

            if (!allowExtension && !invalidFileNameChars.Contains('.'))
                invalidFileNameChars.Add('.');

            this.InvalidChars = new ReadOnlyCollection<char>(invalidFileNameChars);
        }

        public ReadOnlyCollection<char> InvalidChars { get; set; }

        public string Encode(string path)
        {
            if (String.IsNullOrEmpty(path))
                return path;

            StringBuilder result = new StringBuilder();
            foreach (char c in path.ToCharArray())
            {
                if (this.InvalidChars.Contains(c))
                    result.AppendFormat("_0x{0:x2}_", (int)c);
                else
                    result.Append(c);
            }

            return result.ToString();
        }

        public static readonly Regex DecodeRegex = new Regex(@"_0x(?<hex>[\da-f]{2})_", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public string Decode(string path)
        {
            if (String.IsNullOrEmpty(path))
                return path;

            return FileNameEncoder.DecodeRegex.Replace(path, FileNameEncoder.DecodeEvaluator);
        }

        public static string DecodeEvaluator(Match match)
        {
            return new String(new char[] { (char)(Convert.ToInt32(match.Groups["hex"].Value, 16)) });
        }
    }

    public class AppDataConfig
    {
        public const string Company_PathName = "Leonard T. Erwine";
        public const string Platform_PathName = "PowerShell";
        public const string Product_PathName = "PSSecureTransfer";

        private static readonly FileNameEncoder KeyNameEncoder = new FileNameEncoder(false, false);

        private static AppDataConfig _roaming = null;

        public static AppDataConfig Roaming
        {
            get
            {
                if (AppDataConfig._roaming == null)
                    AppDataConfig._roaming = new AppDataConfig(true);

                return AppDataConfig._roaming;
            }
        }

        private static AppDataConfig _local = null;

        public static AppDataConfig Local
        {
            get
            {
                if (AppDataConfig._local == null)
                    AppDataConfig._local = new AppDataConfig(false);

                return AppDataConfig._local;
            }
        }

        private bool _isRoaming;

        public bool IsRoaming { get { return this._isRoaming; } }

        private string _folderPath;

        public string FolderPath { get { return this._folderPath; } }

        private string _privateKeyPath = null;

        public string PrivateKeyPath
        {
            get
            {
                if (this._privateKeyPath == null)
                    this._privateKeyPath = Path.Combine(this.FolderPath, "Private.pkey");

                return this._privateKeyPath;
            }
        }

        private string _publicKeyPath = null;

        public string PublicKeyPath
        {
            get
            {
                if (this._publicKeyPath == null)
                    this._publicKeyPath = Path.Combine(this.FolderPath, "Public.pkey");

                return this._publicKeyPath;
            }
        }

        private AppDataConfig(bool isRoaming)
        {
            this._isRoaming = isRoaming;

            this._folderPath = Path.Combine(Environment.GetFolderPath((isRoaming) ? Environment.SpecialFolder.ApplicationData : Environment.SpecialFolder.LocalApplicationData),
                AppDataConfig.Company_PathName);
            if (!Directory.Exists(this._folderPath))
                Directory.CreateDirectory(this._folderPath);

            this._folderPath = Path.Combine(this._folderPath, AppDataConfig.Platform_PathName);
            if (!Directory.Exists(this._folderPath))
                Directory.CreateDirectory(this._folderPath);

            this._folderPath = Path.Combine(this._folderPath, AppDataConfig.Product_PathName);
            if (!Directory.Exists(this._folderPath))
                Directory.CreateDirectory(this._folderPath);
        }

        public string GetPersonalPublicKey()
        {
            string key;

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(EncryptionHelper.AsymmetricKeySize))
            {
                this.InitializeDecryptionProvider(rsa);
                key = rsa.ToXmlString(false);
            }

            return key;
        }

        public string GetPublicKey(string name)
        {
            if (String.IsNullOrEmpty(name))
                return null;

            string path = Path.Combine(this.FolderPath, AppDataConfig.KeyNameEncoder.Encode(name));

            if (File.Exists(path))
                return File.ReadAllText(path);

            return null;
        }

        internal void InitializeDecryptionProvider(RSACryptoServiceProvider rsa)
        {
            byte[] protectedData;

            if (File.Exists(this.PrivateKeyPath))
            {
                protectedData = File.ReadAllBytes(this.PrivateKeyPath);
                rsa.FromXmlString(Encoding.UTF8.GetString(ProtectedData.Unprotect(protectedData, null, DataProtectionScope.CurrentUser)));
                return;
            }

            AppDataConfig altConfig = (this.IsRoaming) ? AppDataConfig.Local : AppDataConfig.Roaming;
            if (File.Exists(altConfig.PrivateKeyPath))
            {
                protectedData = File.ReadAllBytes(altConfig.PrivateKeyPath);
                File.WriteAllBytes(this.PrivateKeyPath, protectedData);
                rsa.FromXmlString(Encoding.UTF8.GetString(ProtectedData.Unprotect(protectedData, null, DataProtectionScope.CurrentUser)));
                return;
            }

            protectedData = ProtectedData.Protect(Encoding.UTF8.GetBytes(rsa.ToXmlString(true)), null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(this.PrivateKeyPath, protectedData);
            File.WriteAllBytes(altConfig.PrivateKeyPath, protectedData);
        }
    }

    public static class EncryptionHelper
    {
        public const int AsymmetricKeySize = 2048;

        public const int SymmetricKeySize = 256;

        public const int BlockSize = 256;

        public const CipherMode Mode = CipherMode.CBC;

        public static void Encrypt(AppDataConfig config, string keyName, Stream input, Stream output)
        {
            if (config == null)
                throw new ArgumentNullException("config");

            if (keyName == null)
                throw new ArgumentNullException("keyName");

            if (keyName.Trim().Length == 0)
                throw new ArgumentException("keyName cannot be empty.", "keyName");

            if (input == null)
                throw new ArgumentNullException("input");

            if (output == null)
                throw new ArgumentNullException("output");

            if (!input.CanRead)
                throw new ArgumentException("Cannot read from input stream", "input");

            if (!output.CanWrite)
                throw new ArgumentException("Cannot write to output stream", "output");

            string publicKey = config.GetPublicKey(keyName);

            if (publicKey == null)
                throw new ArgumentException("Public key not found.", "keyName");

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(EncryptionHelper.AsymmetricKeySize))
            {
                try { rsa.FromXmlString(publicKey); }
                catch (Exception exc)
                {
                    throw new ArgumentException("Invalid public key", "keyName", exc);
                }

                using (RijndaelManaged rjndl = new RijndaelManaged())
                {
                    rjndl.KeySize = EncryptionHelper.SymmetricKeySize;
                    rjndl.BlockSize = EncryptionHelper.BlockSize;
                    rjndl.Mode = EncryptionHelper.Mode;

                    using (ICryptoTransform transform = rjndl.CreateEncryptor())
                    {
                        byte[] encryptedKeyData = rsa.Encrypt(rjndl.Key, true);
                        byte[] buffer = BitConverter.GetBytes(encryptedKeyData.Length);
                        // Write length of encrypted key data
                        output.Write(buffer, 0, buffer.Length);

                        buffer = BitConverter.GetBytes(rjndl.IV.Length);
                        // Write length of initialization vector data
                        output.Write(buffer, 0, buffer.Length);

                        // Write encrypted key data
                        output.Write(encryptedKeyData, 0, encryptedKeyData.Length);

                        // Write initialization vector data
                        output.Write(rjndl.IV, 0, rjndl.IV.Length);

                        CryptoStream encryptionStream;
                        try { encryptionStream = new CryptoStream(output, transform, CryptoStreamMode.Write); }
                        catch (Exception exc)
                        {
                            throw new Exception(String.Format("Error creation encryption stream: {0}", exc.Message), exc);
                        }

                        using (encryptionStream)
                        {
                            buffer = new byte[rjndl.BlockSize / 8];
                            int count = 0;
                            int offset = 0;
                            int bytesRead = 0;

                            do
                            {
                                try { count = input.Read(buffer, 0, buffer.Length); }
                                catch (Exception exc)
                                {
                                    throw new Exception(String.Format("Error reading from input stream: {0}", exc.Message), exc);
                                }

                                offset += count;

                                try { encryptionStream.Write(buffer, 0, count); }
                                catch (Exception exc)
                                {
                                    throw new Exception(String.Format("Error writing to output stream: {0}", exc.Message), exc);
                                }

                                bytesRead += count;
                            } while (count > 0);

                            try { encryptionStream.FlushFinalBlock(); }
                            catch (Exception exc)
                            {
                                throw new Exception(String.Format("Error writing to output stream: {0}", exc.Message), exc);
                            }
                        }
                    }
                }
            }
        }

        public static void Decrypt(AppDataConfig config, Stream input, Stream output)
        {
            if (config == null)
                throw new ArgumentNullException("config");

            if (input == null)
                throw new ArgumentNullException("input");

            if (output == null)
                throw new ArgumentNullException("output");

            if (!input.CanRead)
                throw new ArgumentException("Cannot read from input stream", "input");

            if (!output.CanWrite)
                throw new ArgumentException("Cannot write to output stream", "output");

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(EncryptionHelper.AsymmetricKeySize))
            {
                config.InitializeDecryptionProvider(rsa);

                using (RijndaelManaged rjndl = new RijndaelManaged())
                {
                    rjndl.KeySize = EncryptionHelper.SymmetricKeySize;
                    rjndl.BlockSize = EncryptionHelper.BlockSize;
                    rjndl.Mode = EncryptionHelper.Mode;

                    // Get bytes for length of encrypted key data
                    byte[] buffer = new byte[4];
                    if (input.Read(buffer, 0, buffer.Length) < 4)
                        throw new Exception("Unexpected end of stream while reading key length");
                    int length = BitConverter.ToInt32(buffer, 0);
                    if (length < 1)
                        throw new Exception("Invalid key length");
                    // Create buffer to read encrypted key data
                    byte[] keyEncrypted = new byte[length];

                    // Get bytes for length of initialization vector data
                    if (input.Read(buffer, 0, buffer.Length) < 4)
                        throw new Exception("Unexpected end of stream while reading IV length");
                    length = BitConverter.ToInt32(buffer, 0);
                    if (length < 1)
                        throw new Exception("Invalid IV length");
                    // Create buffer to read initialization vector
                    buffer = new byte[length];

                    // Read encrypted key data
                    if (input.Read(keyEncrypted, 0, keyEncrypted.Length) < keyEncrypted.Length)
                        throw new EndOfStreamException("Unexpected end of stream while reading key data");

                    // Read initialization vector data
                    if (input.Read(buffer, 0, buffer.Length) < buffer.Length)
                        throw new EndOfStreamException("Unexpected end of stream while reading IV data");

                    using (ICryptoTransform transform = rjndl.CreateDecryptor(rsa.Decrypt(keyEncrypted, true), buffer))
                    {
                        CryptoStream decryptionStream;
                        try { decryptionStream = new CryptoStream(output, transform, CryptoStreamMode.Read); }
                        catch (Exception exc)
                        {
                            throw new Exception(String.Format("Error creation decryption stream: {0}", exc.Message), exc);
                        }

                        using (decryptionStream)
                        {
                            buffer = new byte[rjndl.BlockSize / 8];
                            int count = 0;
                            int offset = 0;
                            int bytesRead = 0;

                            do
                            {
                                try { count = input.Read(buffer, 0, buffer.Length); }
                                catch (Exception exc)
                                {
                                    throw new Exception(String.Format("Error reading from input stream: {0}", exc.Message), exc);
                                }

                                offset += count;

                                try { decryptionStream.Write(buffer, 0, count); }
                                catch (Exception exc)
                                {
                                    throw new Exception(String.Format("Error writing to output stream: {0}", exc.Message), exc);
                                }
                                
                                bytesRead += count;
                            } while (count > 0);

                            decryptionStream.FlushFinalBlock();
                        }
                    }
                }
            }
        }

        public static string MemoryStreamToBase64Text(MemoryStream memoryStream)
        {
            if (memoryStream == null)
                throw new ArgumentNullException("memoryStream");

            return Convert.ToBase64String(memoryStream.ToArray());
        }

        public static MemoryStream Base64TextToMemoryStream(string base64Text)
        {
            if (base64Text == null)
                throw new ArgumentNullException("base64Text");

            if (base64Text.Trim().Length == 0)
                throw new ArgumentException("base64Text cannot be empty.", "base64Text");

            return new MemoryStream(Convert.FromBase64String(base64Text.Trim()));
        }
    }
}
