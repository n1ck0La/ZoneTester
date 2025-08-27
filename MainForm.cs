using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Drawing;
using PacketDotNet;           // EthernetPacket, Packet
using SharpPcap;              // API + GetPacketStatus
using SharpPcap.LibPcap;      // LibPcapLiveDevice (filter support)

namespace ZoneTester
{
    public class MainForm : Form
    {
        private Button btnRed;
        private Button btnBlack;
        private RichTextBox logBox;

        public MainForm()
        {
            Text = "Zone Tester";
            Width = 900;
            Height = 600;
            StartPosition = FormStartPosition.CenterScreen;

            btnRed = new Button { Text = "Test Red Zone", Left = 12, Top = 12, Width = 140, Height = 34 };
            btnBlack = new Button { Text = "Test Black Zone", Left = 162, Top = 12, Width = 140, Height = 34 };
            logBox = new RichTextBox
            {
                Multiline = true,
                ReadOnly = true,
                ScrollBars = RichTextBoxScrollBars.Both,
                WordWrap = false,
                Left = 12,
                Top = 60,
                Width = ClientSize.Width - 24,
                Height = ClientSize.Height - 72,
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                Font = new Font("Consolas", 10)
            };

            Controls.Add(btnRed);
            Controls.Add(btnBlack);
            Controls.Add(logBox);

            btnRed.Click += async (_, __) => await RunChecklist("RED ZONE", "10.10.0.12");
            btnBlack.Click += async (_, __) => await RunChecklist("BLACK ZONE", "11.11.0.12");
        }

        private async Task RunChecklist(string zone, string targetIp)
        {
            btnRed.Enabled = btnBlack.Enabled = false;
            try
            {
                Log($"\n===== {zone} start =====");

                ShowDhcpInfo();             // 1) DHCP/IP
                await PingHost(targetIp);   // 2) Ping
                await HttpProbe(targetIp);  // 3) HTTP
                await LldpScanAsync();      // 4) LLDP

                Log($"===== {zone} done =====");
            }
            catch (Exception ex)
            {
                Log($"ERROR: {ex.Message}");
            }
            finally
            {
                btnRed.Enabled = btnBlack.Enabled = true;
            }
        }

        private void Log(string msg, Color? color = null)
        {
            var ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            logBox.SelectionColor = color ?? logBox.ForeColor;
            logBox.AppendText($"[{ts}] {msg}\r\n");
            logBox.SelectionColor = logBox.ForeColor;
        }

        // --- Step 1: Wired NIC IP info ---
        private void ShowDhcpInfo()
        {
            try
            {
                Log("Wired NIC IPs:");

                var nics = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => IsWired(n));

                if (!nics.Any())
                {
                    Log("No wired network interfaces found.");
                    return;
                }

                foreach (var nic in nics)
                {
                    Log($"{nic.Name} - {nic.Description}");
                    var ips = nic.GetIPProperties().UnicastAddresses
                        .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork);

                    foreach (var ipInfo in ips)
                    {
                        var ip = ipInfo.Address;
                        if (IsRedZone(ip))
                            Log($"  {ip} (redzone)", Color.Green);
                        else if (IsBlackZone(ip))
                            Log($"  {ip} (blackzone)", Color.Green);
                        else
                            Log($"  {ip}", Color.Red);
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"NIC enumeration failed: {ex.Message}");
            }
        }

        private static bool IsWired(NetworkInterface ni)
        {
            switch (ni.NetworkInterfaceType)
            {
                case NetworkInterfaceType.Ethernet:
                case NetworkInterfaceType.Ethernet3Megabit:
                case NetworkInterfaceType.FastEthernetFx:
                case NetworkInterfaceType.FastEthernetT:
                case NetworkInterfaceType.GigabitEthernet:
                    return true;
                default:
                    return false;
            }
        }

        private static bool IsRedZone(IPAddress ip)
        {
            var b = ip.GetAddressBytes();
            return b.Length >= 2 && b[0] == 10 && b[1] == 10;
        }

        private static bool IsBlackZone(IPAddress ip)
        {
            var b = ip.GetAddressBytes();
            return b.Length >= 2 && b[0] == 11 && b[1] == 11;
        }

        // --- Step 2: Ping target ---
        private async Task PingHost(string ip)
        {
            try
            {
                Log($"Pinging {ip} …");
                using var ping = new Ping();
                var rtts = new double[4];
                int ok = 0;

                for (int i = 0; i < 4; i++)
                {
                    var reply = await ping.SendPingAsync(ip, 2000);
                    if (reply.Status == IPStatus.Success)
                    {
                        rtts[ok++] = reply.RoundtripTime;
                        Log($"Ping {i + 1}: {reply.RoundtripTime} ms");
                    }
                    else
                    {
                        Log($"Ping {i + 1}: {reply.Status}");
                    }
                }

                if (ok > 0)
                {
                    var min = rtts.Take(ok).Min();
                    var max = rtts.Take(ok).Max();
                    var avg = rtts.Take(ok).Average();
                    Log($"Ping OK — rtt ms (min/avg/max): {min}/{Math.Round(avg, 2)}/{max}", Color.Green);
                }
                else
                {
                    Log("Ping FAILED.", Color.Red);
                }
            }
            catch (Exception ex) { Log($"Ping error: {ex.Message}", Color.Red); }
        }

        // --- Step 3: HTTP GET (curl-equivalent) ---
        private async Task HttpProbe(string ip)
        {
            try
            {
                var handler = new HttpClientHandler { AllowAutoRedirect = true };
                using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
                var url = $"http://{ip}/";
                Log($"HTTP GET {url} …");
                var resp = await http.GetAsync(url);
                var finalUrl = resp.RequestMessage?.RequestUri?.ToString();
                if (!string.IsNullOrEmpty(finalUrl) && finalUrl != url)
                {
                    Log($"Redirected to {finalUrl}");
                }
                var body = await resp.Content.ReadAsStringAsync();
                Log($"HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}",
                    resp.IsSuccessStatusCode ? Color.Green : Color.Red);
                var preview = body.Length > 200 ? body.Substring(0, 200) + " …" : body;
                Log("Body preview:");
                foreach (var line in preview.Replace("\r", "").Split('\n'))
                    Log(line);
            }
            catch (Exception ex) { Log($"HTTP error: {ex.Message}", Color.Red); }
        }

        // --- Step 4: LLDP discovery (reflection-based polling; works with SharpPcap 6.x or 7.x) ---
        private async Task LldpScanAsync()
        {
            try
            {
                Log("LLDP scan (4s) …");

                var devices = CaptureDeviceList.Instance;
                if (devices == null || devices.Count == 0)
                {
                    Log("No capture devices found. Install Npcap (WinPcap-compatible mode), then reboot.");
                    return;
                }

                // pick first non-loopback device
                var dev = devices.FirstOrDefault(d =>
                    !d.Description.Contains("Loopback", StringComparison.OrdinalIgnoreCase) &&
                    !d.Name.Contains("Loopback", StringComparison.OrdinalIgnoreCase));

                if (dev == null)
                {
                    Log("No suitable NIC for capture.");
                    return;
                }

                var neighbors = new StringBuilder();

                dev.Open(); // default open

                // Apply LLDP filter when supported
                if (dev is LibPcapLiveDevice live)
                {
                    live.Filter = "ether proto 0x88cc";
                }

                // via reflection to support both 6.x (RawCapture) and 7.x (PacketCapture)
                var method = dev.GetType()
                                .GetMethods(BindingFlags.Instance | BindingFlags.Public)
                                .FirstOrDefault(m =>
                                    m.Name == "GetNextPacket" &&
                                    m.GetParameters().Length == 1 &&
                                    m.GetParameters()[0].ParameterType.IsByRef);

                if (method == null)
                {
                    dev.Close();
                    Log("GetNextPacket method not found on device.");
                    return;
                }

                var stopAt = DateTime.UtcNow.AddSeconds(4);
                while (DateTime.UtcNow < stopAt)
                {
                    object[] args = new object[] { null! };
                    var statusObj = method.Invoke(dev, args);
                    var status = (GetPacketStatus)statusObj!;

                    if (status != GetPacketStatus.PacketRead || args[0] == null)
                    {
                        await Task.Delay(25);
                        continue;
                    }

                    try
                    {
                        // Extract RawCapture regardless of 6.x/7.x
                        // 6.x: args[0] is RawCapture
                        // 7.x: args[0] is PacketCapture => call GetPacket() -> RawCapture
                        byte[] data;
                        LinkLayers linkType;

                        var capObj = args[0];
                        var capTypeName = capObj.GetType().Name;

                        if (capTypeName == "RawCapture")
                        {
                            // RawCapture has LinkLayerType + Data props
                            var linkProp = capObj.GetType().GetProperty("LinkLayerType");
                            var dataProp = capObj.GetType().GetProperty("Data");
                            linkType = (LinkLayers)linkProp!.GetValue(capObj)!;
                            data = (byte[])dataProp!.GetValue(capObj)!;
                        }
                        else
                        {
                            // PacketCapture: call GetPacket() -> RawCapture
                            var getPacket = capObj.GetType().GetMethod("GetPacket", Type.EmptyTypes);
                            var raw = getPacket!.Invoke(capObj, null);
                            var linkProp = raw!.GetType().GetProperty("LinkLayerType");
                            var dataProp = raw.GetType().GetProperty("Data");
                            linkType = (LinkLayers)linkProp!.GetValue(raw)!;
                            data = (byte[])dataProp!.GetValue(raw)!;
                        }

                        var packet = Packet.ParsePacket(linkType, data);
                        if (packet is EthernetPacket eth && (ushort)eth.Type == 0x88cc) // LLDP
                        {
                            var payload = eth.PayloadData;
                            var info = ParseLldp(payload);
                            if (!string.IsNullOrEmpty(info))
                            {
                                lock (neighbors) neighbors.AppendLine(info);
                            }
                        }
                    }
                    catch
                    {
                        // ignore malformed frames
                    }
                }

                dev.Close();

                var outStr = neighbors.ToString().Trim();
                if (string.IsNullOrEmpty(outStr))
                    Log("No LLDP neighbors heard (enable LLDP on MikroTik bridge/ports; run app as Administrator).");
                else
                {
                    Log("LLDP neighbors:");
                    foreach (var line in outStr.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                        Log(line);
                }
            }
            catch (Exception ex)
            {
                Log($"LLDP scan failed: {ex.Message}. Try running the EXE as Administrator.");
            }
        }

        // Minimal LLDP TLV parser (ChassisID, PortID, SystemName, MgmtAddress)
        private static string ParseLldp(byte[] payload)
        {
            int idx = 0;
            string chassis = "", port = "", sysName = "", mgmtAddr = "";
            while (idx + 2 <= payload.Length)
            {
                ushort hdr = (ushort)((payload[idx] << 8) | payload[idx + 1]);
                idx += 2;
                int type = (hdr >> 9) & 0x7F;
                int len = hdr & 0x1FF;
                if (len < 0 || idx + len > payload.Length) break;

                switch (type)
                {
                    case 0: // End
                        idx = payload.Length;
                        break;

                    case 1: // Chassis ID
                        if (len > 1)
                        {
                            byte subtype = payload[idx];
                            var val = Encoding.ASCII.GetString(payload, idx + 1, len - 1);
                            chassis = $"{val} (subtype {subtype})";
                        }
                        break;

                    case 2: // Port ID
                        if (len > 1)
                        {
                            byte subtype = payload[idx];
                            var val = Encoding.ASCII.GetString(payload, idx + 1, len - 1);
                            port = $"{val} (subtype {subtype})";
                        }
                        break;

                    case 5: // System Name
                        if (len > 0)
                            sysName = Encoding.ASCII.GetString(payload, idx, len);
                        break;

                    case 8: // Management Address TLV
                        if (len > 1)
                        {
                            int n = payload[idx]; // mgmt addr string len
                            if (n >= 2 && 1 + n <= len)
                            {
                                byte afi = payload[idx + 1]; // 1=IPv4, 2=IPv6
                                if (afi == 1 && n >= 1 + 1 + 4)
                                {
                                    int a0 = payload[idx + 2];
                                    int a1 = payload[idx + 3];
                                    int a2 = payload[idx + 4];
                                    int a3 = payload[idx + 5];
                                    mgmtAddr = $"{a0}.{a1}.{a2}.{a3}";
                                }
                                else if (afi == 2 && n >= 1 + 1 + 16)
                                {
                                    var addr = new byte[16];
                                    Buffer.BlockCopy(payload, idx + 2, addr, 0, 16);
                                    mgmtAddr = new System.Net.IPAddress(addr).ToString();
                                }
                            }
                        }
                        break;
                }

                idx += len;
            }

            if (string.IsNullOrEmpty(chassis) && string.IsNullOrEmpty(port) &&
                string.IsNullOrEmpty(sysName) && string.IsNullOrEmpty(mgmtAddr))
                return string.Empty;

            var sb = new StringBuilder();
            if (!string.IsNullOrEmpty(sysName)) sb.Append($"SysName={sysName}; ");
            if (!string.IsNullOrEmpty(chassis)) sb.Append($"ChassisID={chassis}; ");
            if (!string.IsNullOrEmpty(port)) sb.Append($"PortID={port}; ");
            if (!string.IsNullOrEmpty(mgmtAddr)) sb.Append($"MgmtIP={mgmtAddr}; ");
            return sb.ToString().Trim();
        }
    }
}
