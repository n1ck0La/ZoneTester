using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ZoneTester
{
    public class MainForm : Form
    {
        private Button btnRed;
        private Button btnBlack;
        private RichTextBox logBox; // color-capable

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
                ReadOnly = true,
                DetectUrls = false,
                WordWrap = false,
                Left = 12,
                Top = 60,
                Width = ClientSize.Width - 24,
                Height = ClientSize.Height - 72,
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                Font = new Font("Consolas", 10),
                BackColor = Color.White
            };

            Controls.Add(btnRed);
            Controls.Add(btnBlack);
            Controls.Add(logBox);

            btnRed.Click += async (_, __) => await RunChecklist("RED ZONE", "10.10.0.12");
            btnBlack.Click += async (_, __) => await RunChecklist("BLACK ZONE", "11.11.0.12");
        }

        // --------- Logging helpers (with colors) ----------
        private void Log(string msg, Color? color = null)
        {
            var ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            AppendColored($"[{ts}] {msg}\r\n", color ?? Color.DimGray);
        }

        private void AppendColored(string text, Color color)
        {
            logBox.SelectionStart = logBox.TextLength;
            logBox.SelectionLength = 0;
            logBox.SelectionColor = color;
            logBox.AppendText(text);
            logBox.SelectionColor = Color.Black;
            logBox.ScrollToCaret();
        }

        private Color Ok => Color.FromArgb(0, 128, 0);     // green
        private Color Fail => Color.FromArgb(178, 34, 34); // red
        private Color Info => Color.DimGray;               // gray
        private Color Warn => Color.DarkOrange;

        // --------------- Main flow ----------------
        private async Task RunChecklist(string zone, string targetIp)
        {
            btnRed.Enabled = btnBlack.Enabled = false;
            try
            {
                Log($"\r\n===== {zone} start =====", Info);

                // 1) Wired NICs & IPs + zone highlighting
                ShowWiredNicInfoAndHighlight(zone);

                // 2) Ping
                bool pingOk = await PingHost(targetIp);

                // 3) HTTP (curl -L equivalent)
                bool httpOk = await HttpProbeFollowRedirects(targetIp);

                // 4) “Winbox-like” discovery without drivers
                await DiscoverManagementIp();

                // Summary line
                Log($"Summary: Ping {(pingOk ? "PASS" : "FAIL")}, HTTP {(httpOk ? "PASS" : "FAIL")}", (pingOk && httpOk) ? Ok : (pingOk || httpOk) ? Warn : Fail);
                Log($"===== {zone} done =====", Info);
            }
            catch (Exception ex)
            {
                Log($"ERROR: {ex.Message}", Fail);
            }
            finally
            {
                btnRed.Enabled = btnBlack.Enabled = true;
            }
        }

        // --------------- Step 1: Wired NICs + zone highlighting ---------------
        private void ShowWiredNicInfoAndHighlight(string zone)
        {
            try
            {
                Log("Wired NICs & IPs:", Info);

                var nics = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n =>
                        n.OperationalStatus == OperationalStatus.Up &&
                        n.NetworkInterfaceType == NetworkInterfaceType.Ethernet &&   // only wired
                        !n.Description.Contains("Virtual", StringComparison.OrdinalIgnoreCase) &&
                        !n.Description.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase) &&
                        !n.Description.Contains("Bluetooth", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (nics.Count == 0)
                {
                    Log("No active wired interfaces found.", Warn);
                    return;
                }

                foreach (var nic in nics)
                {
                    AppendColored($"IF: {nic.Name} ({nic.Description})\r\n", Info);

                    var ipProps = nic.GetIPProperties();
                    foreach (var ua in ipProps.UnicastAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork))
                    {
                        var ip = ua.Address;
                        bool isExpected = IsIpInZoneSubnet(ip, zone);
                        var color = isExpected ? Ok : Fail;
                        AppendColored($"  IPv4: {ip}  (zone {(isExpected ? "MATCH" : "MISMATCH")})\r\n", color);
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"NIC enumeration failed: {ex.Message}", Fail);
            }
        }

        private bool IsIpInZoneSubnet(IPAddress ip, string zone)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
            var b = ip.GetAddressBytes();
            if (zone.Contains("RED", StringComparison.OrdinalIgnoreCase))
            {
                // consider 10.10.0.0/16 a “match”
                return b[0] == 10 && b[1] == 10;
            }
            else
            {
                // BLACK ZONE: 11.11.0.0/16
                return b[0] == 11 && b[1] == 11;
            }
        }

        // --------------- Step 2: Ping ---------------
        private async Task<bool> PingHost(string ip)
        {
            try
            {
                Log($"Pinging {ip} …", Info);
                using var ping = new Ping();
                var rtts = new List<long>();
                for (int i = 0; i < 4; i++)
                {
                    var reply = await ping.SendPingAsync(ip, 1500);
                    if (reply.Status == IPStatus.Success)
                    {
                        rtts.Add(reply.RoundtripTime);
                        Log($"Ping {i + 1}: {reply.RoundtripTime} ms", Ok);
                    }
                    else
                    {
                        Log($"Ping {i + 1}: {reply.Status}", Fail);
                    }
                }

                if (rtts.Count > 0)
                {
                    var min = rtts.Min();
                    var max = rtts.Max();
                    var avg = rtts.Average();
                    Log($"Ping OK — rtt ms (min/avg/max): {min}/{Math.Round(avg, 2)}/{max}", Ok);
                    return true;
                }
                else
                {
                    Log("Ping FAILED.", Fail);
                    return false;
                }
            }
            catch (Exception ex)
            {
                Log($"Ping error: {ex.Message}", Fail);
                return false;
            }
        }

        // --------------- Step 3: HTTP with follow-redirects (curl -L) ---------------
        private async Task<bool> HttpProbeFollowRedirects(string ip)
        {
            try
            {
                var handler = new HttpClientHandler
                {
                    AllowAutoRedirect = true,            // follow redirects like curl -L
                    MaxAutomaticRedirections = 10        // similar to curl’s default tolerance
                };
                using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
                var url = $"http://{ip}/";
                Log($"HTTP GET (follow redirects) {url} …", Info);

                var resp = await http.GetAsync(url);
                var finalUrl = resp.RequestMessage?.RequestUri?.ToString() ?? url;
                var body = await resp.Content.ReadAsStringAsync();

                var ok = (int)resp.StatusCode < 400;
                Log($"HTTP {(int)resp.StatusCode} {resp.ReasonPhrase} — Final URL: {finalUrl}", ok ? Ok : Fail);

                var preview = body.Length > 300 ? body.Substring(0, 300) + " …" : body;
                if (!string.IsNullOrWhiteSpace(preview))
                {
                    AppendColored("Body preview:\r\n", Info);
                    foreach (var line in preview.Replace("\r", "").Split('\n'))
                        AppendColored(line + "\r\n", Info);
                }
                return ok;
            }
            catch (Exception ex)
            {
                Log($"HTTP error: {ex.Message}", Fail);
                return false;
            }
        }

        // --------------- Step 4: Management IP discovery (no Npcap) ---------------
        private async Task DiscoverManagementIp()
        {
            Log("Management IP discovery …", Info);

            // 4A) Windows LLDP (no drivers required)
            var lldp = await TryGetLldpNeighborsViaPowerShell();
            if (lldp.Count > 0)
            {
                Log("LLDP neighbors (from OS):", Ok);
                foreach (var n in lldp)
                    AppendColored(n + "\r\n", Ok);
                return;
            }

            // 4B) ARP + micro-probes
            var cidrs = GetLocalIpv4Cidrs();
            if (cidrs.Count == 0)
            {
                Log("No active IPv4 interfaces found for scanning.", Warn);
                return;
            }

            foreach (var (network, mask) in cidrs)
            {
                Log($"Scanning {network}/{mask} for MikroTik …", Info);
                var ips = Enumerate24(network);
                await PingWarmup(ips, 200);
                var arp = ReadArpTable();
                var mkCandidates = new List<string>();

                foreach (var entry in arp)
                {
                    if (!ips.Contains(entry.ip)) continue;
                    if (IsMikroTikOUI(entry.mac) || await QuickMikroTikProbe(entry.ip))
                        mkCandidates.Add(entry.ip);
                }

                if (mkCandidates.Count > 0)
                {
                    Log("Possible MikroTik management IPs:", Ok);
                    foreach (var ip in mkCandidates.Distinct())
                        AppendColored($"- {ip}\r\n", Ok);
                    return;
                }
            }

            Log("No MikroTik candidates found via ARP/probes.", Warn);
        }

        // ---------- Windows LLDP via PowerShell ----------
        private async Task<List<string>> TryGetLldpNeighborsViaPowerShell()
        {
            try
            {
                string script = @"
$ErrorActionPreference = 'SilentlyContinue'
if (Get-Command Get-NetLldpNeighbor -ErrorAction SilentlyContinue) {
  Get-NetLldpNeighbor | Select-Object -Property InterfaceAlias, ChassisId, PortId, SystemName, ManagementAddress | ConvertTo-Json -Depth 3
} else {
  $cls = Get-CimClass -Namespace root/StandardCimv2 -ClassName MSFT_NetLldpNeighbor -ErrorAction SilentlyContinue
  if ($cls) {
    Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetLldpNeighbor |
      Select-Object -Property InterfaceAlias, ChassisId, PortId, SystemName, ManagementAddress | ConvertTo-Json -Depth 3
  } else { ''
  }
}";
                var psi = new ProcessStartInfo("powershell", "-NoProfile -ExecutionPolicy Bypass -Command \"" + script.Replace("\"", "\\\"") + "\"")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                string json = await p!.StandardOutput.ReadToEndAsync();
                string err = await p.StandardError.ReadToEndAsync();
                p.WaitForExit();

                var list = new List<string>();
                if (string.IsNullOrWhiteSpace(json)) return list;

                try
                {
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var el in doc.RootElement.EnumerateArray())
                            list.Add(FormatLldpJson(el));
                    }
                    else if (doc.RootElement.ValueKind == JsonValueKind.Object)
                    {
                        list.Add(FormatLldpJson(doc.RootElement));
                    }
                }
                catch
                {
                    if (!string.IsNullOrWhiteSpace(json?.Trim()))
                        list.Add("Raw LLDP output: " + json.Trim());
                }
                return list;
            }
            catch
            {
                return new List<string>();
            }
        }

        private string FormatLldpJson(JsonElement el)
        {
            string Get(string name) => el.TryGetProperty(name, out var v) ? v.ToString() : "";
            var iface = Get("InterfaceAlias");
            var chassis = Get("ChassisId");
            var port = Get("PortId");
            var sys = Get("SystemName");
            var mgmt = Get("ManagementAddress");
            var parts = new List<string>();
            if (!string.IsNullOrEmpty(iface)) parts.Add($"IF={iface}");
            if (!string.IsNullOrEmpty(sys)) parts.Add($"SysName={sys}");
            if (!string.IsNullOrEmpty(chassis)) parts.Add($"ChassisID={chassis}");
            if (!string.IsNullOrEmpty(port)) parts.Add($"PortID={port}");
            if (!string.IsNullOrEmpty(mgmt)) parts.Add($"MgmtIP={mgmt}");
            return string.Join("; ", parts);
        }

        // ---------- Local /24 enumeration ----------
        private List<(IPAddress network, int mask)> GetLocalIpv4Cidrs()
        {
            var list = new List<(IPAddress, int)>();
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType != NetworkInterfaceType.Ethernet) continue; // only wired

                var ipProps = nic.GetIPProperties();
                foreach (var ua in ipProps.UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (ua.IPv4Mask == null) continue;

                    var b = ua.Address.GetAddressBytes();
                    var network = new IPAddress(new byte[] { b[0], b[1], b[2], 0 });
                    list.Add((network, 24));
                }
            }
            return list;
        }

        private HashSet<string> Enumerate24(IPAddress network)
        {
            var set = new HashSet<string>();
            var b = network.GetAddressBytes();
            for (int host = 1; host <= 254; host++)
                set.Add($"{b[0]}.{b[1]}.{b[2]}.{host}");
            return set;
        }

        private async Task PingWarmup(IEnumerable<string> ips, int timeoutMs)
        {
            var tasks = ips.Select(async ip =>
            {
                try { using var p = new Ping(); await p.SendPingAsync(ip, timeoutMs); }
                catch { }
            });

            // throttle in chunks
            foreach (var chunk in Chunk(ips, 64))
                await Task.WhenAll(chunk.Select(async ip => {
                    try { using var p = new Ping(); await p.SendPingAsync(ip, timeoutMs); } catch { }
                }));
        }

        // ---------- ARP ----------
        private List<(string ip, string mac)> ReadArpTable()
        {
            try
            {
                var psi = new ProcessStartInfo("arp", "-a")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                var output = p!.StandardOutput.ReadToEnd();
                p.WaitForExit();

                var list = new List<(string, string)>();
                foreach (var line in output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 3 && IPAddress.TryParse(parts[0], out _))
                    {
                        var ip = parts[0];
                        var mac = parts[1].Replace("-", ":").ToUpperInvariant();
                        list.Add((ip, mac));
                    }
                }
                return list;
            }
            catch
            {
                return new List<(string, string)>();
            }
        }

        // ---------- MikroTik heuristics ----------
        private static readonly string[] MikroTikOuiPrefixes =
        {
            "4C:5E:0C", "CC:2D:E0", "DC:2C:6E", "D4:CA:6D", "E4:8D:8C",
            "64:D1:54", "B8:69:F4", "F4:8E:38", "F4:1E:26", "18:FD:74"
        };

        private bool IsMikroTikOUI(string mac)
        {
            if (string.IsNullOrWhiteSpace(mac)) return false;
            foreach (var p in MikroTikOuiPrefixes)
                if (mac.StartsWith(p, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        private async Task<bool> QuickMikroTikProbe(string ip)
        {
            if (await CanConnect(ip, 8291, 300)) return true; // Winbox
            if (await CanConnect(ip, 8728, 300)) return true; // API

            try
            {
                using var http = new HttpClient() { Timeout = TimeSpan.FromSeconds(1.5) };
                using var req = new HttpRequestMessage(HttpMethod.Head, $"http://{ip}/");
                var resp = await http.SendAsync(req);
                if (resp.Headers.TryGetValues("Server", out var sv))
                    if (sv.Any(v => v.Contains("RouterOS", StringComparison.OrdinalIgnoreCase)))
                        return true;
            }
            catch { }
            return false;
        }

        private async Task<bool> CanConnect(string ip, int port, int timeoutMs)
        {
            try
            {
                using var client = new TcpClient();
                var task = client.ConnectAsync(ip, port);
                var tmo = Task.Delay(timeoutMs);
                var done = await Task.WhenAny(task, tmo);
                return done == task && client.Connected;
            }
            catch { return false; }
        }

        // small chunk helper
        private static IEnumerable<IEnumerable<T>> Chunk<T>(IEnumerable<T> source, int size)
        {
            var bucket = new List<T>(size);
            foreach (var item in source)
            {
                bucket.Add(item);
                if (bucket.Count == size)
                {
                    yield return bucket.ToArray();
                    bucket.Clear();
                }
            }
            if (bucket.Count > 0) yield return bucket.ToArray();
        }
    }
}
