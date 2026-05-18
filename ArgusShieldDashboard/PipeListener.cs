using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace ArgusShieldDashboard
{
    public class PipeListener
    {
        private const string PIPE_NAME = "ArgusShieldAgent";
        private CancellationTokenSource _cts = new CancellationTokenSource();
        private Task? _listenTask;

        public event Action<Dictionary<string, string>>? AlertReceived;
        public event Action<Dictionary<string, string>>? ImageLoadReceived;
        public event Action<bool>? ConnectionChanged;

        public void Start()
        {
            _cts = new CancellationTokenSource();
            _listenTask = Task.Run(() => ListenLoop(_cts.Token));
        }

        public void Stop()
        {
            _cts.Cancel();
            _listenTask?.Wait();
        }

        private async Task ListenLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                using var stream = new NamedPipeClientStream(".", PIPE_NAME, PipeDirection.In, PipeOptions.None);
                try
                {
                    await stream.ConnectAsync(2000, token);
                    ConnectionChanged?.Invoke(true);

                    using var reader = new StreamReader(stream);
                    while (!token.IsCancellationRequested && stream.IsConnected)
                    {
                        var line = await reader.ReadLineAsync();
                        if (line == null) break;

                        line = line.Trim();
                        if (string.IsNullOrEmpty(line)) continue;

                        DispatchLine(line);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception)
                {
                    // Connection failed or lost, retry after 2 seconds
                }
                finally
                {
                    ConnectionChanged?.Invoke(false);
                }

                if (!token.IsCancellationRequested)
                {
                    try { await Task.Delay(2000, token); }
                    catch { break; }
                }
            }
        }

        private void DispatchLine(string line)
        {
            if (line.StartsWith("InjectionAlert|"))
            {
                AlertReceived?.Invoke(ParseFields(line));
            }
            else if (line.StartsWith("ImageLoad|"))
            {
                ImageLoadReceived?.Invoke(ParseFields(line));
            }
        }

        private Dictionary<string, string> ParseFields(string line)
        {
            var result = new Dictionary<string, string>();
            var tokens = line.Split('|');
            foreach (var token in tokens)
            {
                var idx = token.IndexOf('=');
                if (idx > 0)
                {
                    var key = token.Substring(0, idx);
                    var value = token.Substring(idx + 1);
                    result[key] = value;
                }
            }
            return result;
        }
    }
}
