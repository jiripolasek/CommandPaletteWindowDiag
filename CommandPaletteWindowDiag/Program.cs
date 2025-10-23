using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace CommandPaletteWindowDiag
{
    internal class Program
    {
        // GWL indexes
        private const int GWL_STYLE = -16;
        private const int GWL_EXSTYLE = -20;

        // Extended styles
        private const int WS_EX_TOOLWINDOW = 0x00000080;
        private const int WS_EX_APPWINDOW = 0x00040000;

        // SetWindowPos flags
        private const uint SWP_NOSIZE = 0x0001;
        private const uint SWP_NOMOVE = 0x0002;
        private const uint SWP_NOZORDER = 0x0004;
        private const uint SWP_NOOWNERZORDER = 0x0200;
        private const uint SWP_FRAMECHANGED = 0x0020;

        // GetWindow commands
        private const uint GW_OWNER = 4;

        // Process access rights
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        // Token constants
        private const uint TOKEN_QUERY = 0x0008;
        private const int TokenElevation = 20; // TOKEN_INFORMATION_CLASS.TokenElevation

        static void Main(string[] args)
        {
            try
            {
                Console.OutputEncoding = Encoding.UTF8;

                string targetProcessName = args != null && args.Length > 0 ? args[0] : "Microsoft.CmdPal.UI.exe";
                targetProcessName = NormalizeProcessName(targetProcessName);

                var processes = Process.GetProcessesByName(targetProcessName);
                if (processes.Length == 0)
                {
                    WriteError($"Process not found: {targetProcessName}\n- Make sure the process is running.\n- Pass a custom name as the first argument if different.\n- Try running this tool as Administrator if the UI is elevated.");
                    Environment.ExitCode = 1;
                    return;
                }

                // Determine current process elevation
                var currElev = IsProcessElevatedSafe(Environment.ProcessId, out _);

                foreach (var proc in processes)
                {
                    Console.WriteLine($"Process: {proc.ProcessName} (PID {proc.Id})");

                    // Check for privilege mismatch (best-effort)
                    var targetElev = IsProcessElevatedSafe(proc.Id, out var elevReason);
                    if (currElev == false && targetElev == true)
                    {
                        WriteError("Privilege mismatch: target process is elevated (Admin) but this tool is not. Run this tool as Administrator to modify its windows.");
                    }
                    else if (targetElev == null && !string.IsNullOrEmpty(elevReason))
                    {
                        // Could not determine elevation - hint to user
                        WriteError($"Could not determine elevation for PID {proc.Id}: {elevReason}\nIf the target is elevated, run this tool as Administrator.");
                    }

                    PrintSeparator();

                    var topWindows = new List<IntPtr>(EnumerateTopLevelWindows(proc.Id));
                    if (topWindows.Count == 0)
                    {
                        WriteError("No top-level windows found for this process. The UI may be hosted elsewhere, minimized to tray, or not currently showing any top-level windows.");
                    }

                    for (int i = 0; i < topWindows.Count; i++)
                    {
                        if (i > 0)
                        {
                            PrintSeparator();
                        }

                        var hwnd = topWindows[i];
                        bool isLast = i == topWindows.Count - 1;

                        // Tree print starting from each top-level window
                        PrintWindowTree(proc.Id, hwnd, prefix: string.Empty, isLast: isLast, isRoot: true);

                        // Attempt to hide the "Command Palette" window from the taskbar (top-level only)
                        string title = GetWindowTitle(hwnd);
                        nint exStyle = GetWindowLongPtrSafe(hwnd, GWL_EXSTYLE);
                        if (!string.IsNullOrWhiteSpace(title) && title.Contains("Command Palette", StringComparison.OrdinalIgnoreCase))
                        {
                            TryHideFromTaskbar(hwnd, exStyle);
                        }
                    }

                    PrintSeparator();
                }
            }
            catch (Exception ex)
            {
                WriteError($"Unexpected error: {ex.Message}");
                Environment.ExitCode = 1;
            }

            // Wait for user input before closing
            Console.WriteLine("Press Enter to exit...");
            Console.ReadLine();
        }

        private static void PrintSeparator()
        {
            var def = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(new string('─', 80));
            Console.ForegroundColor = def;
        }

        private static void PrintWindowTree(int processId, IntPtr hwnd, string prefix, bool isLast, bool isRoot)
        {
            string connector = isLast ? "└──" : "├──";
            string line = $"{prefix}{connector} {FormatWindowLine(hwnd)}";

            WriteLineHighlighted(line, hwnd, isRoot);

            var children = GetChildWindows(hwnd, processId);
            string childPrefix = prefix + (isLast ? " " : "│ ");
            for (int i = 0; i < children.Count; i++)
            {
                PrintWindowTree(processId, children[i], childPrefix, i == children.Count - 1, isRoot: false);
            }
        }

        private static void WriteLineHighlighted(string text, IntPtr hwnd, bool isRoot)
        {
            var def = Console.ForegroundColor;

            // Simple highlighting rules:
            // - Title contains "Command Palette": Yellow highlight
            // - Root visible windows: White; root hidden: DarkGray
            // - Child visible windows: Cyan; child hidden: DarkGray
            string title = GetWindowTitle(hwnd);
            bool visible = IsWindowVisible(hwnd);

            ConsoleColor color;
            if (!string.IsNullOrEmpty(title) && title.Contains("Command Palette", StringComparison.OrdinalIgnoreCase))
            {
                color = ConsoleColor.Yellow;
            }
            else if (isRoot)
            {
                color = visible ? ConsoleColor.White : ConsoleColor.DarkGray;
            }
            else
            {
                color = visible ? ConsoleColor.Cyan : ConsoleColor.DarkGray;
            }

            Console.ForegroundColor = color;
            Console.WriteLine(text);
            Console.ForegroundColor = def;
        }

        private static string FormatWindowLine(IntPtr hwnd)
        {
            string title = GetWindowTitle(hwnd);
            string className = GetWindowClassName(hwnd);
            bool visible = IsWindowVisible(hwnd);
            nint style = GetWindowLongPtrSafe(hwnd, GWL_STYLE);
            nint exStyle = GetWindowLongPtrSafe(hwnd, GWL_EXSTYLE);
            IntPtr owner = GetWindow(hwnd, GW_OWNER);

            string titlePart = string.IsNullOrEmpty(title) ? "<no title>" : $"\"{title}\"";
            string classPart = string.IsNullOrEmpty(className) ? "<no class>" : className;
            string ownerPart = $"0x{owner.ToInt64():X}";
            string flags = $"APP={(HasFlag(exStyle, WS_EX_APPWINDOW) ? 1 : 0)},TOOL={(HasFlag(exStyle, WS_EX_TOOLWINDOW) ? 1 : 0)}";

            return $"[0x{hwnd.ToInt64():X}] {titlePart} class={classPart} owner={ownerPart} visible={(visible ? 1 : 0)} style=0x{style.ToInt64():X8} ex=0x{exStyle.ToInt64():X8} [{flags}]";
        }

        private static string NormalizeProcessName(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return name;
            name = name.Trim();
            if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                name = name.Substring(0, name.Length - 4);
            }
            return name;
        }

        private static void TryHideFromTaskbar(IntPtr hwnd, nint currentExStyle)
        {
            try
            {
                int ex = (int)currentExStyle;
                int newEx = (ex & ~WS_EX_APPWINDOW) | WS_EX_TOOLWINDOW;
                if (newEx != ex)
                {
                    var prev = SetWindowLongPtrSafe(hwnd, GWL_EXSTYLE, (nint)newEx);
                    int lastError = Marshal.GetLastWin32Error();

                    if (prev == nint.Zero && lastError != 0)
                    {
                        HandleWin32Error("SetWindowLongPtr(GWL_EXSTYLE)", lastError,
                            "Access denied while changing window styles. If the target is elevated, run this tool as Administrator.");
                    }
                    else
                    {
                        // Apply frame change so shell updates taskbar presence
                        bool ok = SetWindowPos(hwnd, IntPtr.Zero, 0, 0, 0, 0,
                            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
                        if (!ok)
                        {
                            HandleWin32Error("SetWindowPos(SWP_FRAMECHANGED)", Marshal.GetLastWin32Error(),
                                "Failed to refresh window frame after style change.");
                        }
                        else
                        {
                            Console.WriteLine("Attempted to hide window from taskbar by toggling EX styles (removed APPWINDOW, added TOOLWINDOW).");
                        }
                    }
                }
                else
                {
                    Console.WriteLine("No EX style change required (already TOOLWINDOW without APPWINDOW).");
                }
            }
            catch (Exception ex)
            {
                WriteError($"Failed to modify window styles: {ex.Message}");
            }
        }

        private static void HandleWin32Error(string api, int error, string friendlyHint)
        {
            // Provide friendlier messages for common errors
            string message = error switch
            {
                5 => $"{api} failed with ERROR_ACCESS_DENIED (5). {friendlyHint}",
                87 => $"{api} failed with ERROR_INVALID_PARAMETER (87). The window might not accept this change.",
                _ => $"{api} failed with error {error}."
            };
            WriteError(message);
        }

        private static bool? IsProcessElevatedSafe(int pid, out string reason)
        {
            reason = string.Empty;
            IntPtr hProcess = IntPtr.Zero;
            IntPtr hToken = IntPtr.Zero;
            try
            {
                hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION, false, (uint)pid);
                if (hProcess == IntPtr.Zero)
                {
                    reason = $"OpenProcess failed: {Marshal.GetLastWin32Error()}";
                    return null;
                }
                if (!OpenProcessToken(hProcess, TOKEN_QUERY, out hToken))
                {
                    reason = $"OpenProcessToken failed: {Marshal.GetLastWin32Error()}";
                    return null;
                }

                int size = Marshal.SizeOf<TOKEN_ELEVATION>();
                var te = new TOKEN_ELEVATION();
                if (!GetTokenInformation(hToken, TokenElevation, out te, size, out _))
                {
                    reason = $"GetTokenInformation failed: {Marshal.GetLastWin32Error()}";
                    return null;
                }
                return te.TokenIsElevated != 0;
            }
            catch (Exception ex)
            {
                reason = ex.Message;
                return null;
            }
            finally
            {
                if (hToken != IntPtr.Zero) CloseHandle(hToken);
                if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
            }
        }

        private struct TOKEN_ELEVATION
        {
            public int TokenIsElevated;
        }

        private static List<IntPtr> GetChildWindows(IntPtr parent, int processId)
        {
            var result = new List<IntPtr>();
            EnumChildWindows(parent, (hwnd, lparam) =>
            {
                uint pid;
                GetWindowThreadProcessId(hwnd, out pid);
                if (pid == (uint)processId)
                {
                    result.Add(hwnd);
                }
                return true; // continue enumeration
            }, IntPtr.Zero);
            return result;
        }

        private static IEnumerable<IntPtr> EnumerateTopLevelWindows(int processId)
        {
            var result = new List<IntPtr>();
            EnumWindows((hwnd, lparam) =>
            {
                uint pid;
                GetWindowThreadProcessId(hwnd, out pid);
                if (pid == (uint)processId)
                {
                    result.Add(hwnd);
                }
                return true; // continue enumeration
            }, IntPtr.Zero);
            return result;
        }

        private static bool HasFlag(nint value, int flag)
        {
            return ((long)value & flag) == flag;
        }

        private static string GetWindowTitle(IntPtr hwnd)
        {
            int length = GetWindowTextLength(hwnd);
            var sb = new StringBuilder(length + 1);
            if (length > 0)
            {
                GetWindowText(hwnd, sb, sb.Capacity);
            }
            return sb.ToString();
        }

        private static string GetWindowClassName(IntPtr hwnd)
        {
            var sb = new StringBuilder(256);
            int len = GetClassName(hwnd, sb, sb.Capacity);
            return len > 0 ? sb.ToString() : string.Empty;
        }

        // P/Invoke
        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool EnumChildWindows(IntPtr hWndParent, EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetWindow(IntPtr hWnd, uint uCmd);

        // Token/elevation helpers
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, out TOKEN_ELEVATION TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        //32/64-bit safe wrappers for Get/SetWindowLongPtr
        [DllImport("user32.dll", EntryPoint = "GetWindowLong", SetLastError = true)]
        private static extern int GetWindowLong32(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll", EntryPoint = "GetWindowLongPtr", SetLastError = true)]
        private static extern nint GetWindowLongPtr64(IntPtr hWnd, int nIndex);

        private static nint GetWindowLongPtrSafe(IntPtr hWnd, int nIndex)
        {
            if (IntPtr.Size == 8)
                return GetWindowLongPtr64(hWnd, nIndex);
            return (nint)GetWindowLong32(hWnd, nIndex);
        }

        [DllImport("user32.dll", EntryPoint = "SetWindowLong", SetLastError = true)]
        private static extern int SetWindowLong32(IntPtr hWnd, int nIndex, int dwNewLong);

        [DllImport("user32.dll", EntryPoint = "SetWindowLongPtr", SetLastError = true)]
        private static extern nint SetWindowLongPtr64(IntPtr hWnd, int nIndex, nint dwNewLong);

        private static nint SetWindowLongPtrSafe(IntPtr hWnd, int nIndex, nint dwNewLong)
        {
            if (IntPtr.Size == 8)
                return SetWindowLongPtr64(hWnd, nIndex, dwNewLong);
            return (nint)SetWindowLong32(hWnd, nIndex, (int)dwNewLong);
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

        private static void WriteError(string message)
        {
            var def = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(message);
            Console.ForegroundColor = def;
        }
    }
}
