// ============================================================================
//  腾讯会议 —— 掉线自动重进  (WeMeet Auto Rejoin)
// ----------------------------------------------------------------------------
//  单文件 WinForms 程序，编译目标 .NET Framework 4.8 / x64（csc.exe 即可编译）
//
//  设计要点：
//   · 轮询阶段是【纯读操作】——只 EnumWindows 列举窗口，绝不移动/置顶/抢焦点
//   · 只有判定"已掉线"并真正要重进时，才强制把客户端窗口提到前台
//   · 每次掉线最多重进 N 次（MaxAttempts），到上限就停手，不会无限骚扰
//   · 窗口识别不依赖 Get-Process（受限环境会漏进程），
//     而是按窗口所属进程的 exe 路径判断
// ============================================================================

using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace WeMeetAutoRejoin
{
    // ---------------------------------------------------------------- Win32
    internal static class Native
    {
        public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);
        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int GetWindowText(IntPtr h, StringBuilder sb, int n);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int GetClassName(IntPtr h, StringBuilder sb, int n);
        [DllImport("user32.dll")]
        public static extern bool IsWindowVisible(IntPtr h);
        [DllImport("user32.dll")]
        public static extern bool IsIconic(IntPtr h);
        [DllImport("user32.dll")]
        public static extern bool GetWindowRect(IntPtr h, out RECT r);
        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr h);
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr h, int cmd);
        [DllImport("user32.dll")]
        public static extern bool BringWindowToTop(IntPtr h);
        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")]
        public static extern bool AttachThreadInput(uint a, uint b, bool f);
        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentThreadId();
        [DllImport("user32.dll")]
        public static extern bool SetCursorPos(int x, int y);
        [DllImport("user32.dll")]
        public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extra);
        [DllImport("user32.dll")]
        public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern bool QueryFullProcessImageNameW(IntPtr h, uint flags, StringBuilder sb, ref uint size);
        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr h);
        [DllImport("user32.dll")]
        public static extern bool SetProcessDPIAware();

        // ---- 读取本进程的完整性级别 ----
        // 用途：如果 exe 或所在文件夹带有「低完整性(Low)」标签，进程就会以 Low 运行，
        // Windows 的 UIPI 会拦截它向腾讯会议（Medium）注入的鼠标/键盘，表现为
        // 「窗口识别正常、能切前台，但点击完全没反应」。这里主动检测并明确报错。
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr info, int len, out int retLen);
        [DllImport("advapi32.dll")]
        public static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);
        [DllImport("advapi32.dll")]
        public static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        public const uint TOKEN_QUERY = 0x0008;
        public const int TokenIntegrityLevel = 25;
        public const int SECURITY_MANDATORY_LOW_RID = 0x1000;
        public const int SECURITY_MANDATORY_MEDIUM_RID = 0x2000;

        /// 返回本进程完整性级别的 RID（0x1000=Low, 0x2000=Medium, 0x3000=High），失败返回 -1
        public static int GetIntegrityRid()
        {
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out token)) return -1;
            try
            {
                int len = 0;
                GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out len);
                if (len <= 0) return -1;
                IntPtr buf = Marshal.AllocHGlobal(len);
                try
                {
                    if (!GetTokenInformation(token, TokenIntegrityLevel, buf, len, out len)) return -1;
                    IntPtr sid = Marshal.ReadIntPtr(buf);   // SID_AND_ATTRIBUTES.Label.Sid
                    if (sid == IntPtr.Zero) return -1;
                    byte cnt = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
                    if (cnt == 0) return -1;
                    return Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(cnt - 1)));
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            finally { CloseHandle(token); }
        }

        public static string IntegrityName(int rid)
        {
            if (rid < 0) return "未知";
            if (rid < SECURITY_MANDATORY_LOW_RID) return "不受信任 (Untrusted)";
            if (rid < SECURITY_MANDATORY_MEDIUM_RID) return "低 (Low)";
            if (rid < 0x3000) return "中 (Medium)";
            if (rid < 0x4000) return "高 (High)";
            return "系统 (System)";
        }

        public const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
        public const uint MOUSEEVENTF_LEFTUP = 0x0004;
        public const uint KEYEVENTF_KEYUP = 0x0002;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const int SW_RESTORE = 9;

        [StructLayout(LayoutKind.Sequential)]
        public struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }
    }

    // ---------------------------------------------------------------- 窗口模型
    internal class MeetWin
    {
        public IntPtr Handle;
        public uint Pid;
        public string Title = "";
        public string Class = "";
        public bool Visible;
        /// 被最小化。注意：最小化时 IsWindowVisible 返回 false，
        /// 所以必须单独记录，否则"把会议窗口最小化"会被误判成"已离开会议"。
        public bool Minimized;
        public Rectangle Rect;

        public string Describe()
        {
            string state = "隐藏";
            if (Minimized) state = "最小化";
            else if (Visible) state = "可见";
            return string.Format("「{0}」 类={1} {2}x{3} {4}",
                Title, Class, Rect.Width, Rect.Height, state);
        }
    }

    // ---------------------------------------------------------------- 客户端交互
    internal static class MeetApi
    {
        /// 由界面设置的客户端完整路径（用于精确匹配）
        public static string ClientExe = "";

        /// 这个进程是不是腾讯会议客户端？
        /// 注意：绝不能用「路径里含 wemeet」来判断 ——
        /// 本程序自己的目录名就带 wemeet（wemeet-auto-rejoin-gui），
        /// 那样会把程序自己的窗口误认成客户端，导致永远判定"在会议中"、
        /// 永远不触发重进（表现就是"只输出不干活"）。
        public static bool IsClientProcess(string exePath)
        {
            if (string.IsNullOrEmpty(exePath)) return false;
            if (ClientExe.Length > 0 &&
                string.Equals(exePath, ClientExe, StringComparison.OrdinalIgnoreCase)) return true;

            string name;
            try { name = Path.GetFileName(exePath); }
            catch { return false; }
            return string.Equals(name, "WeMeetApp.exe", StringComparison.OrdinalIgnoreCase);
        }

        /// 按 PID 取可执行文件全路径（不依赖 Get-Process，避免漏进程）
        public static string ProcPath(uint pid)
        {
            IntPtr h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return "";
            try
            {
                StringBuilder sb = new StringBuilder(1024);
                uint size = 1024;
                if (Native.QueryFullProcessImageNameW(h, 0, sb, ref size)) return sb.ToString();
                return "";
            }
            finally { Native.CloseHandle(h); }
        }

        /// 列举所有属于腾讯会议的顶层窗口
        public static List<MeetWin> Scan()
        {
            List<MeetWin> list = new List<MeetWin>();
            Native.EnumWindows(delegate(IntPtr h, IntPtr l)
            {
                uint pid;
                Native.GetWindowThreadProcessId(h, out pid);
                string exe = ProcPath(pid);
                if (!IsClientProcess(exe)) return true;

                StringBuilder csb = new StringBuilder(256);
                Native.GetClassName(h, csb, 256);
                string cls = csb.ToString();
                if (cls == "IME" || cls == "Default IME") return true;

                StringBuilder tsb = new StringBuilder(512);
                Native.GetWindowText(h, tsb, 512);

                Native.RECT r;
                Native.GetWindowRect(h, out r);

                MeetWin w = new MeetWin();
                w.Handle = h;
                w.Pid = pid;
                w.Class = cls;
                w.Title = tsb.ToString();
                w.Visible = Native.IsWindowVisible(h);
                w.Minimized = Native.IsIconic(h);
                w.Rect = new Rectangle(r.Left, r.Top, r.Right - r.Left, r.Bottom - r.Top);
                list.Add(w);
                return true;
            }, IntPtr.Zero);
            return list;
        }

        /// 主窗口（最大的可见窗口）
        /// 找客户端【首页】窗口 —— 也就是带「加入会议」磁贴的那个。
        /// 优先认标题恰为「腾讯会议」的窗口（主界面），其次才退回"最大的可见窗口"。
        /// 最小化的也要认：调用方随后会 ForceForeground 把它还原。
        public static MeetWin FindMain(List<MeetWin> wins)
        {
            // 1) 标题为「腾讯会议」且正常显示
            foreach (MeetWin w in wins)
            {
                if (w.Title == null || w.Title.Trim() != "腾讯会议") continue;
                if (!w.Visible) continue;
                if (w.Rect.Width < 400 || w.Rect.Height < 300) continue;
                return w;
            }
            // 2) 标题为「腾讯会议」但被最小化（还原后再用）
            foreach (MeetWin w in wins)
            {
                if (w.Title == null || w.Title.Trim() != "腾讯会议") continue;
                if (w.Minimized) return w;
            }
            // 3) 兜底：最大的可见窗口
            MeetWin best = null;
            int bestArea = 0;
            foreach (MeetWin w in wins)
            {
                if (!w.Visible) continue;
                if (w.Rect.Width < 400 || w.Rect.Height < 300) continue;
                int area = w.Rect.Width * w.Rect.Height;
                if (area > bestArea) { bestArea = area; best = w; }
            }
            return best;
        }

        /// 判定"是否在会议中"：
        ///   存在一个客户端 UI 窗口，标题不是主界面标题（「腾讯会议」/「WeMeetApp」），
        ///   并且它【要么正常显示且尺寸够大，要么处于最小化状态】。
        ///
        /// 关键点：最小化时必须仍然算"在会议中"。
        /// 因为 IsWindowVisible 对最小化的窗口返回 false，
        /// 如果只认 Visible，用户把会议窗口最小化就会被误判成"已掉线"并触发重进。
        public static bool IsInMeeting(List<MeetWin> wins)
        {
            foreach (MeetWin w in wins)
            {
                if (w.Title == null) continue;
                string t = w.Title.Trim();
                if (t.Length == 0) continue;
                if (t == "腾讯会议") continue;
                if (t == "WeMeetApp") continue;

                // 最小化：窗口还在（用户只是收起来了，人仍在会议里）
                if (w.Minimized) return true;

                // 正常显示：要求可见且尺寸合理
                if (!w.Visible) continue;
                if (w.Rect.Width < 200 || w.Rect.Height < 150) continue;
                return true;
            }
            return false;
        }

        /// 实时读取窗口矩形（还原/移动之后必须重读，不能用扫描时的旧值）
        public static Rectangle GetRect(IntPtr h)
        {
            Native.RECT r;
            Native.GetWindowRect(h, out r);
            return new Rectangle(r.Left, r.Top, r.Right - r.Left, r.Bottom - r.Top);
        }

        /// 强制把窗口提到前台（AttachThreadInput 绕过系统的前台切换限制）
        public static bool ForceForeground(IntPtr h)
        {
            IntPtr fg = Native.GetForegroundWindow();
            uint tmpPid;
            uint tidFg = Native.GetWindowThreadProcessId(fg, out tmpPid);
            uint tidMe = Native.GetCurrentThreadId();

            Native.ShowWindow(h, Native.SW_RESTORE);
            Native.AttachThreadInput(tidMe, tidFg, true);
            Native.BringWindowToTop(h);
            Native.SetForegroundWindow(h);
            Native.AttachThreadInput(tidMe, tidFg, false);

            Thread.Sleep(500);
            return Native.GetForegroundWindow() == h;
        }

        public static void ClickAt(int x, int y)
        {
            Native.SetCursorPos(x, y);
            Thread.Sleep(150);
            Native.mouse_event(Native.MOUSEEVENTF_LEFTDOWN, 0, 0, 0, UIntPtr.Zero);
            Thread.Sleep(60);
            Native.mouse_event(Native.MOUSEEVENTF_LEFTUP, 0, 0, 0, UIntPtr.Zero);
        }

        /// 只输入数字（避免输入法/布局差异），用虚拟键码 0-9
        public static void TypeDigits(string s)
        {
            foreach (char c in s)
            {
                if (c < '0' || c > '9') continue;
                byte vk = (byte)(0x30 + (c - '0'));
                Native.keybd_event(vk, 0, 0, UIntPtr.Zero);
                Thread.Sleep(30);
                Native.keybd_event(vk, 0, Native.KEYEVENTF_KEYUP, UIntPtr.Zero);
                Thread.Sleep(30);
            }
        }

        public static void PressEnter()
        {
            Native.keybd_event(0x0D, 0, 0, UIntPtr.Zero);
            Thread.Sleep(40);
            Native.keybd_event(0x0D, 0, Native.KEYEVENTF_KEYUP, UIntPtr.Zero);
        }

        /// 自动探测客户端路径（读 wemeet: 协议的注册表项，最可靠）
        public static string DetectExe()
        {
            string[] keys = new string[]
            {
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\wemeet\shell\open\command",
                @"HKEY_CURRENT_USER\SOFTWARE\Classes\wemeet\shell\open\command",
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\wemeet3\shell\open\command"
            };
            foreach (string k in keys)
            {
                try
                {
                    object o = Registry.GetValue(k, "", null);
                    if (o == null) continue;
                    string s = o.ToString();
                    int a = s.IndexOf('"');
                    if (a >= 0)
                    {
                        int b = s.IndexOf('"', a + 1);
                        if (b > a)
                        {
                            string p = s.Substring(a + 1, b - a - 1);
                            if (File.Exists(p)) return p;
                        }
                    }
                    int e = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                    if (e > 0)
                    {
                        string p2 = s.Substring(0, e + 4).Trim();
                        if (File.Exists(p2)) return p2;
                    }
                }
                catch { }
            }
            // 注册表读不到时的兜底路径（只保留默认安装位置）
            string[] cands = new string[]
            {
                @"C:\Program Files\Tencent\WeMeet\WeMeetApp.exe",
                @"C:\Program Files (x86)\Tencent\WeMeet\WeMeetApp.exe"
            };
            foreach (string c in cands) if (File.Exists(c)) return c;
            return "";
        }
    }

    // ---------------------------------------------------------------- 按钮自动定位
    /// 通过截图自动找「加入会议」磁贴的位置。
    ///
    /// 原理（基于实拍截图分析）：
    ///   客户端首页有 5 个蓝色圆角方块磁贴，实测均为 124x124 的正方形：
    ///     加入会议(248,160) 快速会议(468,160) 预定会议(248,416) 共享屏幕(468,416) 录音笔(248,676)
    ///   而其它蓝色元素都不是正方形：
    ///     会议列表里的「入会」按钮是 124x44（扁的）、左侧栏图标只有 36x24（太小）。
    ///   所以「接近正方形 + 尺寸够大 + 位置最靠左上」的那一块，就是「加入会议」。
    ///   这样窗口大小、位置、甚至磁贴间距变了都能自动适应，不必再手工量坐标。
    internal static class TileDetector
    {
        /// 磁贴蓝。
        /// 注意要覆盖两种状态：
        ///   不在会议中 →「加入会议」是亮蓝 RGB(15,119,255)
        ///   已在会议中 → 首页变成「返回会议(橙) + 加入会议(暗蓝禁用态)」，
        ///                暗蓝是渐变，下半部分会明显偏暗，所以阈值不能卡太紧。
        private static bool IsTileBlue(int r, int g, int b)
        {
            return b > 130 && (b - r) > 50 && g > 50 && g < 200 && r < 140;
        }

        /// 抓取屏幕上一个矩形区域（坐标 = 客户端窗口在屏幕上的位置，所以图像坐标即窗口相对坐标）
        public static Bitmap Capture(Rectangle r)
        {
            Bitmap bmp = new Bitmap(r.Width, r.Height, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.CopyFromScreen(r.Left, r.Top, 0, 0, bmp.Size);
            }
            return bmp;
        }

        /// 在图像里找「加入会议」磁贴中心（返回图像坐标 = 窗口相对坐标）
        public static bool FindJoinTile(Bitmap bmp, out int cx, out int cy, out string detail)
        {
            cx = 0; cy = 0; detail = "";
            int w = bmp.Width, h = bmp.Height;
            if (w < 200 || h < 200) { detail = "图像太小"; return false; }

            int step = 4;
            int gw = w / step + 1, gh = h / step + 1;
            bool[,] grid = new bool[gw, gh];

            System.Drawing.Imaging.BitmapData data = bmp.LockBits(
                new Rectangle(0, 0, w, h),
                System.Drawing.Imaging.ImageLockMode.ReadOnly,
                System.Drawing.Imaging.PixelFormat.Format32bppArgb);
            try
            {
                byte[] buf = new byte[data.Stride * h];
                Marshal.Copy(data.Scan0, buf, 0, buf.Length);
                for (int y = 0; y < h; y += step)
                {
                    int row = y * data.Stride;
                    for (int x = 0; x < w; x += step)
                    {
                        int i = row + x * 4;
                        // Format32bppArgb 内存布局：B G R A
                        if (IsTileBlue(buf[i + 2], buf[i + 1], buf[i])) grid[x / step, y / step] = true;
                    }
                }
            }
            finally { bmp.UnlockBits(data); }

            // 连通域（4 邻域，栈实现）
            bool[,] seen = new bool[gw, gh];
            List<int[]> cand = new List<int[]>();
            int[] dx = new int[] { 1, -1, 0, 0 };
            int[] dy = new int[] { 0, 0, 1, -1 };
            for (int gy = 0; gy < gh; gy++)
            {
                for (int gx = 0; gx < gw; gx++)
                {
                    if (!grid[gx, gy] || seen[gx, gy]) continue;
                    Stack<int[]> st = new Stack<int[]>();
                    st.Push(new int[] { gx, gy });
                    seen[gx, gy] = true;
                    int minx = int.MaxValue, maxx = -1, miny = int.MaxValue, maxy = -1, cnt = 0;
                    while (st.Count > 0)
                    {
                        int[] p = st.Pop();
                        int pxx = p[0], pyy = p[1];
                        cnt++;
                        if (pxx < minx) minx = pxx;
                        if (pxx > maxx) maxx = pxx;
                        if (pyy < miny) miny = pyy;
                        if (pyy > maxy) maxy = pyy;
                        for (int k = 0; k < 4; k++)
                        {
                            int nx = pxx + dx[k], ny = pyy + dy[k];
                            if (nx < 0 || nx >= gw || ny < 0 || ny >= gh) continue;
                            if (!grid[nx, ny] || seen[nx, ny]) continue;
                            seen[nx, ny] = true;
                            st.Push(new int[] { nx, ny });
                        }
                    }

                    int bw = (maxx - minx + 1) * step;
                    int bh = (maxy - miny + 1) * step;
                    // 太小的一律不要：实测磁贴是 124x124，出现 50~60 的小块说明
                    // 磁贴颜色没被完整识别（变成了碎块），宁可判定失败退回手工坐标，
                    // 也不要用一个猜出来的碎块去点。
                    if (bw < 90 || bh < 90) continue;
                    if (bw > 500 || bh > 500) continue;      // 太大
                    double ratio = (double)bw / bh;
                    if (ratio < 0.8 || ratio > 1.25) continue;  // 必须接近正方形（排除「入会」那种扁按钮）
                    cand.Add(new int[] { minx, miny, maxx, maxy });
                }
            }

            if (cand.Count == 0) { detail = "没找到符合特征的蓝色方块磁贴"; return false; }

            // 取最靠左上的一块 = 加入会议
            int[] best = cand[0];
            foreach (int[] c in cand)
            {
                if (c[1] < best[1] || (c[1] == best[1] && c[0] < best[0])) best = c;
            }

            // 在粗网格包围盒内做全分辨率精修，消除 step 带来的误差
            int x0 = best[0] * step, y0 = best[1] * step;
            int x1 = Math.Min(w - 1, (best[2] + 1) * step);
            int y1 = Math.Min(h - 1, (best[3] + 1) * step);
            int fx0 = int.MaxValue, fy0 = int.MaxValue, fx1 = -1, fy1 = -1;

            System.Drawing.Imaging.BitmapData d2 = bmp.LockBits(
                new Rectangle(0, 0, w, h),
                System.Drawing.Imaging.ImageLockMode.ReadOnly,
                System.Drawing.Imaging.PixelFormat.Format32bppArgb);
            try
            {
                byte[] buf = new byte[d2.Stride * h];
                Marshal.Copy(d2.Scan0, buf, 0, buf.Length);
                for (int y = y0; y <= y1; y++)
                {
                    int row = y * d2.Stride;
                    for (int x = x0; x <= x1; x++)
                    {
                        int i = row + x * 4;
                        if (!IsTileBlue(buf[i + 2], buf[i + 1], buf[i])) continue;
                        if (x < fx0) fx0 = x;
                        if (x > fx1) fx1 = x;
                        if (y < fy0) fy0 = y;
                        if (y > fy1) fy1 = y;
                    }
                }
            }
            finally { bmp.UnlockBits(d2); }

            if (fx1 < 0) { detail = "精修失败"; return false; }
            cx = (fx0 + fx1) / 2;
            cy = (fy0 + fy1) / 2;
            detail = string.Format("磁贴 {0}x{1} 位于 ({2},{3})-({4},{5})，中心 ({6},{7})",
                fx1 - fx0 + 1, fy1 - fy0 + 1, fx0, fy0, fx1, fy1, cx, cy);
            return true;
        }

        /// 存一张带十字标记的预览图，方便肉眼确认定位对不对
        public static void SavePreview(Bitmap bmp, int cx, int cy, string path)
        {
            try
            {
                using (Graphics g = Graphics.FromImage(bmp))
                {
                    using (Pen p = new Pen(Color.FromArgb(255, 60, 60), 3))
                    {
                        g.DrawLine(p, cx - 34, cy, cx + 34, cy);
                        g.DrawLine(p, cx, cy - 34, cx, cy + 34);
                        g.DrawEllipse(p, cx - 22, cy - 22, 44, 44);
                    }
                }
                bmp.Save(path, System.Drawing.Imaging.ImageFormat.Png);
            }
            catch { }
        }
    }

    // ---------------------------------------------------------------- 配置
    internal class AppConfig
    {
        // 默认会议号留空：请用户自己填写。
        // （早期版本里这里硬编码了一个真实的会议号，公开发布前必须清掉，
        //   否则等于把自己的会议入口抄送给所有人。）
        public string MeetingCode = "";
        public string ExePath = "";
        public int DetectSeconds = 20;      // 连续多少秒检测不到会议 → 判定掉线
        public int PollSeconds = 5;         // 轮询间隔
        public int RetrySeconds = 90;       // 两次重进之间的最短间隔
        public int MaxAttempts = 3;         // 每次掉线最多尝试几次
        public string Method = "Click";     // Click / DeepLink / Keys
        public bool TestMode = false;       // 只到输入会议号为止，不按回车
        public double ClickX = 309;         // 「加入会议」磁贴中心（相对窗口，基准 1500x1020）
        public double ClickY = 250;
        public bool AutoStart = false;

        private static string ConfigPath()
        {
            return Path.Combine(Application.StartupPath, "config.ini");
        }

        public static AppConfig Load()
        {
            AppConfig c = new AppConfig();
            try
            {
                string p = ConfigPath();
                if (!File.Exists(p)) return c;
                foreach (string raw in File.ReadAllLines(p, Encoding.UTF8))
                {
                    string line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith("#")) continue;
                    int eq = line.IndexOf('=');
                    if (eq <= 0) continue;
                    string k = line.Substring(0, eq).Trim();
                    string v = line.Substring(eq + 1).Trim();
                    switch (k)
                    {
                        case "MeetingCode": c.MeetingCode = v; break;
                        case "ExePath": c.ExePath = v; break;
                        case "DetectSeconds": c.DetectSeconds = ParseInt(v, c.DetectSeconds); break;
                        case "PollSeconds": c.PollSeconds = ParseInt(v, c.PollSeconds); break;
                        case "RetrySeconds": c.RetrySeconds = ParseInt(v, c.RetrySeconds); break;
                        case "MaxAttempts": c.MaxAttempts = ParseInt(v, c.MaxAttempts); break;
                        case "Method": c.Method = v; break;
                        case "TestMode": c.TestMode = (v == "1" || v.ToLower() == "true"); break;
                        case "ClickX": c.ClickX = ParseDouble(v, c.ClickX); break;
                        case "ClickY": c.ClickY = ParseDouble(v, c.ClickY); break;
                        case "AutoStart": c.AutoStart = (v == "1" || v.ToLower() == "true"); break;
                    }
                }
            }
            catch { }
            return c;
        }

        private static int ParseInt(string s, int def)
        {
            int r;
            if (int.TryParse(s, out r)) return r;
            return def;
        }

        private static double ParseDouble(string s, double def)
        {
            double r;
            if (double.TryParse(s, out r)) return r;
            return def;
        }

        public void Save()
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("# 腾讯会议自动重进 配置文件");
                sb.AppendLine("# 直接双击运行 exe 会自动读取本文件；界面上改完点「保存设置」即可写回");
                sb.AppendLine("MeetingCode=" + MeetingCode);
                sb.AppendLine("ExePath=" + ExePath);
                sb.AppendLine("DetectSeconds=" + DetectSeconds);
                sb.AppendLine("PollSeconds=" + PollSeconds);
                sb.AppendLine("RetrySeconds=" + RetrySeconds);
                sb.AppendLine("MaxAttempts=" + MaxAttempts);
                sb.AppendLine("Method=" + Method);
                sb.AppendLine("TestMode=" + (TestMode ? "1" : "0"));
                sb.AppendLine("ClickX=" + ClickX);
                sb.AppendLine("ClickY=" + ClickY);
                sb.AppendLine("AutoStart=" + (AutoStart ? "1" : "0"));
                File.WriteAllText(ConfigPath(), sb.ToString(), Encoding.UTF8);
            }
            catch { }
        }
    }

    // ---------------------------------------------------------------- 主窗体
    internal class MainForm : Form
    {
        private TextBox txtCode;
        private NumericUpDown numDetect;
        private NumericUpDown numPoll;
        private NumericUpDown numRetry;
        private NumericUpDown numMax;
        private RadioButton rdoClick;
        private RadioButton rdoDeep;
        private RadioButton rdoKeys;
        private CheckBox chkTest;
        private CheckBox chkAutoStart;
        private TextBox txtExe;
        private NumericUpDown numClickX;
        private NumericUpDown numClickY;
        private Label lblStatus;
        private TextBox txtLog;
        private Button btnStart;
        private Button btnStop;
        private Button btnOnce;
        private Button btnProbe;
        private Button btnSave;
        private Button btnDetectPos;
        private ToolTip tips;

        private AppConfig cfg;
        private System.Windows.Forms.Timer timerPoll;
        private volatile bool busy = false;
        private bool wasInMeeting = false;
        private int absentSeconds = 0;
        private int attempts = 0;
        private DateTime lastAttempt = DateTime.MinValue;
        private bool maxWarned = false;
        private string logPath;

        private const double RefWidth = 1500.0;
        private const double RefHeight = 1020.0;

        public MainForm()
        {
            cfg = AppConfig.Load();
            logPath = Path.Combine(Application.StartupPath, "rejoin.log");
            BuildUi();
            LoadIntoUi();
            if (cfg.ExePath.Length == 0 || !File.Exists(cfg.ExePath))
            {
                string d = MeetApi.DetectExe();
                if (d.Length > 0) { cfg.ExePath = d; txtExe.Text = d; }
            }
            MeetApi.ClientExe = cfg.ExePath;
        }

        // ------------------------------------------------------------ 界面
        private void BuildUi()
        {
            Text = "腾讯会议 —— 掉线自动重进";
            ClientSize = new Size(600, 680);
            // 不用 AutoScaleMode.Dpi：csc 编译的代码构建窗体上它不生效，
            // 结果会字体放大而控件框没放大（数字显示成 0、按钮文字截断）。
            // 改为构建完成后手动按 DPI 等比缩放整棵控件树（见 ScaleForDpi）。
            AutoScaleMode = AutoScaleMode.None;
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9F);
            BackColor = Color.FromArgb(245, 246, 248);
            tips = new ToolTip();   // 必须先建：下面添加控件时就要挂悬停提示

            int x1 = 14, x2 = 150, y = 16;

            Label l1 = new Label();
            l1.Text = "会议号";
            l1.Location = new Point(x1, y + 4);
            l1.AutoSize = true;
            Controls.Add(l1);

            txtCode = new TextBox();
            txtCode.Location = new Point(x2, y);
            txtCode.Size = new Size(140, 25);
            Controls.Add(txtCode);

            Label l1b = new Label();
            l1b.Text = "（只填数字，横杠可省略）";
            l1b.Location = new Point(x2 + 150, y + 4);
            l1b.AutoSize = true;
            l1b.ForeColor = Color.Gray;
            Controls.Add(l1b);

            y += 40;
            Label l2 = new Label();
            l2.Text = "掉线判定(秒)";
            l2.Location = new Point(x1, y + 4);
            l2.AutoSize = true;
            Controls.Add(l2);

            numDetect = new NumericUpDown();
            numDetect.Location = new Point(x2, y);
            numDetect.Size = new Size(70, 25);
            numDetect.Minimum = 5;
            numDetect.Maximum = 600;
            Controls.Add(numDetect);

            Label l3 = new Label();
            l3.Text = "轮询间隔(秒)";
            l3.Location = new Point(250, y + 4);
            l3.AutoSize = true;
            Controls.Add(l3);

            numPoll = new NumericUpDown();
            numPoll.Location = new Point(350, y);
            numPoll.Size = new Size(70, 25);
            numPoll.Minimum = 2;
            numPoll.Maximum = 120;
            Controls.Add(numPoll);

            y += 36;
            Label l4 = new Label();
            l4.Text = "重进间隔(秒)";
            l4.Location = new Point(x1, y + 4);
            l4.AutoSize = true;
            Controls.Add(l4);

            numRetry = new NumericUpDown();
            numRetry.Location = new Point(x2, y);
            numRetry.Size = new Size(70, 25);
            numRetry.Minimum = 10;
            numRetry.Maximum = 3600;
            Controls.Add(numRetry);

            Label l5 = new Label();
            l5.Text = "最大尝试次数";
            l5.Location = new Point(250, y + 4);
            l5.AutoSize = true;
            Controls.Add(l5);

            numMax = new NumericUpDown();
            numMax.Location = new Point(350, y);
            numMax.Size = new Size(70, 25);
            numMax.Minimum = 1;
            numMax.Maximum = 99;
            Controls.Add(numMax);

            y += 42;
            GroupBox grp = new GroupBox();
            grp.Text = "重进方式";
            grp.Location = new Point(x1, y);
            grp.Size = new Size(570, 62);
            Controls.Add(grp);

            rdoClick = new RadioButton();
            rdoClick.Text = "界面点击（推荐）";
            rdoClick.Location = new Point(14, 26);
            rdoClick.AutoSize = true;
            rdoClick.Checked = true;
            grp.Controls.Add(rdoClick);

            rdoDeep = new RadioButton();
            rdoDeep.Text = "深链唤起";
            rdoDeep.Location = new Point(180, 26);
            rdoDeep.AutoSize = true;
            grp.Controls.Add(rdoDeep);

            rdoKeys = new RadioButton();
            rdoKeys.Text = "键盘盲打";
            rdoKeys.Location = new Point(300, 26);
            rdoKeys.AutoSize = true;
            grp.Controls.Add(rdoKeys);

            y += 72;
            chkTest = new CheckBox();
            chkTest.Text = "测试模式：只点开入会界面并输入会议号，不按回车（不会真的进会议）";
            chkTest.Location = new Point(x1, y);
            chkTest.AutoSize = true;
            Controls.Add(chkTest);

            y += 30;
            chkAutoStart = new CheckBox();
            chkAutoStart.Text = "启动后自动开始监控";
            chkAutoStart.Location = new Point(x1, y);
            chkAutoStart.AutoSize = true;
            Controls.Add(chkAutoStart);

            y += 32;
            Label l6 = new Label();
            l6.Text = "客户端路径";
            l6.Location = new Point(x1, y + 4);
            l6.AutoSize = true;
            Controls.Add(l6);

            txtExe = new TextBox();
            txtExe.Location = new Point(x2, y);
            txtExe.Size = new Size(340, 25);
            Controls.Add(txtExe);

            Button btnFind = new Button();
            btnFind.Text = "自动检测";
            btnFind.Location = new Point(500, y - 1);
            btnFind.Size = new Size(80, 27);
            btnFind.Click += delegate { DoDetectExe(); };
            Controls.Add(btnFind);

            y += 38;
            Label l7 = new Label();
            l7.Text = "点击位置 X / Y";
            l7.Location = new Point(x1, y + 4);
            l7.AutoSize = true;
            Controls.Add(l7);

            numClickX = new NumericUpDown();
            numClickX.Location = new Point(x2, y);
            numClickX.Size = new Size(70, 25);
            numClickX.Minimum = 0;
            numClickX.Maximum = 5000;
            numClickX.DecimalPlaces = 0;
            Controls.Add(numClickX);

            numClickY = new NumericUpDown();
            numClickY.Location = new Point(x2 + 80, y);
            numClickY.Size = new Size(70, 25);
            numClickY.Minimum = 0;
            numClickY.Maximum = 5000;
            numClickY.DecimalPlaces = 0;
            Controls.Add(numClickY);

            btnDetectPos = new Button();
            btnDetectPos.Text = "自动定位按钮位置";
            btnDetectPos.Location = new Point(310, y - 2);
            btnDetectPos.Size = new Size(150, 27);
            btnDetectPos.Click += delegate { DoDetectButtonPos(); };
            Controls.Add(btnDetectPos);
            tips.SetToolTip(btnDetectPos, "截图识别「加入会议」蓝色方块磁贴的位置，自动填好左边的 X/Y。\n识别结果会存成 detect-preview.png（红圈十字标记），可以打开核对。");

            tips.SetToolTip(numClickX, "「加入会议」磁贴中心，相对客户端窗口左上角的坐标。\n通常不用手填：程序每次重进前都会截图自动识别按钮位置，\n这两个值只是识别失败时的兜底。");
            tips.SetToolTip(numClickY, "同上，Y 坐标。");
            tips.SetToolTip(numDetect, "连续多少秒检测不到会议，才判定为已掉线。\n免费版 40 分钟到点后会议会直接结束，建议 15~30 秒。");
            tips.SetToolTip(numPoll, "每隔多少秒检查一次是否在会议中。\n轮询是只读操作，不会抢焦点。");
            tips.SetToolTip(numRetry, "两次重进尝试之间的最短间隔。");
            tips.SetToolTip(numMax, "每次掉线最多自动重进几次。到上限就停手，\n避免你主动退出会议后被反复拽回去。");
            tips.SetToolTip(rdoClick, "按实拍界面坐标点击「加入会议」→ 输入会议号 → 回车。");
            tips.SetToolTip(rdoDeep, "发送 wemeet:// 深链唤起客户端（依赖客户端支持该路由）。");
            tips.SetToolTip(rdoKeys, "把客户端切到前台后直接盲打会议号并回车，不点击任何按钮。");
            tips.SetToolTip(chkTest, "勾选后只做到「输入会议号」为止，不按回车。\n用来验证坐标有没有点准，不会真的进会议。");

            y += 38;
            lblStatus = new Label();
            lblStatus.Text = "状态：未启动";
            lblStatus.Location = new Point(x1, y);
            lblStatus.AutoSize = true;
            lblStatus.Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Bold);
            lblStatus.ForeColor = Color.FromArgb(30, 90, 170);
            Controls.Add(lblStatus);

            y += 30;
            txtLog = new TextBox();
            txtLog.Location = new Point(x1, y);
            txtLog.Size = new Size(570, 200);
            txtLog.Multiline = true;
            txtLog.ReadOnly = true;
            txtLog.ScrollBars = ScrollBars.Vertical;
            txtLog.BackColor = Color.FromArgb(28, 30, 34);
            txtLog.ForeColor = Color.FromArgb(210, 214, 220);
            txtLog.Font = new Font("Consolas", 8.5F);
            txtLog.WordWrap = true;
            Controls.Add(txtLog);

            y += 210;
            btnStart = new Button();
            btnStart.Text = "开始监控";
            btnStart.Location = new Point(x1, y);
            btnStart.Size = new Size(100, 32);
            btnStart.Click += delegate { StartMonitor(); };
            Controls.Add(btnStart);

            btnStop = new Button();
            btnStop.Text = "停止";
            btnStop.Location = new Point(x1 + 110, y);
            btnStop.Size = new Size(80, 32);
            btnStop.Enabled = false;
            btnStop.Click += delegate { StopMonitor("手动停止"); };
            Controls.Add(btnStop);

            btnOnce = new Button();
            btnOnce.Text = "立即重进一次";
            btnOnce.Location = new Point(x1 + 200, y);
            btnOnce.Size = new Size(120, 32);
            btnOnce.Click += delegate { BeginRejoin("手动触发"); };
            Controls.Add(btnOnce);

            btnProbe = new Button();
            btnProbe.Text = "测试窗口识别";
            btnProbe.Location = new Point(x1 + 330, y);
            btnProbe.Size = new Size(120, 32);
            btnProbe.Click += delegate { DoProbe(); };
            Controls.Add(btnProbe);

            btnSave = new Button();
            btnSave.Text = "保存设置";
            btnSave.Location = new Point(x1 + 460, y);
            btnSave.Size = new Size(110, 32);
            btnSave.Click += delegate { SaveFromUi(); Log("设置已保存到 config.ini"); };
            Controls.Add(btnSave);

            timerPoll = new System.Windows.Forms.Timer();
            timerPoll.Tick += delegate { OnPoll(); };

            ScaleForDpi();
        }

        // ------------------------------------------------------------ DPI 缩放
        /// 当前系统 DPI 相对 96 的倍率（100% = 1.0，200% = 2.0）
        private static float DpiScale()
        {
            try
            {
                using (Graphics g = Graphics.FromHwnd(IntPtr.Zero))
                {
                    return g.DpiX / 96f;
                }
            }
            catch { return 1f; }
        }

        /// 整棵控件树等比缩放（Location 相对父控件，所以父子同时缩放结果一致）
        private static void ScaleTree(Control c, float s)
        {
            int nx = (int)Math.Round(c.Left * s);
            int ny = (int)Math.Round(c.Top * s);
            int nw = (int)Math.Round(c.Width * s);
            int nh = (int)Math.Round(c.Height * s);
            if (nw < 1) nw = 1;
            if (nh < 1) nh = 1;
            c.Location = new Point(nx, ny);
            c.Size = new Size(nw, nh);
            // 注意：这里【不能】再缩放 Font.Size。
            // 进程已声明 DPI 感知，GDI+ 会按系统 DPI 自动把 9pt 渲染成 2 倍像素；
            // 若再把字号乘 2 就是 4 倍，文字会撑破控件（数字显示不全、按钮文字截断）。
            foreach (Control child in c.Controls) ScaleTree(child, s);
        }

        private void ScaleForDpi()
        {
            float s = DpiScale();
            if (Math.Abs(s - 1f) < 0.01f) return;
            ClientSize = new Size((int)Math.Round(ClientSize.Width * s),
                                  (int)Math.Round(ClientSize.Height * s));
            foreach (Control c in Controls) ScaleTree(c, s);
        }

        private void LoadIntoUi()
        {
            txtCode.Text = cfg.MeetingCode;
            txtExe.Text = cfg.ExePath;
            numDetect.Value = Clamp(cfg.DetectSeconds, numDetect.Minimum, numDetect.Maximum);
            numPoll.Value = Clamp(cfg.PollSeconds, numPoll.Minimum, numPoll.Maximum);
            numRetry.Value = Clamp(cfg.RetrySeconds, numRetry.Minimum, numRetry.Maximum);
            numMax.Value = Clamp(cfg.MaxAttempts, numMax.Minimum, numMax.Maximum);
            numClickX.Value = Clamp((int)Math.Round(cfg.ClickX), numClickX.Minimum, numClickX.Maximum);
            numClickY.Value = Clamp((int)Math.Round(cfg.ClickY), numClickY.Minimum, numClickY.Maximum);
            chkTest.Checked = cfg.TestMode;
            chkAutoStart.Checked = cfg.AutoStart;
            if (cfg.Method == "DeepLink") rdoDeep.Checked = true;
            else if (cfg.Method == "Keys") rdoKeys.Checked = true;
            else rdoClick.Checked = true;
        }

        private static decimal Clamp(int v, decimal lo, decimal hi)
        {
            if (v < lo) return lo;
            if (v > hi) return hi;
            return v;
        }

        private void SaveFromUi()
        {
            cfg.MeetingCode = DigitsOnly(txtCode.Text);
            txtCode.Text = cfg.MeetingCode;
            cfg.ExePath = txtExe.Text.Trim();
            MeetApi.ClientExe = cfg.ExePath;
            cfg.DetectSeconds = (int)numDetect.Value;
            cfg.PollSeconds = (int)numPoll.Value;
            cfg.RetrySeconds = (int)numRetry.Value;
            cfg.MaxAttempts = (int)numMax.Value;
            cfg.ClickX = (double)numClickX.Value;
            cfg.ClickY = (double)numClickY.Value;
            cfg.TestMode = chkTest.Checked;
            cfg.AutoStart = chkAutoStart.Checked;
            if (rdoDeep.Checked) cfg.Method = "DeepLink";
            else if (rdoKeys.Checked) cfg.Method = "Keys";
            else cfg.Method = "Click";
            cfg.Save();
        }

        private static string DigitsOnly(string s)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char c in s) if (c >= '0' && c <= '9') sb.Append(c);
            return sb.ToString();
        }

        // ------------------------------------------------------------ 日志 / 状态
        private void Log(string msg)
        {
            string line = string.Format("[{0:HH:mm:ss}] {1}{2}", DateTime.Now, msg, Environment.NewLine);
            try { File.AppendAllText(logPath, line, Encoding.UTF8); } catch { }
            if (txtLog.InvokeRequired) txtLog.BeginInvoke(new Action<string>(AppendLog), new object[] { line });
            else AppendLog(line);
        }

        private void AppendLog(string line)
        {
            txtLog.AppendText(line);
            txtLog.SelectionStart = txtLog.TextLength;
            txtLog.ScrollToCaret();
        }

        private void SetStatus(string s)
        {
            if (lblStatus.InvokeRequired) lblStatus.BeginInvoke(new Action<string>(SetStatus), new object[] { s });
            else lblStatus.Text = "状态：" + s;
        }

        // ------------------------------------------------------------ 监控
        private void StartMonitor()
        {
            SaveFromUi();
            if (cfg.MeetingCode.Length == 0)
            {
                MessageBox.Show("请先填写会议号。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            absentSeconds = 0;
            attempts = 0;
            maxWarned = false;
            wasInMeeting = false;
            lastAttempt = DateTime.MinValue;
            timerPoll.Interval = cfg.PollSeconds * 1000;
            timerPoll.Start();
            btnStart.Enabled = false;
            btnStop.Enabled = true;
            SetStatus("监控中");
            Log(string.Format("=== 开始监控 === 会议号 {0}，轮询 {1}s，掉线判定 {2}s，重进间隔 {3}s，最多 {4} 次",
                cfg.MeetingCode, cfg.PollSeconds, cfg.DetectSeconds, cfg.RetrySeconds, cfg.MaxAttempts));
            Log("方式：" + MethodName() + (cfg.TestMode ? "（测试模式）" : ""));
        }

        private void StopMonitor(string reason)
        {
            timerPoll.Stop();
            btnStart.Enabled = true;
            btnStop.Enabled = false;
            SetStatus("已停止");
            Log("=== 已停止：" + reason + " ===");
        }

        private string MethodName()
        {
            if (cfg.Method == "DeepLink") return "深链唤起";
            if (cfg.Method == "Keys") return "键盘盲打";
            return "界面点击";
        }

        private void OnPoll()
        {
            try
            {
                List<MeetWin> wins = MeetApi.Scan();
                bool inMeeting = MeetApi.IsInMeeting(wins);

                if (inMeeting)
                {
                    if (!wasInMeeting)
                    {
                        Log("检测到会议进行中");
                        wasInMeeting = true;
                        attempts = 0;
                        maxWarned = false;
                    }
                    absentSeconds = 0;
                    SetStatus("会议中");
                    return;
                }

                if (wasInMeeting)
                {
                    Log("会议已结束 / 已掉线，开始计时");
                    Log("（下面是此刻识别到的客户端窗口，便于判断是不是误判：）");
                    if (wins.Count == 0) Log("   没有任何客户端窗口");
                    foreach (MeetWin w in wins) Log("   " + w.Describe());
                    wasInMeeting = false;
                }

                SetStatus("不在会议中（" + absentSeconds + "s）");
                absentSeconds += cfg.PollSeconds;

                if (absentSeconds < cfg.DetectSeconds) return;
                if (busy) return;

                if (attempts >= cfg.MaxAttempts)
                {
                    if (!maxWarned)
                    {
                        maxWarned = true;
                        Log(string.Format("已达到最大尝试次数 {0}，停止重进。点「立即重进一次」可手动再试。", cfg.MaxAttempts));
                        SetStatus("已放弃（达上限）");
                    }
                    return;
                }

                if (lastAttempt != DateTime.MinValue &&
                    (DateTime.Now - lastAttempt).TotalSeconds < cfg.RetrySeconds) return;

                BeginRejoin(string.Format("连续 {0} 秒不在会议中", absentSeconds));
            }
            catch (Exception ex)
            {
                Log("轮询出错：" + ex.Message);
            }
        }

        // ------------------------------------------------------------ 重进
        private void BeginRejoin(string reason)
        {
            if (busy) return;
            busy = true;
            attempts++;
            lastAttempt = DateTime.Now;
            Log(string.Format("--- 第 {0}/{1} 次重进（{2}，{3}）---",
                attempts, cfg.MaxAttempts, reason, MethodName()));
            Thread t = new Thread(new ThreadStart(delegate { RejoinWorker(); }));
            t.IsBackground = true;
            t.Start();
        }

        private void RejoinWorker()
        {
            try
            {
                if (cfg.Method == "DeepLink") { DoDeepLink(); }
                else if (cfg.Method == "Keys") { DoKeys(); }
                else { DoClick(); }

                Thread.Sleep(8000);
                bool ok = MeetApi.IsInMeeting(MeetApi.Scan());
                if (ok)
                {
                    Log("已回到会议中 ✓");
                    attempts = 0;
                    absentSeconds = 0;
                    wasInMeeting = true;
                    SetStatus("会议中");
                }
                else
                {
                    Log("重进后仍未检测到会议，稍后会再试");
                }
            }
            catch (Exception ex)
            {
                Log("重进出错：" + ex.Message);
            }
            finally { busy = false; }
        }

        private void DoDeepLink()
        {
            string exe = cfg.ExePath;
            if (exe.Length == 0 || !File.Exists(exe)) throw new Exception("客户端路径无效");
            string uri = "wemeet://page/join_meeting/init?meeting_code=" + cfg.MeetingCode;
            Log("发送深链：" + uri);
            System.Diagnostics.Process.Start(exe, "\"" + uri + "\"");
        }

        private void DoKeys()
        {
            List<MeetWin> wins = MeetApi.Scan();
            MeetWin main = MeetApi.FindMain(wins);
            if (main == null)
            {
                Log("主窗口不存在，尝试启动客户端…");
                if (cfg.ExePath.Length > 0 && File.Exists(cfg.ExePath))
                    System.Diagnostics.Process.Start(cfg.ExePath);
                Thread.Sleep(7000);
                main = MeetApi.FindMain(MeetApi.Scan());
            }
            if (main == null) throw new Exception("找不到腾讯会议主窗口");

            if (!MeetApi.ForceForeground(main.Handle))
                throw new Exception("无法把客户端切到前台，已中止（避免把会议号输进别的窗口）");

            Log("已置前台，直接输入会议号");
            MeetApi.TypeDigits(cfg.MeetingCode);
            if (cfg.TestMode) { Log("测试模式：不按回车"); return; }
            Thread.Sleep(400);
            MeetApi.PressEnter();
            Log("已按回车");
        }

        /// 找到客户端主窗口（必要时启动），并把「加入会议」按钮定位到屏幕坐标。
        /// 优先**实时截图自动识别**；识别不出来才退回界面上手工填的坐标。
        private bool LocateJoinButton(out int sx, out int sy, out string how)
        {
            sx = 0; sy = 0; how = "";

            List<MeetWin> wins = MeetApi.Scan();
            MeetWin main = MeetApi.FindMain(wins);
            if (main == null)
            {
                Log("主窗口不存在，尝试启动客户端…");
                if (cfg.ExePath.Length > 0 && File.Exists(cfg.ExePath))
                    System.Diagnostics.Process.Start(cfg.ExePath);
                Thread.Sleep(7000);
                main = MeetApi.FindMain(MeetApi.Scan());
            }
            if (main == null) { Log("找不到腾讯会议主窗口"); return false; }

            if (!MeetApi.ForceForeground(main.Handle))
            {
                Log("无法把客户端切到前台，已中止（避免点错窗口）");
                return false;
            }
            Thread.Sleep(600);
            // 窗口可能是刚被还原/移动的，这里重读一次矩形，避免用到扫描时的过期值
            Rectangle wr = MeetApi.GetRect(main.Handle);
            Log(string.Format("客户端窗口 {0}x{1} @({2},{3})",
                wr.Width, wr.Height, wr.Left, wr.Top));

            // ---- 优先：实时截图自动定位 ----
            try
            {
                Bitmap shot = TileDetector.Capture(wr);
                int cx, cy;
                string detail;
                if (TileDetector.FindJoinTile(shot, out cx, out cy, out detail))
                {
                    TileDetector.SavePreview(shot, cx, cy,
                        Path.Combine(Application.StartupPath, "detect-preview.png"));
                    sx = wr.Left + cx;
                    sy = wr.Top + cy;
                    how = "自动定位，" + detail;
                    shot.Dispose();
                    return true;
                }
                Log("自动定位失败：" + detail + " → 退回手工坐标");
                shot.Dispose();
            }
            catch (Exception ex)
            {
                Log("自动定位出错：" + ex.Message + " → 退回手工坐标");
            }

            // ---- 兜底：界面上填的参考坐标，按窗口尺寸等比换算 ----
            sx = (int)Math.Round(wr.Left + cfg.ClickX * (wr.Width / RefWidth));
            sy = (int)Math.Round(wr.Top + cfg.ClickY * (wr.Height / RefHeight));
            how = string.Format("手工坐标 ({0},{1}) 换算", cfg.ClickX, cfg.ClickY);
            return true;
        }

        /// 界面按钮：自动定位并把结果写回 X/Y，同时留一张带标记的预览图
        private void DoDetectButtonPos()
        {
            SaveFromUi();
            Log("===== 自动定位「加入会议」按钮 =====");

            int sx, sy;
            string how;
            if (!LocateJoinButton(out sx, out sy, out how))
            {
                Log("定位失败。请确认客户端已打开并停在首页。");
                MessageBox.Show("没能定位到按钮。\n请确认腾讯会议已打开并停在首页，然后重试。",
                    "定位失败", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            Log("定位结果：" + how);
            Log(string.Format("屏幕坐标 ({0},{1})", sx, sy));

            MeetWin main = MeetApi.FindMain(MeetApi.Scan());
            if (main != null && main.Rect.Width > 0)
            {
                double rx = (sx - main.Rect.Left) * RefWidth / main.Rect.Width;
                double ry = (sy - main.Rect.Top) * RefHeight / main.Rect.Height;
                numClickX.Value = Clamp((int)Math.Round(rx), numClickX.Minimum, numClickX.Maximum);
                numClickY.Value = Clamp((int)Math.Round(ry), numClickY.Minimum, numClickY.Maximum);
                SaveFromUi();
                Log(string.Format("已把兜底参考坐标更新为 X={0} Y={1}（按窗口 {2}x{3} 折算）",
                    numClickX.Value, numClickY.Value, main.Rect.Width, main.Rect.Height));
            }

            Log("预览图已存为 detect-preview.png（红圈十字 = 识别到的按钮位置），打开看一眼即可确认。");
            MessageBox.Show("定位完成。\n\n已打开同目录的 detect-preview.png 供你核对：\n红圈十字标记的就是识别到的「加入会议」按钮位置。",
                "定位完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void DoClick()
        {
            int sx, sy;
            string how;
            if (!LocateJoinButton(out sx, out sy, out how)) throw new Exception("定位「加入会议」按钮失败");

            Log(string.Format("点击「加入会议」 → 屏幕 ({0},{1})   来源：{2}", sx, sy, how));
            MeetApi.ClickAt(sx, sy);
            Thread.Sleep(1500);

            Log("输入会议号 " + cfg.MeetingCode);
            MeetApi.TypeDigits(cfg.MeetingCode);
            Thread.Sleep(500);

            if (cfg.TestMode) { Log("测试模式：不按回车，流程到此为止"); return; }
            MeetApi.PressEnter();
            Log("已按回车提交入会");
        }

        // ------------------------------------------------------------ 工具
        private void DoDetectExe()
        {
            string p = MeetApi.DetectExe();
            if (p.Length == 0)
            {
                Log("自动检测失败：注册表里没有 wemeet 协议，常见路径也没找到");
                MessageBox.Show("没能自动找到腾讯会议客户端，请手动填写路径。", "提示");
                return;
            }
            txtExe.Text = p;
            MeetApi.ClientExe = p;
            Log("已检测到客户端：" + p);
        }

        private void DoProbe()
        {
            List<MeetWin> wins = MeetApi.Scan();
            Log("===== 窗口识别测试 =====");
            Log("属于腾讯会议的顶层窗口：" + wins.Count + " 个");
            foreach (MeetWin w in wins) Log("   " + w.Describe());
            bool inMeeting = MeetApi.IsInMeeting(wins);
            MeetWin main = MeetApi.FindMain(wins);
            Log("判定：在会议中 = " + (inMeeting ? "是" : "否"));
            Log("主窗口：" + (main == null ? "（无）" : main.Describe()));
            if (!inMeeting)
                Log("提示：如果你此时其实正在开会，说明识别规则需要调整，请把上面这段发我。");
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            Log("程序已启动。日志文件：" + logPath);
            if (cfg.ExePath.Length > 0) Log("客户端路径：" + cfg.ExePath);
            else Log("尚未确定客户端路径，请点「自动检测」");
            Log("轮询阶段只读取窗口信息，不会置顶或抢焦点；只有真正重进时才会切前台。");

            // 关键自检：低完整性进程无法向普通权限的腾讯会议注入鼠标/键盘，
            // 症状是"什么都能识别，就是点了没反应"。必须明确告知，不能静默失效。
            int rid = Native.GetIntegrityRid();
            Log("本进程完整性级别：" + Native.IntegrityName(rid));
            if (rid >= 0 && rid < Native.SECURITY_MANDATORY_MEDIUM_RID)
            {
                Log("⚠️ 严重问题：本程序正在以【低完整性】运行！");
                Log("   Windows 的 UIPI 会拦截它对腾讯会议注入的鼠标点击和键盘输入，");
                Log("   结果是：窗口能识别、能切前台，但点击完全没有反应。");
                Log("   原因：exe 文件或所在文件夹被打上了 Low 完整性标签");
                Log("        （凡是由受限/沙箱进程创建的文件都会这样）。");
                Log("   解决：把整个文件夹复制到一个新位置（例如 D:\\腾讯会议自动重进），");
                Log("        从新位置运行 exe 即可 —— 复制出来的文件会恢复正常标签。");
                MessageBox.Show(
                    "检测到本程序以【低完整性】运行，点击将无效。\n\n" +
                    "原因：exe 文件或所在文件夹带有 Low 完整性标签\n" +
                    "（由受限/沙箱进程创建的文件会自动带这个标签）。\n\n" +
                    "解决办法：\n" +
                    "把整个文件夹复制到一个新位置（例如 D:\\腾讯会议自动重进），\n" +
                    "然后从新位置运行 exe。复制出来的文件标签就正常了。\n\n" +
                    "详情见程序同目录的 使用说明.md「完整性标签」一节。",
                    "需要先修复完整性标签",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            if (cfg.AutoStart) StartMonitor();
        }
    }

    internal static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            // 声明 DPI 感知：否则在 200% 缩放的显示器上会被系统位图拉伸，界面发虚，
            // 而且窗口坐标会被虚拟化，和实拍量取的基准坐标不在同一坐标系。
            try { Native.SetProcessDPIAware(); }
            catch { }

            // 命令行自检：--probe 只做一次窗口识别并把结果写进 probe-result.txt，不开界面。
            // 方便在不方便点鼠标的环境（比如受限沙箱）里核对识别规则。
            if (args != null && args.Length > 0 && args[0] == "--probe")
            {
                RunProbeCli();
                return;
            }

            // 命令行自检：--detect 做一次「加入会议」按钮自动定位，结果写进 detect-result.txt，
            // 并把带十字标记的预览图存成 detect-preview.png。
            if (args != null && args.Length > 0 && args[0] == "--detect")
            {
                RunDetectCli();
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }

        private static void RunProbeCli()
        {
            AppConfig cfg = AppConfig.Load();
            if (cfg.ExePath.Length == 0 || !File.Exists(cfg.ExePath))
            {
                string d = MeetApi.DetectExe();
                if (d.Length > 0) cfg.ExePath = d;
            }
            MeetApi.ClientExe = cfg.ExePath;

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("腾讯会议自动重进 —— 窗口识别自检");
            sb.AppendLine("时间：" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("进程完整性级别：" + Native.IntegrityName(Native.GetIntegrityRid()));
            sb.AppendLine("客户端路径：" + (cfg.ExePath.Length > 0 ? cfg.ExePath : "（未确定）"));
            sb.AppendLine();

            List<MeetWin> wins = MeetApi.Scan();
            sb.AppendLine("识别到属于腾讯会议的顶层窗口：" + wins.Count + " 个");
            foreach (MeetWin w in wins) sb.AppendLine("   " + w.Describe());
            sb.AppendLine();
            sb.AppendLine("判定在会议中：" + (MeetApi.IsInMeeting(wins) ? "是" : "否"));
            MeetWin main = MeetApi.FindMain(wins);
            sb.AppendLine("主窗口：" + (main == null ? "（无）" : main.Describe()));

            string p = Path.Combine(Application.StartupPath, "probe-result.txt");
            try { File.WriteAllText(p, sb.ToString(), Encoding.UTF8); }
            catch { }
        }

        private static void RunDetectCli()
        {
            AppConfig cfg = AppConfig.Load();
            if (cfg.ExePath.Length == 0 || !File.Exists(cfg.ExePath))
            {
                string d = MeetApi.DetectExe();
                if (d.Length > 0) cfg.ExePath = d;
            }
            MeetApi.ClientExe = cfg.ExePath;

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("腾讯会议自动重进 —— 「加入会议」按钮自动定位自检");
            sb.AppendLine("时间：" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("进程完整性级别：" + Native.IntegrityName(Native.GetIntegrityRid()));
            sb.AppendLine();

            MeetWin main = MeetApi.FindMain(MeetApi.Scan());
            if (main == null && cfg.ExePath.Length > 0 && File.Exists(cfg.ExePath))
            {
                sb.AppendLine("主窗口不在，先启动客户端…");
                try { System.Diagnostics.Process.Start(cfg.ExePath); }
                catch { }
                Thread.Sleep(8000);
                main = MeetApi.FindMain(MeetApi.Scan());
            }
            if (main == null)
            {
                sb.AppendLine("找不到客户端主窗口，定位中止。");
                try { File.WriteAllText(Path.Combine(Application.StartupPath, "detect-result.txt"), sb.ToString(), Encoding.UTF8); }
                catch { }
                return;
            }

            sb.AppendLine(string.Format("客户端窗口 {0}x{1} @({2},{3})",
                main.Rect.Width, main.Rect.Height, main.Rect.Left, main.Rect.Top));
            sb.AppendLine("切到前台：" + (MeetApi.ForceForeground(main.Handle) ? "成功" : "失败"));
            Thread.Sleep(600);

            Bitmap shot = null;
            try
            {
                shot = TileDetector.Capture(main.Rect);
                int cx, cy;
                string detail;
                bool ok = TileDetector.FindJoinTile(shot, out cx, out cy, out detail);
                sb.AppendLine("定位成功：" + (ok ? "是" : "否"));
                sb.AppendLine("详情：" + detail);
                if (ok)
                {
                    sb.AppendLine(string.Format("窗口相对坐标 ({0},{1})   屏幕坐标 ({2},{3})",
                        cx, cy, main.Rect.Left + cx, main.Rect.Top + cy));
                    TileDetector.SavePreview(shot, cx, cy,
                        Path.Combine(Application.StartupPath, "detect-preview.png"));
                    sb.AppendLine("预览图：detect-preview.png");
                }
                else
                {
                    shot.Save(Path.Combine(Application.StartupPath, "detect-fail.png"),
                        System.Drawing.Imaging.ImageFormat.Png);
                    sb.AppendLine("已把截图存为 detect-fail.png，便于分析");
                }
            }
            catch (Exception ex) { sb.AppendLine("出错：" + ex.Message); }
            finally { if (shot != null) shot.Dispose(); }

            try { File.WriteAllText(Path.Combine(Application.StartupPath, "detect-result.txt"), sb.ToString(), Encoding.UTF8); }
            catch { }
        }
    }
}
