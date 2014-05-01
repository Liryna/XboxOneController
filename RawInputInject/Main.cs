using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.IO;
using System.Runtime.InteropServices;
using EasyHook;
using System.Reflection;

namespace XboxOneController
{
    public class XboxOneControllerInjection : EasyHook.IEntryPoint
    {
        public RemoInterface Interface = null;
        public List<LocalHook> Hooks = null;
        Stack<String> Queue = new Stack<string>();

        public XboxOneControllerInjection(
            RemoteHooking.IContext InContext,
            String InChannelName)
        {
            Interface = RemoteHooking.IpcConnectClient<RemoInterface>(InChannelName);
            Hooks = new List<LocalHook>();
            Interface.Ping(RemoteHooking.GetCurrentProcessId());
        }

        public void Run(
            RemoteHooking.IContext InContext,
            String InArg1)
        {
            try
            {
                Hooks.Add(LocalHook.Create(LocalHook.GetProcAddress("user32.dll", "GetRawInputData"),
                    new DGetRawInputData(GetRawInputData_hook),
                    this));
                Hooks.Add(LocalHook.Create(LocalHook.GetProcAddress("user32.dll", "GetRawInputDeviceInfoW"),
                    new DGetRawInputDeviceInfo(GetRawInputDeviceInfo_hook),
                    this));
                Hooks.Add(LocalHook.Create(LocalHook.GetProcAddress("user32.dll", "GetRawInputDeviceList"),
                    new DGetRawInputDeviceList(GetRawInputDeviceList_hook),
                    this));
                Hooks.Add(LocalHook.Create(LocalHook.GetProcAddress("user32.dll", "RegisterRawInputDevices"),
                    new DRegisterRawInputDevices(RegisterRawInputDevices_hook),
                    this));

                Hooks.Add(LocalHook.Create(LocalHook.GetProcAddress("hid.dll", "HidP_GetCaps"),
                    new DHidP_GetCaps(HidP_GetCaps_hook),
                    this));
                Hooks.Add(LocalHook.Create(LocalHook.GetProcAddress("hid.dll", "HidP_GetUsages"),
                    new DHidP_GetUsages(HidP_GetUsages_hook),
                    this));
                Hooks.Add(LocalHook.Create(LocalHook.GetProcAddress("hid.dll", "HidP_GetValueCaps"),
                    new DHidP_GetValueCaps(HidP_GetValueCaps_hook),
                    this));
                /*
                 * Don't forget that all hooks will start deaktivated...
                 * The following ensures that all threads are intercepted:
                 */
                foreach (LocalHook hook in Hooks)
                    hook.ThreadACL.SetExclusiveACL(new Int32[1]);
            }
            catch (Exception e)
            {
                /*
                    Now we should notice our host process about this error...
                 */
                Interface.ReportError(RemoteHooking.GetCurrentProcessId(), Assembly.GetExecutingAssembly().GetName().Name, e);

                return;
            }


            // wait for host process termination...
            try
            {
                while (Interface.Ping(RemoteHooking.GetCurrentProcessId()))
                {
                    Thread.Sleep(500);

                    // transmit newly monitored file accesses...
                    lock (Queue)
                    {
                        if (Queue.Count > 0)
                        {
                            String[] Package = null;

                            Package = Queue.ToArray();

                            Queue.Clear();

                            Interface.OnFunctionsCalled(RemoteHooking.GetCurrentProcessId(), Package);
                        }
                    }
                }
            }
            catch
            {
                // NET Remoting will raise an exception if host is unreachable
            }
        }

        private const uint RID_HEADER = 0x10000005;
        private const uint RID_INPUT = 0x10000003;
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate uint DGetRawInputData(IntPtr hRawInput, uint uiCommand, IntPtr pData, ref uint pcbSize, uint cbSizeHeader);
        delegate uint DGetRawInputDataAsync(IntPtr hRawInput, uint uiCommand, IntPtr pData, ref uint pcbSize, uint cbSizeHeader);
        [DllImport("user32.dll", EntryPoint = "GetRawInputData", CharSet = CharSet.Unicode, SetLastError = true)]
        public extern static uint GetRawInputData(IntPtr hRawInput, uint uiCommand, IntPtr pData, ref uint pcbSize, uint cbSizeHeader);

        static uint GetRawInputData_hook(IntPtr hRawInput, uint uiCommand, IntPtr pData, ref uint pcbSize, uint cbSizeHeader)
        {
            try
            {
                XboxOneControllerInjection This = (XboxOneControllerInjection)HookRuntimeInfo.Callback;
                //TODO
                lock (This.Queue)
                {
                    if (uiCommand == RID_HEADER)
                    {
                        This.Queue.Push("GetRawInputData RID_HEADER");
                    }
                    else if (uiCommand == RID_INPUT)
                    {
                        This.Queue.Push("GetRawInputData RID_INPUT");
                    }
                    else
                        This.Queue.Push("GetRawInputData " + uiCommand);
                }
            }
            catch
            {
            }
            return GetRawInputData(hRawInput, uiCommand, pData, ref pcbSize, cbSizeHeader);
        }


        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate uint DGetRawInputDeviceInfo(IntPtr hDevice, uint uiCommand, IntPtr pData, ref uint pcbSize);
        delegate uint DGetRawInputDeviceInfoAsync(IntPtr hDevice, uint uiCommand, IntPtr pData, ref uint pcbSize);
        [DllImport("user32.dll", EntryPoint = "GetRawInputDeviceInfo", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint GetRawInputDeviceInfo(IntPtr hDevice, uint uiCommand, IntPtr pData, ref uint pcbSize);

        static uint GetRawInputDeviceInfo_hook(IntPtr hDevice, uint uiCommand, IntPtr pData, ref uint pcbSize)
        {
            try
            {
                XboxOneControllerInjection This = (XboxOneControllerInjection)HookRuntimeInfo.Callback;

                //TODO
                lock (This.Queue)
                {
                    if (This.Queue.Count < 1000)
                        This.Queue.Push("GetRawInputDeviceInfo");
                }
            }
            catch
            {
            }
            return GetRawInputDeviceInfo(hDevice, uiCommand, pData, ref pcbSize);
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct RAWINPUTDEVICELIST
        {
            public IntPtr hDevice;
            public Int32 dwType;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate uint DGetRawInputDeviceList([Out]RAWINPUTDEVICELIST[] pRawInputDeviceList, ref uint puiNumDevices, uint cbSize);
        delegate uint DGetRawInputDeviceListAsync([Out]RAWINPUTDEVICELIST[] pRawInputDeviceList, ref uint puiNumDevices, uint cbSize);
        [DllImport("user32.dll")]
        public static extern uint GetRawInputDeviceList([Out]RAWINPUTDEVICELIST[] pRawInputDeviceList, ref uint puiNumDevices, uint cbSize);
        static uint GetRawInputDeviceList_hook([Out]RAWINPUTDEVICELIST[] pRawInputDeviceList, ref uint puiNumDevices, uint cbSize)
        {
            try
            {
                XboxOneControllerInjection This = (XboxOneControllerInjection)HookRuntimeInfo.Callback;
                //TODO
                lock (This.Queue)
                {
                    if (This.Queue.Count < 1000)
                        This.Queue.Push("GetRawInputDeviceInfo");
                }
            }
            catch
            {
            }
            return GetRawInputDeviceList(pRawInputDeviceList, ref puiNumDevices, cbSize);
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RAWINPUTDEVICE
        {
            [MarshalAs(UnmanagedType.U2)]
            public ushort usUsagePage;
            [MarshalAs(UnmanagedType.U2)]
            public ushort usUsage;
            [MarshalAs(UnmanagedType.U4)]
            public int dwFlags;
            public IntPtr hwndTarget; // The window that will receive WM_INPUT messages
        }


        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool DRegisterRawInputDevices(RAWINPUTDEVICE[] pRawInputDevices, uint uiNumDevices, int cbSize);
        delegate bool DRegisterRawInputDevicesAsync(RAWINPUTDEVICE[] pRawInputDevices, uint uiNumDevices, int cbSize);
        [DllImport("user32.dll", EntryPoint = "RegisterRawInputDevices")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool RegisterRawInputDevices(RAWINPUTDEVICE[] pRawInputDevices, uint uiNumDevices, int cbSize);
        static bool RegisterRawInputDevices_hook(RAWINPUTDEVICE[] pRawInputDevices, uint uiNumDevices, int cbSize)
        {
            try
            {
                XboxOneControllerInjection This = (XboxOneControllerInjection)HookRuntimeInfo.Callback;
                //TODO
                lock (This.Queue)
                {
                    if (This.Queue.Count < 1000)
                        This.Queue.Push("RegisterRawInputDevices");
                }
            }
            catch
            {
            }
            return RegisterRawInputDevices(pRawInputDevices, uiNumDevices, cbSize);
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct HidCaps
        {
            public ushort Usage;
            public ushort UsagePage;
            public ushort InputReportByteLength;
            public ushort OutputReportByteLength;
            public ushort FeatureReportByteLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 17)]
            public short[] Reserved;
            public ushort NumberLinkCollectionNodes;
            public ushort NumberInputButtonCaps;
            public ushort NumberInputValueCaps;
            public ushort NumberInputDataIndices;
            public ushort NumberOutputButtonCaps;
            public ushort NumberOutputValueCaps;
            public ushort NumberOutputDataIndices;
            public ushort NumberFeatureButtonCaps;
            public ushort NumberFeatureValueCaps;
            public ushort NumberFeatureDataIndices;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool DHidP_GetCaps(IntPtr lpData, out HidCaps oCaps);
        delegate bool DHidP_GetCapsAsync(IntPtr lpData, out HidCaps oCaps);
        [DllImport("hid.dll", SetLastError = true)]
        public static extern bool HidP_GetCaps(IntPtr lpData, out HidCaps oCaps);
        static bool HidP_GetCaps_hook(IntPtr lpData, out HidCaps oCaps)
        {
            try
            {
                XboxOneControllerInjection This = (XboxOneControllerInjection)HookRuntimeInfo.Callback;
                //TODO
                lock (This.Queue)
                {
                    if (This.Queue.Count < 1000)
                        This.Queue.Push("HidP_GetCaps");
                }
            }
            catch
            {
            }
            return HidP_GetCaps(lpData, out oCaps);
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HidRange
        {
            public short UsageMin;
            public short UsageMax;
            public short StringMin;
            public short StringMax;
            public short DesignatorMin;
            public short DesignatorMax;
            public short DataIndexMin;
            public short DataIndexMax;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HidNotRange
        {
            public ushort Usage;
            public ushort Reserved1;
            public ushort StringIndex;
            public ushort Reserved2;
            public ushort DesignatorIndex;
            public ushort Reserved3;
            public ushort DataIndex;
            public ushort Reserved4;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct HidValueCaps
        {
            [FieldOffset(0)]
            public ushort UsagePage;
            [FieldOffset(2)]
            public byte ReportID;
            [MarshalAs(UnmanagedType.I1)]
            [FieldOffset(3)]
            public bool IsAlias;
            [FieldOffset(4)]
            public short BitField;
            [FieldOffset(6)]
            public short LinkCollection;
            [FieldOffset(8)]
            public short LinkUsage;
            [FieldOffset(10)]
            public short LinkUsagePage;
            [MarshalAs(UnmanagedType.I1)]
            [FieldOffset(12)]
            public bool IsRange;
            [MarshalAs(UnmanagedType.I1)]
            [FieldOffset(13)]
            public bool IsStringRange;
            [MarshalAs(UnmanagedType.I1)]
            [FieldOffset(14)]
            public bool IsDesignatorRange;
            [MarshalAs(UnmanagedType.I1)]
            [FieldOffset(15)]
            public bool IsAbsolute;
            [MarshalAs(UnmanagedType.I1)]
            [FieldOffset(16)]
            public bool HasNull;
            [FieldOffset(17)]
            public byte Reserved;						// UCHAR  Reserved;
            [FieldOffset(18)]
            public short BitSize;
            [FieldOffset(20)]
            public short ReportCount;
            [FieldOffset(22)]
            public short Reserved2a;
            [FieldOffset(24)]
            public short Reserved2b;
            [FieldOffset(26)]
            public short Reserved2c;
            [FieldOffset(28)]
            public short Reserved2d;
            [FieldOffset(30)]
            public short Reserved2e;
            [FieldOffset(32)]
            public short UnitsExp;
            [FieldOffset(34)]
            public short Units;
            [FieldOffset(36)]
            public short LogicalMin;
            [FieldOffset(38)]
            public short LogicalMax;
            [FieldOffset(40)]
            public short PhysicalMin;
            [FieldOffset(42)]
            public short PhysicalMax;
            // The Structs in the Union			
            [FieldOffset(44)]
            public HidRange Range;
            [FieldOffset(44)]
            public HidNotRange NotRange;
        }

        public enum HIDP_REPORT_TYPE
        {
            HidP_Input,
            HidP_Output,
            HidP_Feature,
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate int DHidP_GetValueCaps(HIDP_REPORT_TYPE reportType, [In, Out] HidValueCaps[] valueCaps, ref ushort valueCapsLength, IntPtr preparsedData);
        delegate int DHidP_GetValueCapsAsync(HIDP_REPORT_TYPE reportType, [In, Out] HidValueCaps[] valueCaps, ref ushort valueCapsLength, IntPtr preparsedData);
        [DllImport("hid.dll", SetLastError = true)]
        public static extern int HidP_GetValueCaps(HIDP_REPORT_TYPE reportType, [In, Out] HidValueCaps[] valueCaps, ref ushort valueCapsLength, IntPtr preparsedData);
        static int HidP_GetValueCaps_hook(HIDP_REPORT_TYPE reportType, [In, Out] HidValueCaps[] valueCaps, ref ushort valueCapsLength, IntPtr preparsedData)
        {
                try
            {
                XboxOneControllerInjection This = (XboxOneControllerInjection)HookRuntimeInfo.Callback;
                //TODO
                lock (This.Queue)
                {
                    if (This.Queue.Count < 1000)
                        This.Queue.Push("HidP_GetValueCaps");
                }
            }
            catch
            {
            }
            return HidP_GetValueCaps(reportType, valueCaps, ref valueCapsLength, preparsedData);
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct HIDP_DATA
        {
            [FieldOffset(0)]
            public short DataIndex;
            [FieldOffset(2)]
            public short Reserved;

            [FieldOffset(4)]
            public int RawValue;
            [FieldOffset(4), MarshalAs(UnmanagedType.U1)]
            public bool On;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate int DHidP_GetUsages(HIDP_REPORT_TYPE ReportType, short UsagePage, short LinkCollection, [In, Out] HIDP_DATA[] UsageList, ref int UsageLength, IntPtr PreparsedData, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 7)] byte[] Report, int ReportLength);
        delegate int DHidP_GetUsagesAsync(HIDP_REPORT_TYPE ReportType, short UsagePage, short LinkCollection, [In, Out] HIDP_DATA[] UsageList, ref int UsageLength, IntPtr PreparsedData, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 7)] byte[] Report, int ReportLength);
        [DllImport("hid.dll", SetLastError = true)]
        static public extern int HidP_GetUsages(HIDP_REPORT_TYPE ReportType, short UsagePage, short LinkCollection, [In, Out] HIDP_DATA[] UsageList, ref int UsageLength, IntPtr PreparsedData, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 7)] byte[] Report, int ReportLength);
        static int HidP_GetUsages_hook(HIDP_REPORT_TYPE ReportType, short UsagePage, short LinkCollection, [In, Out] HIDP_DATA[] UsageList, ref int UsageLength, IntPtr PreparsedData, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 7)] byte[] Report, int ReportLength)
        {
            try
            {
                XboxOneControllerInjection This = (XboxOneControllerInjection)HookRuntimeInfo.Callback;
                //TODO
                lock (This.Queue)
                {
                    if (This.Queue.Count < 1000)
                        This.Queue.Push("HidP_GetUsages");
                }
            }
            catch
            {
            }
            return HidP_GetUsages(ReportType, UsagePage, LinkCollection, UsageList, ref UsageLength, PreparsedData, Report, ReportLength);
        }
    }
}
