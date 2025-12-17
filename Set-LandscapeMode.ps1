# Change any monitor set to "Landscape (flipped)" back to "Landscape"
# Run PowerShell as Administrator
Start-Transcript -Path "c:\OSDCloud\Set-Landscape.log"

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Configuration\*\*\*" -Name Rotation -Value 1 -ErrorAction SilentlyContinue

$Source = @"
using System;
using System.Runtime.InteropServices;

public class SystemRotation {
    // Calling the undocumented SetAutoRotation function by its ordinal (2507)
    [DllImport("user32.dll", EntryPoint = "#2507", SetLastError = true)]
    public static extern bool SetAutoRotation(bool bEnable);
}
"@

Add-Type -TypeDefinition $Source
[SystemRotation]::SetAutoRotation($false)

Add-Type -Language CSharp @"
using System;
using System.Runtime.InteropServices;

public class ScreenRotate {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct DEVMODE {
        private const int CCHDEVICENAME = 32;
        private const int CCHFORMNAME = 32;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCHDEVICENAME)]
        public string dmDeviceName;
        public short  dmSpecVersion;
        public short  dmDriverVersion;
        public short  dmSize;
        public short  dmDriverExtra;
        public int    dmFields;

        public int    dmPositionX;
        public int    dmPositionY;
        public int    dmDisplayOrientation;
        public int    dmDisplayFixedOutput;

        public short  dmColor;
        public short  dmDuplex;
        public short  dmYResolution;
        public short  dmTTOption;
        public short  dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCHFORMNAME)]
        public string dmFormName;
        public short  dmLogPixels;
        public int    dmBitsPerPel;
        public int    dmPelsWidth;
        public int    dmPelsHeight;
        public int    dmDisplayFlags;
        public int    dmDisplayFrequency;
        public int    dmICMMethod;
        public int    dmICMIntent;
        public int    dmMediaType;
        public int    dmDitherType;
        public int    dmReserved1;
        public int    dmReserved2;
        public int    dmPanningWidth;
        public int    dmPanningHeight;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct DISPLAY_DEVICE {
        public int cb;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string DeviceName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string DeviceString;
        public int StateFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string DeviceID;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string DeviceKey;
    }

    [DllImport("user32.dll", CharSet = CharSet.Ansi)]
    public static extern bool EnumDisplayDevices(string lpDevice, uint iDevNum, ref DISPLAY_DEVICE lpDisplayDevice, uint dwFlags);

    [DllImport("user32.dll", CharSet = CharSet.Ansi)]
    public static extern bool EnumDisplaySettings(string lpszDeviceName, int iModeNum, ref DEVMODE lpDevMode);

    [DllImport("user32.dll", CharSet = CharSet.Ansi)]
    public static extern int ChangeDisplaySettingsEx(string lpszDeviceName, ref DEVMODE lpDevMode, IntPtr hwnd, int dwflags, IntPtr lParam);

    public const int ENUM_CURRENT_SETTINGS = -1;
    public const int DM_DISPLAYORIENTATION = 0x00000080;

    public const int DMDO_DEFAULT = 0; // Landscape
    public const int DMDO_90 = 1;      // Portrait
    public const int DMDO_180 = 2;     // Landscape (flipped)
    public const int DMDO_270 = 3;     // Portrait (flipped)

    public const int CDS_UPDATEREGISTRY = 0x00000001;
    public const int CDS_RESET = 0x40000000;
    public const int DISP_CHANGE_SUCCESSFUL = 0;

    public static int ForceLandscapeIfFlipped() {
        uint i = 0;
        int changes = 0;
        while (true) {
            DISPLAY_DEVICE dd = new DISPLAY_DEVICE();
            dd.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICE));
            if (!EnumDisplayDevices(null, i, ref dd, 0)) break;

            // 0x00000001 = DISPLAY_DEVICE_ATTACHED_TO_DESKTOP
            if ((dd.StateFlags & 0x1) == 0) { i++; continue; }

            DEVMODE dm = new DEVMODE();
            dm.dmSize = (short)Marshal.SizeOf(typeof(DEVMODE));

            if (EnumDisplaySettings(dd.DeviceName, ENUM_CURRENT_SETTINGS, ref dm)) {
                int originalOrientation = dm.dmDisplayOrientation;

                // If not already landscape, force to landscape
                if (originalOrientation != DMDO_DEFAULT) {
                    // If coming from portrait, swap width and height
                    if (originalOrientation == DMDO_90 || originalOrientation == DMDO_270) {
                        int temp = dm.dmPelsWidth;
                        dm.dmPelsWidth = dm.dmPelsHeight;
                        dm.dmPelsHeight = temp;
                    }

                    dm.dmFields |= DM_DISPLAYORIENTATION;
                    dm.dmDisplayOrientation = DMDO_DEFAULT;

                    int res = ChangeDisplaySettingsEx(dd.DeviceName, ref dm, IntPtr.Zero, CDS_UPDATEREGISTRY, IntPtr.Zero);
                    if (res == DISP_CHANGE_SUCCESSFUL) changes++;
                }
            }
            i++;
        }
        if (changes > 0) {
            // Commit and apply to all
            DEVMODE dummy = new DEVMODE();
            dummy.dmSize = (short)Marshal.SizeOf(typeof(DEVMODE));
            return ChangeDisplaySettingsEx(null, ref dummy, IntPtr.Zero, CDS_RESET, IntPtr.Zero);
        }
        return DISP_CHANGE_SUCCESSFUL;
    }
}
"@


Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Configuration\*\*\*"

Stop-Transcript

# Run the fix
$result = [ScreenRotate]::ForceLandscapeIfFlipped()
if ($result -eq 0) {
    Write-Host "Orientation set to Landscape where needed."
} else {
    Write-Host "ChangeDisplaySettingsEx returned code $result"
}
