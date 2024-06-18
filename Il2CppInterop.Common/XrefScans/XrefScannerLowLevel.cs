using System.Runtime.InteropServices;
using Disarm;
using Iced.Intel;
using Microsoft.Extensions.Logging;

namespace Il2CppInterop.Common.XrefScans;

public static class XrefScannerLowLevel
{
    public static IEnumerable<IntPtr> JumpTargets(IntPtr codeStart, bool ignoreRetn = false)
    {
        return JumpTargetsImpl(XrefScanner.DecoderForAddress(codeStart), ignoreRetn);
    }

    private static IEnumerable<IntPtr> JumpTargetsImpl(IEnumerable<Arm64Instruction> myDecoder, bool ignoreRetn)
    {
        foreach (Arm64Instruction instruction in myDecoder)
        {
            if (instruction.MnemonicCategory.HasFlag(Arm64MnemonicCategory.Return) && !ignoreRetn)
                yield break;

            if (XrefScanUtilFinder.HasGroup(instruction.Mnemonic, "AArch64_GRP_CALL") || XrefScanUtilFinder.HasGroup(instruction.Mnemonic, "AArch64_GRP_JUMP"))
            {
                var target = XrefScanUtilFinder.ExtractTargetAddress(instruction);
                yield return (IntPtr)target;

                if (XrefScanUtilFinder.HasGroup(instruction.Mnemonic, "AArch64_GRP_JUMP") || target == 0)
                    yield break;
            }
        }
    }

    /*public static IEnumerable<IntPtr> CallAndIndirectTargets(IntPtr pointer)
    {
        return CallAndIndirectTargetsImpl(XrefScanner.DecoderForAddress(pointer, 1024 * 1024));
    }

    private static IEnumerable<IntPtr> CallAndIndirectTargetsImpl(Decoder decoder)
    {
        while (true)
        {
            decoder.Decode(out var instruction);
            if (decoder.LastError == DecoderError.NoMoreBytes) yield break;

            if (instruction.FlowControl == FlowControl.Return)
                yield break;

            if (instruction.Mnemonic == Mnemonic.Int || instruction.Mnemonic == Mnemonic.Int1)
                yield break;

            if (instruction.Mnemonic == Mnemonic.Call || instruction.Mnemonic == Mnemonic.Jmp)
            {
                var targetAddress = XrefScanner.ExtractTargetAddress(instruction);
                if (targetAddress != 0)
                    yield return (IntPtr)targetAddress;
                continue;
            }

            if (instruction.Mnemonic == Mnemonic.Lea)
                if (instruction.MemoryBase == Register.RIP)
                {
                    var targetAddress = instruction.IPRelativeMemoryAddress;
                    if (targetAddress != 0)
                        yield return (IntPtr)targetAddress;
                }
        }
    }*/
}
