using System.Diagnostics;
using Disarm;

namespace Il2CppInterop.Common.XrefScans;

public static class XrefScannerLowLevel
{
    public static IEnumerable<IntPtr> JumpTargets(IntPtr codeStart, bool ignoreRetn = false)
    {
        return JumpTargetsImpl(XrefScanner.DecoderForAddress(codeStart), ignoreRetn);
    }

    private static IEnumerable<IntPtr> JumpTargetsImpl(IEnumerable<Arm64Instruction> myDecoder, bool ignoreRetn)
    {
        var firstFlowControl = true;

        foreach (Arm64Instruction instruction in myDecoder)
        {
            if ((instruction.MnemonicCategory.HasFlag(Arm64MnemonicCategory.Return) || instruction.Mnemonic == Arm64Mnemonic.RET) && !ignoreRetn)
                yield break;

            // BL and BLR are calls; B and BR are unconditional branches (B can have a CC qualifier, but the additional check fixes that)
            // BC is a conditional branch, but adding it fixes a weird bug where it causes Pass 16 to take multiple minutes rather than seconds
            if (instruction.Mnemonic is Arm64Mnemonic.BL or Arm64Mnemonic.BLR or Arm64Mnemonic.B or Arm64Mnemonic.BR or Arm64Mnemonic.BC && instruction.MnemonicConditionCode == Arm64ConditionCode.NONE)
            {
                var target = XrefScanUtilFinder.ExtractTargetAddress(instruction);
                yield return (IntPtr)target;

                if (XrefScanUtilFinder.HasGroup(instruction.Mnemonic, "AArch64_GRP_JUMP") || target == 0) yield break;
                //if (firstFlowControl && instruction.Mnemonic is Arm64Mnemonic.B or Arm64Mnemonic.BR) // if unconditional
                //    yield break;
            }

            if (XrefScanUtilFinder.HasGroup(instruction.Mnemonic, "AArch64_GRP_JUMP") || XrefScanUtilFinder.HasGroup(instruction.Mnemonic, "AArch64_GRP_CALL"))
                firstFlowControl = false;
        }
    }

    public static int InstructionsToBL(IntPtr codeStart, int maxInstructions = 20)
    {
        var decoder = XrefScanner.DecoderForAddress(codeStart, maxInstructions * 4);
        var instructionCount = 0;

        foreach (Arm64Instruction instruction in decoder)
        {
            instructionCount++;
            if (instruction.Mnemonic == Arm64Mnemonic.BL)
                return instructionCount;
        }

        return instructionCount;
    }

    // in the wise words of sircoolness, when porting this, i don't know what it does
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
