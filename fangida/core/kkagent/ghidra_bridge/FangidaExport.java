// Bounded headless export of Ghidra functions, references, p-code, and decompiled C.
// @category Fangida

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class FangidaExport extends HeadlessScript {
    private static final int MAX_OPS_PER_INSTRUCTION = 256;
    private static final int MAX_PSEUDOC_CHARS_PER_FUNCTION = 131_072;
    private static final int MAX_TOTAL_PSEUDOC_CHARS = 524_288;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 6) {
            throw new IllegalArgumentException(
                "Expected output path, function/xref/p-code/decompile limits, and decompile seconds"
            );
        }
        int maxFunctions = positive(args[1]);
        int maxXrefs = positive(args[2]);
        int maxPcode = positive(args[3]);
        int maxDecompiledFunctions = nonNegative(args[4]);
        int maxDecompileSeconds = positive(args[5]);
        File output = new File(args[0]);
        if (currentProgram == null) {
            throw new IllegalStateException("Ghidra did not load a program");
        }

        int functionCount = 0;
        int xrefCount = 0;
        int pcodeCount = 0;
        int omittedNonMemoryXrefs = 0;
        int truncatedPcodeOps = 0;
        boolean functionsTruncated;
        boolean xrefsTruncated;
        boolean pcodeTruncated;
        boolean analysisTimedOut = analysisTimeoutOccurred();
        List<Function> decompileTargets = new ArrayList<>();

        try (Writer writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(output), StandardCharsets.UTF_8))) {
            writer.write("{\"schema_version\":2,\"status\":\"ok\",\"functions\":[");
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && functionCount < maxFunctions) {
                monitor.checkCancelled();
                Function function = functions.next();
                if (decompileTargets.size() < maxDecompiledFunctions) {
                    decompileTargets.add(function);
                }
                if (functionCount++ != 0) {
                    writer.write(',');
                }
                Address address = function.getEntryPoint();
                writer.write("{\"start\":");
                address(writer, address);
                writer.write(",\"name\":");
                string(writer, function.getName());
                writer.write(",\"address_space\":");
                string(writer, address.getAddressSpace().getName());
                writer.write('}');
            }
            functionsTruncated = functions.hasNext();

            writer.write("],\"xrefs\":[");
            Address minAddress = currentProgram.getMinAddress();
            ReferenceIterator references = minAddress == null ? null
                : currentProgram.getReferenceManager().getReferenceIterator(minAddress);
            while (references != null && references.hasNext() && xrefCount < maxXrefs) {
                monitor.checkCancelled();
                Reference ref = references.next();
                Address src = ref.getFromAddress();
                Address dst = ref.getToAddress();
                // Offsets in stack/register/external spaces cannot be merged as memory xrefs.
                if (!ref.isMemoryReference() || !src.isMemoryAddress() || !dst.isMemoryAddress()) {
                    omittedNonMemoryXrefs++;
                    continue;
                }
                if (xrefCount++ != 0) {
                    writer.write(',');
                }
                RefType type = ref.getReferenceType();
                writer.write("{\"src\":");
                address(writer, src);
                writer.write(",\"dst\":");
                address(writer, dst);
                writer.write(",\"src_space\":");
                string(writer, src.getAddressSpace().getName());
                writer.write(",\"dst_space\":");
                string(writer, dst.getAddressSpace().getName());
                writer.write(",\"kind\":");
                string(writer, type.isCall() ? "call" : type.isJump() ? "jmp" : "data");
                writer.write(",\"ghidra_type\":");
                string(writer, type.toString());
                writer.write(",\"source\":");
                string(writer, ref.getSource().toString());
                writer.write('}');
            }
            xrefsTruncated = references != null && references.hasNext();

            writer.write("],\"pcode\":[");
            InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
            while (instructions.hasNext() && pcodeCount < maxPcode) {
                monitor.checkCancelled();
                Instruction instruction = instructions.next();
                PcodeOp[] operations = instruction.getPcode();
                if (operations.length == 0) {
                    continue;
                }
                if (pcodeCount++ != 0) {
                    writer.write(',');
                }
                Address instructionAddress = instruction.getAddress();
                writer.write("{\"addr\":");
                address(writer, instructionAddress);
                writer.write(",\"address_space\":");
                string(writer, instructionAddress.getAddressSpace().getName());
                writer.write(",\"ops\":[");
                int opLimit = Math.min(operations.length, MAX_OPS_PER_INSTRUCTION);
                for (int i = 0; i < opLimit; i++) {
                    if (i != 0) {
                        writer.write(',');
                    }
                    PcodeOp operation = operations[i];
                    writer.write("{\"opcode\":");
                    string(writer, operation.getMnemonic());
                    writer.write(",\"output\":");
                    Varnode result = operation.getOutput();
                    if (result == null) {
                        writer.write("null");
                    } else {
                        string(writer, result.toString());
                    }
                    writer.write(",\"inputs\":[");
                    for (int j = 0; j < operation.getNumInputs(); j++) {
                        if (j != 0) {
                            writer.write(',');
                        }
                        string(writer, operation.getInput(j).toString());
                    }
                    writer.write("]}");
                }
                writer.write("]");
                if (operations.length > opLimit) {
                    writer.write(",\"truncated_ops\":true");
                    truncatedPcodeOps++;
                }
                writer.write('}');
            }
            pcodeTruncated = instructions.hasNext();

            writer.write("],\"decompiled_functions\":[");
            DecompileReport decompile = writeDecompiled(
                writer, decompileTargets, maxDecompileSeconds
            );

            writer.write("],\"stats\":{\"function_count\":");
            writer.write(Integer.toString(functionCount));
            writer.write(",\"xref_count\":");
            writer.write(Integer.toString(xrefCount));
            writer.write(",\"pcode_instruction_count\":");
            writer.write(Integer.toString(pcodeCount));
            writer.write(",\"omitted_non_memory_xrefs\":");
            writer.write(Integer.toString(omittedNonMemoryXrefs));
            writer.write(",\"truncated_pcode_ops\":");
            writer.write(Integer.toString(truncatedPcodeOps));
            writer.write(",\"analysis_timed_out\":");
            writer.write(Boolean.toString(analysisTimedOut));
            writer.write(",\"decompile_attempted\":");
            writer.write(Integer.toString(decompile.attempted));
            writer.write(",\"decompile_succeeded\":");
            writer.write(Integer.toString(decompile.succeeded));
            writer.write(",\"decompile_failed\":");
            writer.write(Integer.toString(decompile.failed));
            writer.write(",\"decompile_timed_out\":");
            writer.write(Integer.toString(decompile.timedOut));
            writer.write(",\"decompile_setup_failed\":");
            writer.write(Boolean.toString(decompile.setupFailed));
            writer.write(",\"decompile_budget_seconds\":");
            writer.write(Integer.toString(maxDecompileSeconds));
            writer.write(",\"decompile_text_truncated\":");
            writer.write(Integer.toString(decompile.textTruncated));
            writer.write(",\"decompile_budget_exhausted\":");
            writer.write(Boolean.toString(decompile.budgetExhausted));
            writer.write("},\"warnings\":[");
            boolean comma = false;
            if (analysisTimedOut) {
                string(writer, "Ghidra analysis timed out; results may be incomplete");
                comma = true;
            }
            if (functionsTruncated) {
                if (comma) writer.write(',');
                string(writer, "Function limit reached");
                comma = true;
            }
            if (xrefsTruncated) {
                if (comma) writer.write(',');
                string(writer, "Xref limit reached");
                comma = true;
            }
            if (pcodeTruncated) {
                if (comma) writer.write(',');
                string(writer, "P-code instruction limit reached");
                comma = true;
            }
            if (truncatedPcodeOps != 0) {
                if (comma) writer.write(',');
                string(writer, "P-code operations truncated for some instructions");
                comma = true;
            }
            if (maxDecompiledFunctions > 0 &&
                    (functionCount > decompileTargets.size() || functionsTruncated)) {
                if (comma) writer.write(',');
                string(writer, "Decompiler function limit reached");
                comma = true;
            }
            if (decompile.failed != 0) {
                if (comma) writer.write(',');
                string(writer, "Ghidra decompilation failed for some functions");
                comma = true;
            }
            if (decompile.setupFailed) {
                if (comma) writer.write(',');
                string(writer, "Ghidra decompiler initialization failed");
                comma = true;
            }
            if (decompile.timedOut != 0 || decompile.budgetExhausted) {
                if (comma) writer.write(',');
                string(writer, "Ghidra decompilation time budget reached");
                comma = true;
            }
            if (decompile.textTruncated != 0) {
                if (comma) writer.write(',');
                string(writer, "Ghidra pseudo-C text truncated for some functions");
            }
            writer.write("]}");
        }
    }

    private static final class DecompileReport {
        int attempted;
        int succeeded;
        int failed;
        int timedOut;
        int textTruncated;
        boolean budgetExhausted;
        boolean setupFailed;
    }

    private DecompileReport writeDecompiled(
            Writer writer, List<Function> targets, int budgetSeconds) throws Exception {
        DecompileReport report = new DecompileReport();
        if (targets.isEmpty()) {
            return report;
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                report.setupFailed = true;
                return report;
            }
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(budgetSeconds);
            int charsRemaining = MAX_TOTAL_PSEUDOC_CHARS;
            for (Function function : targets) {
                monitor.checkCancelled();
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0 || charsRemaining <= 0) {
                    report.budgetExhausted = true;
                    break;
                }
                int timeout = (int) Math.max(
                    1L, Math.min((long) budgetSeconds,
                        (remaining + TimeUnit.SECONDS.toNanos(1) - 1) /
                        TimeUnit.SECONDS.toNanos(1))
                );
                report.attempted++;
                try {
                    DecompileResults result = decompiler.decompileFunction(
                        function, timeout, monitor
                    );
                    if (result == null || !result.decompileCompleted()) {
                        if (result != null && result.isTimedOut()) {
                            report.timedOut++;
                        } else {
                            report.failed++;
                        }
                        continue;
                    }
                    DecompiledFunction value = result.getDecompiledFunction();
                    String pseudoc = value == null ? null : value.getC();
                    if (pseudoc == null || pseudoc.trim().isEmpty()) {
                        report.failed++;
                        continue;
                    }
                    int chars = Math.min(
                        pseudoc.length(), Math.min(MAX_PSEUDOC_CHARS_PER_FUNCTION, charsRemaining)
                    );
                    // Avoid cutting a UTF-16 surrogate pair at the export limit.
                    if (chars < pseudoc.length() && chars > 0 &&
                            Character.isHighSurrogate(pseudoc.charAt(chars - 1))) {
                        chars--;
                    }
                    if (chars == 0) {
                        report.budgetExhausted = true;
                        break;
                    }
                    boolean truncated = chars < pseudoc.length();
                    if (report.succeeded++ != 0) {
                        writer.write(',');
                    }
                    Address address = function.getEntryPoint();
                    writer.write("{\"start\":");
                    address(writer, address);
                    writer.write(",\"address_space\":");
                    string(writer, address.getAddressSpace().getName());
                    writer.write(",\"pseudoc\":");
                    string(writer, pseudoc.substring(0, chars));
                    writer.write(",\"producer\":\"ghidra\",\"truncated\":");
                    writer.write(Boolean.toString(truncated));
                    writer.write('}');
                    charsRemaining -= chars;
                    if (truncated) {
                        report.textTruncated++;
                    }
                } catch (RuntimeException exception) {
                    // One bad function should not discard the successful exports.
                    report.failed++;
                }
            }
        } catch (RuntimeException exception) {
            // Decompiler initialization can fail independently of analysis.
            report.setupFailed = true;
        } finally {
            decompiler.dispose();
        }
        return report;
    }

    private static int positive(String value) {
        int result = Integer.parseInt(value);
        if (result <= 0) {
            throw new IllegalArgumentException("Export limits must be positive");
        }
        return result;
    }

    private static int nonNegative(String value) {
        int result = Integer.parseInt(value);
        if (result < 0) {
            throw new IllegalArgumentException("Export limits must be nonnegative");
        }
        return result;
    }

    private static void address(Writer writer, Address value) throws java.io.IOException {
        writer.write(Long.toUnsignedString(value.getUnsignedOffset()));
    }

    private static void string(Writer writer, String value) throws java.io.IOException {
        writer.write('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': writer.write("\\\""); break;
                case '\\': writer.write("\\\\"); break;
                case '\n': writer.write("\\n"); break;
                case '\r': writer.write("\\r"); break;
                case '\t': writer.write("\\t"); break;
                default:
                    if (c < 0x20 || c > 0x7e) {
                        String hex = Integer.toHexString(c);
                        writer.write("\\u");
                        for (int pad = hex.length(); pad < 4; pad++) writer.write('0');
                        writer.write(hex);
                    } else {
                        writer.write(c);
                    }
            }
        }
        writer.write('"');
    }
}
