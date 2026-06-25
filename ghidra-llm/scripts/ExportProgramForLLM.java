/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Exports human-readable disassembly + decompilation text files for the analyzed
// program so they can be ingested by an LLM (e.g. Claude) for Q&A about the binary.
//
// Run headless as a post-script, passing an output directory:
//   analyzeHeadless <proj> <name> -import <binary> \
//       -scriptPath <dir-of-this-script> \
//       -postScript ExportProgramForLLM.java <outputDir> [nodecompile]
//
// Writes into <outputDir>:
//   program_info.txt   - small context header (arch, hashes, image base, ...)
//   disassembly.txt    - full instruction listing, grouped by function
//   decompilation.c    - decompiled C per (non-thunk, non-external) function
//@category Export
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;

public class ExportProgramForLLM extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		File outDir = (args.length >= 1) ? new File(args[0])
				: askDirectory("Select output directory", "OK");
		if (!outDir.exists() && !outDir.mkdirs()) {
			throw new IOException("Cannot create output directory: " + outDir);
		}

		boolean skipDecompile = false;
		for (int i = 1; i < args.length; i++) {
			if ("nodecompile".equalsIgnoreCase(args[i])) {
				skipDecompile = true;
			}
		}

		println("ExportProgramForLLM: writing to " + outDir.getAbsolutePath());

		writeProgramInfo(new File(outDir, "program_info.txt"));
		writeDisassembly(new File(outDir, "disassembly.txt"));
		if (skipDecompile) {
			println("ExportProgramForLLM: decompilation skipped (nodecompile flag)");
		}
		else {
			writeDecompilation(new File(outDir, "decompilation.c"));
		}

		println("ExportProgramForLLM: export complete -> " + outDir.getAbsolutePath());
	}

	private PrintWriter pw(File f) throws IOException {
		return new PrintWriter(new BufferedWriter(new FileWriter(f)));
	}

	private void writeProgramInfo(File f) throws Exception {
		try (PrintWriter w = pw(f)) {
			w.println("# Program info (context for LLM analysis)");
			w.println();
			w.println("Name:           " + currentProgram.getName());
			w.println("Executable:     " + currentProgram.getExecutablePath());
			w.println("Format:         " + currentProgram.getExecutableFormat());
			w.println("Language:       " + currentProgram.getLanguageID());
			w.println("Compiler:       " + currentProgram.getCompilerSpec().getCompilerSpecID());
			w.println("Image base:     " + currentProgram.getImageBase());
			w.println("Address range:  " + currentProgram.getMinAddress() + " - "
					+ currentProgram.getMaxAddress());
			w.println("MD5:            " + currentProgram.getExecutableMD5());
			w.println("SHA256:         " + currentProgram.getExecutableSHA256());
			w.println("Created:        " + currentProgram.getCreationDate());
			w.println("Function count: "
					+ currentProgram.getFunctionManager().getFunctionCount());
			w.println();
			w.println("Memory map:");
			for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
				w.printf("  %-20s %s - %s  %s%s%s%n", b.getName(), b.getStart(), b.getEnd(),
					b.isRead() ? "r" : "-", b.isWrite() ? "w" : "-",
					b.isExecute() ? "x" : "-");
			}
		}
	}

	private void writeDisassembly(File f) throws Exception {
		try (PrintWriter w = pw(f)) {
			w.println("; Disassembly of " + currentProgram.getName());
			w.println("; format: <address>  <bytes>  <instruction>");
			Listing listing = currentProgram.getListing();
			FunctionManager fm = currentProgram.getFunctionManager();
			InstructionIterator it = listing.getInstructions(true);
			Function current = null;
			boolean first = true;
			while (it.hasNext() && !monitor.isCancelled()) {
				Instruction ins = it.next();
				Function fn = fm.getFunctionContaining(ins.getMinAddress());
				if (first || fn != current) {
					current = fn;
					first = false;
					w.println();
					w.println("; ---- "
							+ (fn != null ? fn.getName() + " @ " + fn.getEntryPoint()
									: "<no function>")
							+ " ----");
				}
				String bytes;
				try {
					StringBuilder hb = new StringBuilder();
					for (byte b : ins.getBytes()) {
						hb.append(String.format("%02x", b));
					}
					bytes = hb.toString();
				}
				catch (Exception e) {
					bytes = "??";
				}
				w.printf("%s  %-16s  %s%n", ins.getAddress(), bytes, ins.toString());
			}
		}
	}

	private void writeDecompilation(File f) throws Exception {
		DecompInterface dec = new DecompInterface();
		try (PrintWriter w = pw(f)) {
			// In headless mode there is no GUI tool, so grab options from the program
			// rather than from a tool/service provider.
			DecompileOptions opts = new DecompileOptions();
			opts.grabFromProgram(currentProgram);
			dec.setOptions(opts);
			dec.toggleCCode(true);
			dec.toggleSyntaxTree(true);
			dec.setSimplificationStyle("decompile");
			if (!dec.openProgram(currentProgram)) {
				w.println("// Failed to open program in decompiler: " + dec.getLastMessage());
				return;
			}
			int timeout = dec.getOptions().getDefaultTimeout();
			w.println("// Decompilation of " + currentProgram.getName());
			w.println();
			FunctionIterator it = currentProgram.getListing().getFunctions(true);
			while (it.hasNext() && !monitor.isCancelled()) {
				Function fn = it.next();
				if (fn.isThunk() || fn.isExternal()) {
					continue;
				}
				w.println("// ==== " + fn.getName() + " @ " + fn.getEntryPoint() + " ====");
				DecompileResults res = dec.decompileFunction(fn, timeout, monitor);
				DecompiledFunction df = (res != null) ? res.getDecompiledFunction() : null;
				if (df != null && df.getC() != null) {
					w.println(df.getC());
				}
				else {
					w.println("// decompile failed: "
							+ (res != null ? res.getErrorMessage() : "null result"));
				}
				w.println();
			}
		}
		finally {
			dec.dispose();
		}
	}
}
