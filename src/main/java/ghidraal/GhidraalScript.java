package ghidraal;

import java.io.InputStream;
import java.io.OutputStream;

import org.graalvm.polyglot.PolyglotException;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;
import ghidra.util.Swing;
import ghidra.util.SystemUtilities;

public class GhidraalScript extends GhidraScript {
	final LangInfo langInfo;

	protected String storedContextName;
	protected ScriptingContext ctx;

	public GhidraalScript(LangInfo langInfo) {
		this.langInfo = langInfo;
		storedContextName = "ghidraaal_" + langInfo.extension + "_stored_context";
	}

	@Override
	protected void run() throws Exception {
		ctx = (ScriptingContext) state.getEnvironmentVar(storedContextName);
		if (SystemUtilities.isInHeadlessMode()) {
			doRun(System.in, System.out, System.err);
		}
		else {
			Swing.runNow(() -> {
				ConsoleService consoleservice = state.getTool().getService(ConsoleService.class);
				try {
					doRun(null, Util.asOutputStream(consoleservice.getStdOut()),
						Util.asOutputStream(consoleservice.getStdErr()));
				}
				catch (PolyglotException e) {
					e.printStackTrace(consoleservice.getStdErr());
				}
				catch (Exception e) {
					e.printStackTrace();
				}
			});
		}
	}

	protected void doRun(InputStream in, OutputStream out, OutputStream err) throws Exception {
		if (ctx == null) {
			ctx = langInfo.newScriptingContext();
			ctx.init(in, out, err);
		}
		ctx.putGlobal(LangInfo.API_VARNAME, this);
		ctx.putGlobal("tool", state.getTool());
		ctx.putGlobal("currentProgram", currentProgram);
		ctx.putGlobal("currentAddress", currentAddress);
		ctx.putGlobal("currentLocation", currentLocation);
		ctx.putGlobal("currentHighlight", currentHighlight);
		ctx.putGlobal("monitor", monitor);

		ctx.evalResource("_ghidraal_initscript");

		ResourceFile f = getSourceFile();
		ctx.evalWithReporting(f.getName(), f.getInputStream());
	}
}
