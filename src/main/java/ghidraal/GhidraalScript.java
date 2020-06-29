package ghidraal;

import org.graalvm.polyglot.PolyglotException;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;
import ghidra.util.Swing;

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
		Swing.runNow(() -> {
			try {
				doRun();
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		});
	}

	protected void doRun() throws Exception {
		ConsoleService consoleservice = state.getTool().getService(ConsoleService.class);
		ctx = (ScriptingContext) state.getEnvironmentVar(storedContextName);

		try {
			if (ctx == null) {
				ctx = langInfo.newScriptingContext();
				ctx.init(consoleservice);
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
		catch (PolyglotException e) {
			e.printStackTrace(consoleservice.getStdErr());
		}
	}
}
