package ghidraal;

import java.io.InputStreamReader;

import org.graalvm.polyglot.*;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;
import ghidra.util.Swing;
import resources.ResourceManager;

public class GraalPythonScript extends GhidraScript {
	static final String PYTHON_CONTEXT = "ghidraal.python.context";

	@Override
	protected void run() throws Exception {
		Swing.runNow(() -> {
			try {
				bun();
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		});
	}

	protected void bun() throws Exception {
		ConsoleService consoleservice = state.getTool().getService(ConsoleService.class);
		Context ctx = (Context) state.getEnvironmentVar(PYTHON_CONTEXT);
		Value pb;
		if (ctx == null) {
			ctx = Context.newBuilder("python").allowAllAccess(true).build();
			state.addEnvironmentVar(PYTHON_CONTEXT, ctx);
			pb = ctx.getBindings("python");
			pb.putMember("_gsout", consoleservice.getStdOut());
			pb.putMember("_gserr", consoleservice.getStdErr());

			try (InputStreamReader reader = new InputStreamReader(
				ResourceManager.getResourceAsStream("python/_ghidraal_initctx.py"))) {
				Source init_source =
					Source.newBuilder("python", reader, "_ghidraal_initctx.py").build();
				ctx.eval(init_source);
			}
		}
		else {
			pb = ctx.getBindings("python");
		}

		pb.putMember("gs", this);

		try (InputStreamReader reader = new InputStreamReader(
			ResourceManager.getResourceAsStream("python/_ghidraal_initscript.py"))) {
			Source init_source =
				Source.newBuilder("python", reader, "_ghidraal_initscript.py").build();
			ctx.eval(init_source);
		}

		pb.putMember("currentProgram", currentProgram);
		pb.putMember("currentAddress", currentAddress);
		pb.putMember("currentLocation", currentLocation);
		pb.putMember("currentHighlight", currentHighlight);
		pb.putMember("currentSelection", currentSelection);

		ResourceFile f = getSourceFile();
		try (InputStreamReader reader = new InputStreamReader(f.getInputStream())) {
			Source source = Source.newBuilder("python", reader, f.getName()).build();
			Value v1 = ctx.eval(source);
			if (v1.canExecute()) {
				Value v2 = v1.execute();
				printf("Executed to %s\n", v2);
			}
		}
	}
}
