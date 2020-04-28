package ghidraal;

import java.io.*;

import org.graalvm.polyglot.*;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;
import ghidra.util.Swing;
import resources.ResourceManager;

public class GhidraalScript extends GhidraScript {
	protected String storedContextName;

	Context ctx;

	final GhidraalPlugin.LangInfo li;

	public GhidraalScript(GhidraalPlugin.LangInfo li) {
		this.li = li;
		storedContextName = "ghidraaal_" + li.ext + "_stored_context";
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

	protected void eval(String resource) throws IOException {
		resource = resource + li.ext;
		try (InputStreamReader reader =
			new InputStreamReader(ResourceManager.getResourceAsStream(resource))) {
			Source init_source = Source.newBuilder(li.langid, reader, resource).build();
			ctx.eval(init_source);
		}
	}

	protected OutputStream os(final Writer w) {
		return new OutputStream() {
			@Override
			public void write(int b) throws IOException {
				w.write(b);
			}
		};
	}

	void putGlobal(String identifier, Object value) {
		pb.putMember(identifier, value);
	}

	protected Value pgb;
	protected Value pb;

	protected void doRun() throws Exception {
		ConsoleService consoleservice = state.getTool().getService(ConsoleService.class);
		ctx = (Context) state.getEnvironmentVar(storedContextName);

		if (ctx == null) {
			// @formatter:off
			ctx = Context.newBuilder(li.langid)
					.allowAllAccess(true)
					.out(os(consoleservice.getStdOut()))
					.err(os(consoleservice.getStdErr()))
					.options(li.options)
					.build();
			// @formatter:on
			state.addEnvironmentVar(storedContextName, ctx);
			eval("_ghidraal_initctx");
		}
		pgb = ctx.getPolyglotBindings();
		pb = ctx.getBindings(li.langid);

		putGlobal("gs", this);
		putGlobal("tool", state.getTool());
		putGlobal("currentProgram", currentProgram);
		putGlobal("currentAddress", currentAddress);
		putGlobal("currentLocation", currentLocation);
		putGlobal("currentHighlight", currentHighlight);
		putGlobal("monitor", monitor);

		eval("_ghidraal_initscript");

		ResourceFile f = getSourceFile();
		try (InputStreamReader reader = new InputStreamReader(f.getInputStream())) {
			Source source = Source.newBuilder(li.langid, reader, f.getName()).build();
			ctx.eval(source);
		}
	}

	public static void main(String[] args) {
		Context ctx = Context.newBuilder("ruby").allowAllAccess(true).build();
		Value pb = ctx.getBindings("ruby");
		for (String k : pb.getMemberKeys()) {
			System.err.printf("%s\n", k);
		}

		Value pgb = ctx.getPolyglotBindings();
		pgb.putMember("v", 7);
		ctx.eval("ruby", "v=Polyglot.import('v')\n");
	}
}
