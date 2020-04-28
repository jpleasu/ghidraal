package ghidraal;

import java.io.PrintWriter;
import java.util.*;
import java.util.stream.Collectors;

import org.graalvm.polyglot.Engine;
import org.graalvm.polyglot.Language;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * A simple shim to add script providers to GhidraScriptUtil before they're loaded by 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "Ghidraal",
	category = PluginCategoryNames.INTERPRETERS,
	shortDescription = "GraalVM scripting for Ghidra",
	description = "Ghidraal integrates GraalVM scripting languages into Ghidra's scripting manager"
)
//@formatter:on
public class GhidraalPlugin extends ProgramPlugin {

	static class LangInfo {
		final String ext;
		final String langid;
		final String comment;
		final Map<String, String> options;

		LangInfo(String ext, String langid, String comment, String... options) {
			this.ext = ext;
			this.langid = langid;
			this.comment = comment;
			this.options = new HashMap<String, String>();
			for (int i = 0; i < options.length - 1; i += 2) {
				this.options.put(options[i], options[i + 1]);
			}
		}

		GhidraalScript newScript() {
			return new GhidraalScript(this);
		}
	}

	// @formatter:off
	static List<GhidraalPlugin.LangInfo> linfos = Arrays.asList(
		new GhidraalPlugin.LangInfo(".py", "python", "#"),
		
		new GhidraalPlugin.LangInfo(".js", "js", "//",
			"js.commonjs-require", "true",
			"js.commonjs-require-cwd", System.getProperty("java.home")+"/languages/js/npm"
		),
		
		new GhidraalPlugin.LangInfo(".r", "R", "#"),
		
		new GhidraalPlugin.LangInfo(".rb", "ruby", "#") {
			@Override
			GhidraalScript newScript() {
				return new GhidraalScript(this) {
					@Override
					void putGlobal(String identifier, Object value) {
						pgb.putMember(identifier, value);
						ctx.eval("ruby", "$"+identifier+"=Polyglot.import('"+identifier+"')\n");
					}
				};
			}
		}
	);
	// @formatter:on
	public static Map<String, GhidraalPlugin.LangInfo> ext2li =
		linfos.stream().collect(Collectors.toUnmodifiableMap(li -> li.ext, li -> li));

	public GhidraalPlugin(PluginTool tool) {
		super(tool, true, true);
	}

	static boolean done = false;
	static GhidraScriptProvider removed_python_provider = null;

	@Override
	public void init() {
		super.init();
		System.err.printf("Ghidraal plugin init\n");
		ConsoleService consoleService = tool.getService(ConsoleService.class);
		if (!done) {
			done = true;
			Map<String, Language> allLangs = Engine.newBuilder().build().getLanguages();

			// remove Provider registered for .py handling
			Iterator<GhidraScriptProvider> it = GhidraScriptUtil.getProviders().iterator();
			while (it.hasNext()) {
				GhidraScriptProvider p = it.next();
				if (p.getExtension().equals(".py")) {
					System.err.printf("removing old python provider\n");
					removed_python_provider = p;
					it.remove();

					if (consoleService != null) {
						PrintWriter stdout = consoleService.getStdOut();
						if (stdout != null) {
							stdout.printf("Removed old .py provider, %s\n", p);
						}
					}
				}
			}
			System.err.printf("adding our providers\n");

			GhidraScriptUtil.getProviders().addAll(
				ext2li.values().stream().filter(li -> allLangs.containsKey(li.langid)).map(
					GhidraalScriptProviderBase::new).collect(Collectors.toUnmodifiableList()));

			for (GhidraScriptProvider p : GhidraScriptUtil.getProviders()) {
				System.err.printf("  %s %s\n", p.getExtension(), p.getDescription());
			}
		}
	}

	@Override
	protected void dispose() {
		if (done) {
			List<GhidraScriptProvider> providers = GhidraScriptUtil.getProviders();
			if (removed_python_provider != null) {
				providers.add(removed_python_provider);
				removed_python_provider = null;
			}
			Iterator<GhidraScriptProvider> it = GhidraScriptUtil.getProviders().iterator();
			while (it.hasNext()) {
				GhidraScriptProvider p = it.next();
				if (p instanceof GhidraalScriptProviderBase) {
					it.remove();
				}
			}
			done = false;
		}
	}
}
