package ghidraal;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;
import java.util.stream.Collectors;

import org.graalvm.polyglot.Engine;
import org.graalvm.polyglot.Language;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidraal.langs.*;

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
	static boolean TRIED_TO_MODIFY_PROVIDERS = false;
	static GhidraScriptProvider REMOVED_JYTHON_PROVIDER = null;

	// @formatter:off
	static List<LangInfo> langInfos = Arrays.asList(
		new Python3LangInfo(),
		new JavascriptLangInfo(),
		new RscriptLangInfo(),
		new RubyLangInfo()
	);
	// @formatter:on

	public GhidraalPlugin(PluginTool tool) {
		super(tool, true, true);
	}

	@Override
	public void init() {
		super.init();

		if (!TRIED_TO_MODIFY_PROVIDERS) {
			injectGhidraalProviders();
		}
		addConsoles();
	}

	/** once per Ghidra instance */
	static void injectGhidraalProviders() {
		TRIED_TO_MODIFY_PROVIDERS = true;

		PrintWriter out = new PrintWriter(System.err);
		Map<String, Language> allLangs = Engine.newBuilder().build().getLanguages();

		// remove Provider registered for .py handling
		Iterator<GhidraScriptProvider> providerIterator =
			GhidraScriptUtil.getProviders().iterator();
		while (providerIterator.hasNext()) {
			GhidraScriptProvider provider = providerIterator.next();
			if (provider.getExtension().equals(".py")) {
				out.printf("removing jython script provider\n");
				REMOVED_JYTHON_PROVIDER = provider;
				providerIterator.remove();
				out.printf("removed jython .py script provider, %s\n", provider);
			}
		}

		out.printf("adding ghidraal script providers\n");

		GhidraScriptUtil.getProviders()
				.addAll(langInfos.stream()
						.filter(li -> allLangs.containsKey(li.langId))
						.map(GhidraalScriptProviderBase::new)
						.collect(Collectors.toUnmodifiableList()));

		out.printf("all providers:\n");
		for (GhidraScriptProvider p : GhidraScriptUtil.getProviders()) {
			out.printf("  %s %s\n", p.getExtension(), p.getDescription());
		}
	}

	void addConsoles() {
		for (LangInfo langInfo : langInfos) {
			DockingAction action = new DockingAction(
				"create_ghidraal_" + langInfo.langId + "_console", this.getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					new GhidraalConsole(langInfo) {
						protected void initializeGraalContext() throws IOException {
							super.initializeGraalContext();
							ctx.putGlobal("tool", tool);
							ctx.putGlobal("currentProgram", currentProgram);
							ctx.putGlobal("currentLocation", currentLocation);
							ctx.putGlobal("currentSelection", currentSelection);
							ctx.putGlobal("currentHighlight", currentHighlight);
							ctx.putGlobal(LangInfo.API_VARNAME, new FlatProgramAPI(currentProgram));

							ctx.evalResource("_ghidraal_initscript");
						}

						protected void welcome(PrintWriter out) {
							super.welcome(out);
							out.println("  globals defined: tool, currentProgram, currentLocation");
							out.println(
								"    and the methods of _ghidra_api, a FlatProgramAPI object for currentProgram");

						}
					}.create(tool);
				}
			};
			action.setMenuBarData(new MenuData(
				new String[] { "&Window", "New ghidraal Console for " + langInfo.langId }));
			action.setDescription("Create and show a new ghidraal console for " + langInfo.langId);
			tool.addAction(action);
		}
	}

	@Override
	protected void dispose() {
		if (TRIED_TO_MODIFY_PROVIDERS) {
			List<GhidraScriptProvider> providers = GhidraScriptUtil.getProviders();
			if (REMOVED_JYTHON_PROVIDER != null) {
				providers.add(REMOVED_JYTHON_PROVIDER);
				REMOVED_JYTHON_PROVIDER = null;
			}
			Iterator<GhidraScriptProvider> it = GhidraScriptUtil.getProviders().iterator();
			while (it.hasNext()) {
				GhidraScriptProvider p = it.next();
				if (p instanceof GhidraalScriptProviderBase) {
					it.remove();
				}
			}
			TRIED_TO_MODIFY_PROVIDERS = false;
		}
	}
}
