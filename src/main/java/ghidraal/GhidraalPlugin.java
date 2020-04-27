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
package ghidraal;

import java.io.PrintWriter;
import java.util.Iterator;

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
	description = "Ghidraal is an extension that exposes GraalVM scripting languages to the Ghidra API"
)
//@formatter:on
public class GhidraalPlugin extends ProgramPlugin {

	public GhidraalPlugin(PluginTool tool) {
		super(tool, true, true);
	}

	@Override
	public void init() {
		super.init();
		ConsoleService consoleService = tool.getService(ConsoleService.class);
		// remove other Providers registered for .py handling
		Iterator<GhidraScriptProvider> it = GhidraScriptUtil.getProviders().iterator();
		while (it.hasNext()) {
			GhidraScriptProvider p = it.next();
			if (p.getExtension().equals(".py")) {
				if (!(p instanceof Python3ScriptProvider)) {
					it.remove();
					if (consoleService != null) {
						PrintWriter stdout = consoleService.getStdOut();
						if (stdout != null) {
							stdout.printf("Removed old .py provider, %s\n", p);
						}
					}
				}
			}
		}
		// GhidraScriptUtil.getProviders().add(new Python3ScriptProvider());
	}
}
