package ghidraal;

import ghidra.framework.ModuleInitializer;
import ghidra.util.SystemUtilities;

public class GhidraalInitializer implements ModuleInitializer {

	@Override
	public void run() {
		if (SystemUtilities.isInHeadlessMode()) {
			GhidraalPlugin.injectGhidraalProviders();
		}
	}

	@Override
	public String getName() {
		return "Ghidraal Extension Module";
	}

}
