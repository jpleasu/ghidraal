package ghidraal;

import java.util.HashMap;
import java.util.Map;

abstract public class LangInfo {

	static public final String API_VARNAME = "_ghidra_api";

	final String extension;
	final String langId;
	final String comment;
	final Map<String, String> options;

	protected LangInfo(String extension, String langId, String comment, String... options) {
		this.extension = extension;
		this.langId = langId;
		this.comment = comment;
		this.options = new HashMap<String, String>();
		for (int i = 0; i < options.length - 1; i += 2) {
			this.options.put(options[i], options[i + 1]);
		}
	}

	protected GhidraalScript newScript() {
		return new GhidraalScript(this);
	}

	protected ScriptingContext newScriptingContext() {
		return new ScriptingContext(this);
	}

}