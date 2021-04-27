package ghidraal.langs;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.graalvm.polyglot.PolyglotException;
import org.graalvm.polyglot.Value;

import ghidraal.*;

public class NodeJSLangInfo extends LangInfo {

	static private String[] getOptions() {
		Path langDir = Path.of(System.getProperty("java.home") + "/languages");
		Path npmDir = langDir.resolve("nodejs/npm");
		if (!Files.isDirectory(npmDir)) {
			npmDir = langDir.resolve("js/npm");
			if (!Files.isDirectory(npmDir)) {
				npmDir = null;
			}
		}
		if (npmDir != null) {
			// @formatter:off
			return new String[] {
				"js.commonjs-require", "true",
				"js.commonjs-require-cwd", npmDir.toString()
			};
			// @formatter:on
		}
		return new String[] {};
	}

	public NodeJSLangInfo() {
		super(".js", "js", "//", getOptions());
	}

	@Override
	protected ScriptingContext newScriptingContext() {
		return new NodeJSScriptContext();
	}

	class NodeJSScriptContext extends ScriptingContext {
		public NodeJSScriptContext() {
			super(NodeJSLangInfo.this);
		}

		@Override
		public Set<String> getMembersFromIntrospection(String varName) {
			try {
				Stream<Value> stream = Util.asStream(eval(varName + ".keys()"));
				if (stream != null) {
					return stream.map(v -> v.asString()).collect(Collectors.toSet());
				}
			}
			catch (PolyglotException e) {
				//
			}
			return Collections.emptySet();
		}

	}
}
