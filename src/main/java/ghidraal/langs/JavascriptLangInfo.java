package ghidraal.langs;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.graalvm.polyglot.PolyglotException;
import org.graalvm.polyglot.Value;

import ghidraal.*;

public class JavascriptLangInfo extends LangInfo {

	public JavascriptLangInfo() {
		// @formatter:off
		super(".js", "js", "//",
			"js.commonjs-require", "true",
			"js.commonjs-require-cwd", System.getProperty("java.home")+"/languages/js/npm"
		);
		// @formatter:on
	}

	@Override
	protected ScriptingContext newScriptingContext() {
		return new JavascriptScriptContext();
	}

	class JavascriptScriptContext extends ScriptingContext {
		public JavascriptScriptContext() {
			super(JavascriptLangInfo.this);
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
