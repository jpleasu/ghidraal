package ghidraal.langs;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.graalvm.polyglot.PolyglotException;
import org.graalvm.polyglot.Value;

import ghidraal.*;

public class RscriptLangInfo extends LangInfo {

	public RscriptLangInfo() {
		super(".r", "R", "#");
	}

	@Override
	protected ScriptingContext newScriptingContext() {
		return new RscriptScriptingContext();
	}

	class RscriptScriptingContext extends ScriptingContext {
		public RscriptScriptingContext() {
			super(RscriptLangInfo.this);
		}

		@Override
		protected void evalWithReporting(String n, InputStream s) throws IOException {
			// @formatter:off
			super.evalWithReporting(n,
				Util.wrap("tryCatch(" +
					"(function(){", s,"})()," +
					"warning=function(w) {"+
						API_VARNAME+"$printf('warning: %s\\n', w);" +
						"traceback()" +
					"}, " +
					"error=function(e) {"+
						API_VARNAME+"$printf('error: %s\\n', e);" +
						"traceback()" +
					"}" +
				");"));
			// @formatter:on
		}

		private Pattern completionPattern =
			Pattern.compile(".*?(?:([a-zA-Z0-9._@$]*)([@$.]))?([a-zA-Z0-9_]*)$");

		protected CompletionData matchCompletionPattern(String cmd) {
			Matcher matcher = completionPattern.matcher(cmd);
			if (matcher.matches()) {
				return new CompletionData(matcher.group(1), matcher.group(2), matcher.group(3));
			}
			return null;
		}

		@Override
		public Set<String> getMembersFromIntrospection(String varName) {
			try {
				Stream<Value> stream = Util.asStream(eval("names(" + varName + ")"));
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
