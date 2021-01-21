package ghidraal;

import java.io.*;
import java.util.Collections;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.graalvm.polyglot.*;
import org.graalvm.polyglot.Context.Builder;

import resources.ResourceManager;

/**
 * wrapper of GraalVM context with higher level abstractions for scripting.
 */
public class ScriptingContext implements AutoCloseable {
	protected Context ctx;

	protected Value polyglotBindings;
	protected Value globalBindings;

	final protected LangInfo langInfo;

	public ScriptingContext(LangInfo langInfo) {
		this.langInfo = langInfo;
	}

	public Value eval(String string) {
		return ctx.eval(langInfo.langId, string);
	}

	public Value evalInputStream(String name, InputStream inputStream) throws IOException {
		try (InputStreamReader reader = new InputStreamReader(inputStream)) {
			Source init_source =
				Source.newBuilder(langInfo.langId, reader, name).cached(false).build();
			return ctx.eval(init_source);
		}
	}

	protected void evalResource(String resource) throws IOException {
		resource = resource + langInfo.extension;
		evalInputStream(resource, ResourceManager.getResourceAsStream(resource));
	}

	protected void evalWithReporting(String scriptName, InputStream scriptContents)
			throws IOException {
		evalInputStream(scriptName, scriptContents);
	}

	protected void putGlobal(String identifier, Object value) {
		globalBindings.putMember(identifier, value);
	}

	public Value getGlobalObject() {
		return globalBindings;
	}

	/**
	 * initialize fields assuming ctx is defined
	 */
	protected void initFields() {
		polyglotBindings = ctx.getPolyglotBindings();
		globalBindings = ctx.getBindings(langInfo.langId);
	}

	protected void buildAndInit(Builder builder) throws IOException {
		ctx = builder.build();
		evalResource("_ghidraal_initctx");
		initFields();
	}

	public void init(InputStream stdin, OutputStream stdOut, OutputStream stdErr)
			throws IOException {
		Builder builder = Context.newBuilder(langInfo.langId)
				// .engine(shared_engine) // caused native code issues with both python and fastr
				.allowAllAccess(true)
				.out(stdOut)
				.err(stdErr)
				.options(langInfo.options);

		if (stdin != null) {
			builder.in(stdin);
		}

		buildAndInit(builder);
	}

	/** using introspection (e.g. not Value.getMemberKeys) return members of {@code varName}. 
	 * 
	 * @param varName e.g. "a.b.c"
	 * @return a set of member names
	 */
	public Set<String> getMembersFromIntrospection(String varName) {
		return Collections.emptySet();
	}

	public static class CompletionData {
		final String varName;
		final String accessor;
		final String memberPrefix;

		public CompletionData(String varName, String accessor, String memberPrefix) {
			this.varName = varName;
			this.accessor = accessor;
			this.memberPrefix = memberPrefix;

		}
	}

	private Pattern completionPattern =
		Pattern.compile(".*?(?:([a-zA-Z0-9._$]*)(\\.))?([a-zA-Z0-9_$]*)$");

	/** For completions - find the longest variable name and method/field prefix in {@code cmd}.
	 * 
	 * <p>E.g. in Python if cmd is
	 * <pre>
	 *    blah blah foo.bar
	 * </pre>
	 * return ("foo", ".", "bar").
	 * <br>
	 * 
	 * <p>If the member prefix appears to be global, the varName and accessor are null, e.g. in Python
	 * <pre>
	 *   blah bar
	 * </pre>
	 * return (null, null, "bar")
	 * 
	 * @param cmd a (partial) command
	 * @return a CompletionData object with varName, accessor, and memberPrefix or null if no match was found
	 */
	protected CompletionData matchCompletionPattern(String cmd) {
		Matcher matcher = completionPattern.matcher(cmd);
		if (matcher.matches()) {
			return new CompletionData(matcher.group(1), matcher.group(2), matcher.group(3));
		}
		return null;
	}

	@Override
	public void close() {
		ctx.close(true);
	}

}
