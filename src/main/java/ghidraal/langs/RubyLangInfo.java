package ghidraal.langs;

import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Value;

import ghidraal.LangInfo;
import ghidraal.ScriptingContext;

public class RubyLangInfo extends LangInfo {

	public RubyLangInfo() {
		super(".rb", "ruby", "#");
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

	@Override
	protected ScriptingContext newScriptingContext() {
		return new RubyScriptingContext();
	}

	class RubyScriptingContext extends ScriptingContext {
		public RubyScriptingContext() {
			super(RubyLangInfo.this);
		}

		@Override
		protected void putGlobal(String identifier, Object value) {
			polyglotBindings.putMember(identifier, value);
			ctx.eval("ruby", "$" + identifier + "=Polyglot.import('" + identifier + "')\n");
		}

	}

}
