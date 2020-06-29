package ghidraal;

import java.io.*;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;

// class name mustn't end with provider, or ClassSearcher will find it
public class GhidraalScriptProviderBase extends GhidraScriptProvider {
	final LangInfo langInfo;

	public GhidraalScriptProviderBase(LangInfo langInfo) {
		this.langInfo = langInfo;
	}

	@Override
	public String getDescription() {
		return "graal" + langInfo.langId;
	}

	@Override
	public void createNewScript(ResourceFile newScript, String category) throws IOException {
		PrintWriter writer = new PrintWriter(new FileWriter(newScript.getFile(false)));
		writeHeader(writer, category);
		writer.println("");
		writeBody(writer);
		writer.println("");
		writer.close();
	}

	@Override
	public String getCommentCharacter() {
		return langInfo.comment;
	}

	@Override
	public String getExtension() {
		return langInfo.extension;
	}

	@Override
	public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws ClassNotFoundException, InstantiationException, IllegalAccessException {
		GhidraalScript scr = langInfo.newScript();
		scr.setSourceFile(sourceFile);
		return scr;
	}

}
