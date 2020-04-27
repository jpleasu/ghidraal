package ghidraal;

import java.io.*;
import java.lang.reflect.InvocationTargetException;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;

public class Python3ScriptProvider extends GhidraScriptProvider {

	@Override
	public String getDescription() {
		return "graalpython";
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
		return "#";
	}

	@Override
	public String getExtension() {
		return ".py";
	}

	@Override
	public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws ClassNotFoundException, InstantiationException, IllegalAccessException {

		Class<?> clazz = Class.forName(GraalPythonScript.class.getName());
		GhidraScript script;
		try {
			script = (GhidraScript) clazz.getDeclaredConstructor().newInstance();
		}
		catch (InstantiationException | IllegalAccessException | IllegalArgumentException
				| InvocationTargetException | NoSuchMethodException | SecurityException e) {
			throw new InstantiationException(e.getMessage());
		}
		script.setSourceFile(sourceFile);
		return script;
	}

}
