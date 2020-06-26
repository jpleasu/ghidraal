package ghidraal;

import java.awt.event.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.*;

import org.graalvm.polyglot.*;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.Msg;
import ghidra.util.Swing;
import resources.Icons;

public class GhidraalConsole {
	String langId = "python";
	String prompt = ">>>";
	String morePrompt = "...";

	// when tab is hit, this pattern has two capture groups, e.g. 
	//   (x.x.x).(y)
	// if this pattern matches when tab is pressed, we lookup the first group
	// and return its members filtered by the second group.
	Pattern completionPattern = Pattern.compile(".*?(?:([a-zA-Z0-9._$]*)\\.)?([a-zA-Z0-9_$]*)$");

	// override to get members from within the language
	protected Set<String> getMembers(String varName) {
		Set<String> members = new HashSet<>();
		try {
			Value dirOutput = ctx.eval(langId, "dir(" + varName + ")");
			if (dirOutput.hasArrayElements()) {
				for (int i = 0; i < dirOutput.getArraySize(); ++i) {
					members.add(dirOutput.getArrayElement(i).asString());
				}
			}
		}
		catch (PolyglotException e) {
			// oh well
		}
		return members;
	}

	protected void initializeGraalContext() {
		ctx = Context.newBuilder(langId)
				.allowAllAccess(true)
				.out(console.getStdOut())
				.in(console.getStdin())
				.err(console.getStdErr())
				.build();
	}

	protected Context ctx;

	protected InterpreterConsole console;
	protected MyInterpreterConnection interpreter;
	protected MyInputThread inputThread;

	public void initializeConsole() {
		PrintWriter out = console.getOutWriter();
		out.println("GraalVM Console - " + langId);
		out.println("  press TAB for member lookup");
		out.println("  press SHIFT-ENTER to continue input on next line");
		console.addFirstActivationCallback(this::onFirstActivation);

		Swing.runNow(() -> {
			InterpreterComponentProvider provider = (InterpreterComponentProvider) console;

			DockingAction disposeAction =
				new DockingAction("Remove Interpreter", provider.getName()) {
					@Override
					public void actionPerformed(ActionContext context) {
						console.dispose();
						inputThread.dispose();
						inputThread = null;
					}
				};
			disposeAction.setDescription("Remove interpreter from tool");
			disposeAction.setToolBarData(new ToolBarData(Icons.STOP_ICON, null));
			disposeAction.setEnabled(true);
			console.addAction(disposeAction);

			// add a key listener for shift-enter
			InterpreterPanel panel = (InterpreterPanel) provider.getComponent();
			JPanel interiorPanel = (JPanel) panel.getComponent(1);
			JTextPane inputTextPane = (JTextPane) interiorPanel.getComponent(1);
			inputTextPane.addKeyListener(new KeyAdapter() {
				@SuppressWarnings("deprecation")
				@Override
				public void keyPressed(KeyEvent e) {
					if (e.getKeyCode() == KeyEvent.VK_ENTER &&
						e.getModifiersEx() == InputEvent.SHIFT_DOWN_MASK) {

						inputThread.wantsMore.set(true);

						// remove the shift modifier so that the text pane treats this even
						// like an enter
						e.setModifiers(0);
					}
				}
			});
		});
	}

	void onFirstActivation() {
		if (inputThread != null) {
			inputThread.dispose();
			inputThread = null;
		}
		inputThread = new MyInputThread();
		inputThread.start();
	}

	public void create(ServiceProvider serviceProvider) {
		interpreter = new MyInterpreterConnection();

		Swing.runNow(() -> {
			console = serviceProvider.getService(InterpreterPanelService.class)
					.createInterpreterPanel(interpreter, true);
		});
		initializeConsole();
		initializeGraalContext();
	}

	class MyInterpreterConnection implements InterpreterConnection {

		@Override
		public String getTitle() {
			return "GraalVM Console - " + langId;
		}

		@Override
		public ImageIcon getIcon() {
			return Icons.EMPTY_ICON;
		}

		@Override
		public List<CodeCompletion> getCompletions(String cmd) {
			Matcher m = completionPattern.matcher(cmd);
			Value value = null;
			String memberDisplayPrefix = "";
			String memberPrefix = "";
			String varName = null;
			if (m.matches()) {
				varName = m.group(1);
				memberPrefix = m.group(2);
				if (varName != null) {
					try {
						value = ctx.eval(langId, varName);
						if (value != null) {
							memberDisplayPrefix = varName + ".";
						}
					}
					catch (PolyglotException e) {
						// oh well
					}
				}
			}
			if (value == null) {
				value = ctx.getBindings(langId);
			}
			List<CodeCompletion> completions = new ArrayList<>();
			Set<String> members = new TreeSet<>((a, b) -> {
				int c = Integer.compare(a.length(), b.length());
				if (c == 0)
					c = a.compareTo(b);
				return c;
			});
			members.addAll(value.getMemberKeys());
			if (varName != null) {
				members.addAll(getMembers(varName));
			}

			for (String member : members) {
				if (member.startsWith(memberPrefix)) {
					completions.add(new CodeCompletion(memberDisplayPrefix + member,
						member.substring(memberPrefix.length()), null));
				}
			}
			return completions;
		}

	}

	class MyInputThread extends Thread {
		private AtomicBoolean shouldContinue;
		AtomicBoolean wantsMore;

		MyInputThread() {
			super("my input thread");
			this.shouldContinue = new AtomicBoolean(true);
			this.wantsMore = new AtomicBoolean(false);
		}

		@Override
		public void run() {
			InputStream stdin = console.getStdin();
			console.setPrompt(prompt);
			PrintWriter out = console.getOutWriter();
			try (BufferedReader reader = new BufferedReader(new InputStreamReader(stdin))) {
				StringBuffer sb = new StringBuffer();
				while (shouldContinue.get()) {
					String line;
					if (stdin.available() > 0) {
						line = reader.readLine();
					}
					else {
						try {
							Thread.sleep(50);
						}
						catch (InterruptedException e) {
							// Nothing to do...just continue.
						}
						continue;
					}
					if (wantsMore.get()) {
						sb.append(line);
						sb.append('\n');
						wantsMore.set(false);
						console.setPrompt(morePrompt);
						continue;
					}

					sb.append(line);

					try {
						Value result = ctx.eval(langId, sb.toString());
						out.printf("%s\n", result);
					}
					catch (PolyglotException e) {
						e.printStackTrace(console.getErrWriter());
					}
					sb.setLength(0);
					console.setPrompt(prompt);
				}
			}
			catch (IOException e) {
				Msg.error(MyInputThread.class,
					"Internal error reading commands from interpreter console.", e);
			}
		}

		void dispose() {
			shouldContinue.set(false);
		}
	}
}
