package ghidraal;

import java.awt.event.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.*;

import org.graalvm.polyglot.PolyglotException;
import org.graalvm.polyglot.Value;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidraal.ScriptingContext.CompletionData;
import resources.Icons;

public class GhidraalConsole {
	String prompt = ">>>";
	String morePrompt = "...";

	final LangInfo langInfo;

	protected ScriptingContext ctx;

	protected InterpreterConsole console;

	protected MyInterpreterConnection interpreter;

	protected MyInputThread inputThread;

	public GhidraalConsole(LangInfo langInfo) {
		this.langInfo = langInfo;
	}

	protected void initializeGraalContext() throws IOException {
		if (ctx != null) {
			closeGraalContext();
		}
		ctx = langInfo.newScriptingContext();
		ctx.init(console.getStdin(), console.getStdOut(), console.getStdErr());
	}

	protected void closeGraalContext() {
		ctx.close();
		ctx = null;
	}

	protected void welcome(PrintWriter out) {
		out.println("GraalVM Console - " + langInfo.langId);
		out.println("  press TAB for member lookup");
		out.println("  press SHIFT-ENTER to continue input on next line");
	}

	// must be run in swing thread
	protected void initializeConsole(ServiceProvider serviceProvider) {
		console = serviceProvider.getService(InterpreterPanelService.class)
				.createInterpreterPanel(interpreter, true);

		PrintWriter out = console.getOutWriter();
		welcome(out);
		console.addFirstActivationCallback(this::onFirstConsoleActivation);

		InterpreterComponentProvider provider = (InterpreterComponentProvider) console;

		DockingAction disposeAction = new DockingAction("Remove Interpreter", provider.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				console.dispose();
				inputThread.dispose();
				inputThread = null;
				closeGraalContext();
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

					// remove the shift modifier so that the text pane treats this event
					// like an enter
					e.setModifiers(0);
				}
			}
		});
	}

	void onFirstConsoleActivation() {
		if (inputThread != null) {
			inputThread.dispose();
			inputThread = null;
		}
		try {
			initializeGraalContext();
			inputThread = new MyInputThread();
			inputThread.start();
		}
		catch (IOException e) {
			Msg.showError(this, null, "Error initializing GraalVM context", e);
		}
	}

	public void create(ServiceProvider serviceProvider) {
		interpreter = new MyInterpreterConnection();

		Swing.runNow(() -> {
			initializeConsole(serviceProvider);
		});
	}

	class MyInterpreterConnection implements InterpreterConnection {

		@Override
		public String getTitle() {
			return "Ghidraal console for " + langInfo.langId;
		}

		@Override
		public ImageIcon getIcon() {
			return Icons.EMPTY_ICON;
		}

		@Override
		public List<CodeCompletion> getCompletions(String cmd) {
			Value object = null;
			String varNameWithAccessor = "";
			String memberPrefix = "";
			String varName = null;

			CompletionData completionData = ctx.matchCompletionPattern(cmd);
			if (completionData != null) {
				varName = completionData.varName;
				memberPrefix = completionData.memberPrefix;
				if (varName != null) {
					try {
						object = ctx.eval(varName);
						if (object != null) {
							varNameWithAccessor = varName + completionData.accessor;
						}
					}
					catch (PolyglotException e) {
						// oh well
					}
				}
			}

			// completionData wasn't found, or we don't trust it since no variable was found
			if (object == null) {
				varName = null;
				object = ctx.getGlobalObject();
			}

			// members are sorted by length, then lexicographically
			Set<String> members = new TreeSet<>((a, b) -> {
				int c = Integer.compare(a.length(), b.length());
				if (c == 0)
					c = a.compareTo(b);
				return c;
			});

			members.addAll(object.getMemberKeys());
			if (varName != null) {
				members.addAll(ctx.getMembersFromIntrospection(varName));
			}

			// now filter with our prefix and construct CodeCompletion objects
			List<CodeCompletion> completions = new ArrayList<>();
			for (String member : members) {
				if (member.startsWith(memberPrefix)) {
					completions.add(new CodeCompletion(varNameWithAccessor + member,
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
						Value result = ctx.eval(sb.toString());
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
