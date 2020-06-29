package ghidraal;

import java.io.*;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import org.graalvm.polyglot.Value;

public class Util {
	public static Iterable<Value> asIterable(Value arr) {
		if (arr.hasArrayElements()) {
			return () -> {
				return new Iterator<Value>() {
					int i = 0;

					@Override
					public Value next() {
						return arr.getArrayElement(i++);
					}

					@Override
					public boolean hasNext() {
						return i < arr.getArraySize();
					}
				};
			};
		}
		return null;
	}

	public static Stream<Value> asStream(Value arr) {
		if (!arr.hasArrayElements()) {
			return null;
		}
		return StreamSupport.stream(
			new Spliterators.AbstractSpliterator<Value>(Long.MAX_VALUE, Spliterator.ORDERED) {
				int i = 0;

				public boolean tryAdvance(Consumer<? super Value> action) {
					if (i < arr.getArraySize()) {
						action.accept(arr.getArrayElement(i++));
						return true;
					}
					return false;
				}

				public void forEachRemaining(Consumer<? super Value> action) {
					while (i < arr.getArraySize())
						action.accept(arr.getArrayElement(i++));
				}
			}, false);
	}

	static public OutputStream asOutputStream(final Writer w) {
		return new OutputStream() {
			@Override
			public void write(int b) throws IOException {
				w.write(b);
			}
		};
	}

	static public InputStream wrap(String pre, InputStream stream, String post) {
		Vector<InputStream> v = new Vector<>(2);
		v.addElement(new ByteArrayInputStream(pre.getBytes()));
		v.addElement(stream);
		v.addElement(new ByteArrayInputStream(post.getBytes()));
		return new SequenceInputStream(v.elements());
	}
}
