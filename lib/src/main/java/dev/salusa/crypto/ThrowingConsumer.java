package dev.salusa.crypto;

/**
 * Like {@link java.util.function.Consumer} but the method is allowed to throw
 * an exception or error.
 * 
 * @param <T> type consumed
 * @param <E> exception or error thrown
 */
@FunctionalInterface
public interface ThrowingConsumer<T, E extends Throwable> {
    void accept(T value) throws E;
}
