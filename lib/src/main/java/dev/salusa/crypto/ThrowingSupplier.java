package dev.salusa.crypto;

/**
 * Like {@link java.util.function.Supplier} but the method is allowed to throw
 * an exception or error.
 * 
 * @param <T> type returned
 * @param <E> exception or error thrown
 */
@FunctionalInterface
public interface ThrowingSupplier<T, E extends Throwable> {
    public T get() throws E;
}
