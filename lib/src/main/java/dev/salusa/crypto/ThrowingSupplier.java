package dev.salusa.crypto;

@FunctionalInterface 
public interface ThrowingSupplier<T, E extends Exception>  {
    public T get() throws E;
}
