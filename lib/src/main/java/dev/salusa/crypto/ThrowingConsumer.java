package dev.salusa.crypto;

@FunctionalInterface 
interface ThrowingConsumer<T, E extends Exception> {
    void accept(T value) throws E;
}
