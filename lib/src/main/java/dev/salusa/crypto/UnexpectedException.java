package dev.salusa.crypto;

/**
 * Is similar to an {@link AssertionError} in that {@code UnexpectedException} should never occur.
 * This is generally used to wrap an exception declared by a dependency which should not be possible in practice.
 */
public class UnexpectedException extends RuntimeException {

    public UnexpectedException() {
    }

    public UnexpectedException(String message) {
        super(message);
    }

    public UnexpectedException(Throwable cause) {
        super(cause);
    }

    public UnexpectedException(String message, Throwable cause) {
        super(message, cause);
    }

    public UnexpectedException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
    
}
