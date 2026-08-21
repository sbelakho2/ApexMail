package ee.apexmail;

/**
 * Base exception for all ApexMail SDK errors.
 */
public class ApexMailException extends RuntimeException {

    private final String code;
    private final int statusCode;
    private final Object details;

    public ApexMailException(String message) {
        this(message, null, 0);
    }

    public ApexMailException(String message, Throwable cause) {
        super(message, cause);
        this.code       = null;
        this.statusCode = 0;
        this.details    = null;
    }

    public ApexMailException(String message, String code, int statusCode) {
        this(message, code, statusCode, null);
    }

    public ApexMailException(String message, String code, int statusCode, Object details) {
        super(message);
        this.code       = code;
        this.statusCode = statusCode;
        this.details    = details;
    }

    public ApexMailException(String message, String code, int statusCode, Object details, Throwable cause) {
        super(message, cause);
        this.code       = code;
        this.statusCode = statusCode;
        this.details    = details;
    }

    /** Machine-readable error code returned by the API (may be null). */
    public String getCode() { return code; }

    /** HTTP status code (0 for network-level errors). */
    public int getStatusCode() { return statusCode; }

    /** API error details object, often validation field errors (may be null). */
    public Object getDetails() { return details; }

    @Override
    public String toString() {
        return getClass().getSimpleName() +
            "[status=" + statusCode + ", code=" + code + ", details=" + details + "]: " + getMessage();
    }
}

// ── Typed sub-classes ─────────────────────────────────────────────────────
