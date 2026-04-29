package ee.apexmail;

import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ApexMailClientResponseLimitTest {
    @Test
    void ensureResponseWithinLimitCountsUtf8Bytes() throws Exception {
        Method method = ApexMailClient.class.getDeclaredMethod("ensureResponseWithinLimit", String.class);
        method.setAccessible(true);

        String responseBody = "€".repeat((20 * 1024 * 1024 / 3) + 1);

        InvocationTargetException error = assertThrows(
            InvocationTargetException.class,
            () -> method.invoke(null, responseBody)
        );

        ApexMailException cause = assertInstanceOf(ApexMailException.class, error.getCause());
        assertEquals("response_too_large", cause.getCode());
    }
}