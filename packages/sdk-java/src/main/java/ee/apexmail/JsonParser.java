package ee.apexmail;

import java.util.*;

/**
 * Minimal recursive-descent JSON parser.
 *
 * Supports all JSON value types. Returned Java types:
 *   JSON object  → {@code Map<String, Object>}
 *   JSON array   → {@code List<Object>}
 *   JSON string  → {@code String}
 *   JSON number  → {@code Long} (integer) or {@code Double} (floating-point)
 *   JSON boolean → {@code Boolean}
 *   JSON null    → {@code null}
 */
final class JsonParser {

    private static final int MAX_DEPTH = 100;

    private final String src;
    private int pos;
    private int depth;

    JsonParser(String src) {
        this.src = src;
        this.pos = 0;
        this.depth = 0;
    }

    Object parse() {
        skipWhitespace();
        if (pos >= src.length()) throw new ApexMailException("Empty JSON");
        return parseValue();
    }

    private Object parseValue() {
        skipWhitespace();
        if (pos >= src.length()) throw new ApexMailException("Unexpected end of input");
        char c = src.charAt(pos);
        return switch (c) {
            case '{' -> parseObject();
            case '[' -> parseArray();
            case '"' -> parseString();
            case 't', 'f' -> parseBoolean();
            case 'n' -> parseNull();
            default -> parseNumber();
        };
    }

    private Map<String, Object> parseObject() {
        enterDepth();
        try {
            expect('{');
            Map<String, Object> map = new LinkedHashMap<>();
            skipWhitespace();
            if (peek() == '}') { pos++; return map; }
            while (true) {
                String key = parseString();
                skipWhitespace();
                expect(':');
                Object value = parseValue();
                map.put(key, value);
                skipWhitespace();
                if (peek() == '}') { pos++; break; }
                expect(',');
            }
            return map;
        } finally {
            exitDepth();
        }
    }

    private List<Object> parseArray() {
        enterDepth();
        try {
            expect('[');
            List<Object> list = new ArrayList<>();
            skipWhitespace();
            if (peek() == ']') { pos++; return list; }
            while (true) {
                list.add(parseValue());
                skipWhitespace();
                if (peek() == ']') { pos++; break; }
                expect(',');
            }
            return list;
        } finally {
            exitDepth();
        }
    }

    private void enterDepth() {
        depth++;
        if (depth > MAX_DEPTH) {
            throw new ApexMailException("Maximum JSON depth exceeded");
        }
    }

    private void exitDepth() {
        depth--;
    }

    private String parseString() {
        skipWhitespace();
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (pos < src.length()) {
            char c = src.charAt(pos++);
            if (c == '"') return sb.toString();
            if (c == '\\') {
                char esc = src.charAt(pos++);
                sb.append(switch (esc) {
                    case '"', '\\', '/' -> esc;
                    case 'b' -> '\b';
                    case 'f' -> '\f';
                    case 'n' -> '\n';
                    case 'r' -> '\r';
                    case 't' -> '\t';
                    case 'u' -> {
                        if (pos + 4 > src.length()) {
                            throw new ApexMailException("Invalid unicode escape at pos " + pos);
                        }
                        String hex = src.substring(pos, pos + 4);
                        pos += 4;
                        yield (char) Integer.parseInt(hex, 16);
                    }
                    default -> esc;
                });
            } else {
                sb.append(c);
            }
        }
        throw new ApexMailException("Unterminated string");
    }

    private Number parseNumber() {
        int start = pos;
        if (pos < src.length() && src.charAt(pos) == '-') pos++;

        int intStart = pos;
        while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
        if (intStart == pos) {
            throw new ApexMailException("Invalid number at pos " + start);
        }

        boolean isFloat = false;
        if (pos < src.length() && src.charAt(pos) == '.') {
            isFloat = true;
            pos++;
            int fracStart = pos;
            while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
            if (fracStart == pos) {
                throw new ApexMailException("Invalid number at pos " + start);
            }
        }

        if (pos < src.length() && (src.charAt(pos) == 'e' || src.charAt(pos) == 'E')) {
            isFloat = true;
            pos++;
            if (pos < src.length() && (src.charAt(pos) == '+' || src.charAt(pos) == '-')) pos++;
            int expStart = pos;
            while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
            if (expStart == pos) {
                throw new ApexMailException("Invalid number at pos " + start);
            }
        }

        if (pos < src.length()) {
            char next = src.charAt(pos);
            if (!(Character.isWhitespace(next) || next == ',' || next == ']' || next == '}')) {
                throw new ApexMailException("Invalid number at pos " + start);
            }
        }

        String raw = src.substring(start, pos);
        return isFloat ? Double.parseDouble(raw) : Long.parseLong(raw);
    }

    private Boolean parseBoolean() {
        if (src.startsWith("true", pos))  { pos += 4; return Boolean.TRUE; }
        if (src.startsWith("false", pos)) { pos += 5; return Boolean.FALSE; }
        throw new ApexMailException("Expected boolean at pos " + pos);
    }

    private Object parseNull() {
        if (src.startsWith("null", pos)) { pos += 4; return null; }
        throw new ApexMailException("Expected null at pos " + pos);
    }

    private char peek() {
        skipWhitespace();
        return pos < src.length() ? src.charAt(pos) : '\0';
    }

    private void expect(char c) {
        skipWhitespace();
        if (pos >= src.length() || src.charAt(pos) != c)
            throw new ApexMailException("Expected '" + c + "' at pos " + pos);
        pos++;
    }

    private void skipWhitespace() {
        while (pos < src.length() && Character.isWhitespace(src.charAt(pos))) pos++;
    }
}
