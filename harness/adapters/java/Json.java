// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal, dependency-free JSON reader/writer for the N-AALP conformance adapter's wire protocol.
 *
 * <p>Parses into {@code Map<String,Object>} (objects), {@code List<Object>} (arrays), {@code String},
 * {@code Long}/{@code Double} (integers vs reals), {@code Boolean}, and {@code null}. Integer tokens
 * become {@code Long} so 64-bit counters survive without float rounding. The writer emits the same
 * value shapes plus {@code Integer}. This is a real recursive-descent parser (not a regex or a
 * string match): it validates structure and raises on malformed input.
 */
public final class Json {
    private Json() {}

    // --- parser ---

    public static Object parse(String s) {
        Parser p = new Parser(s);
        p.skipWs();
        Object v = p.value();
        p.skipWs();
        if (p.pos != p.src.length()) {
            throw new IllegalArgumentException("trailing content after JSON value");
        }
        return v;
    }

    private static final class Parser {
        final String src;
        int pos;
        Parser(String src) { this.src = src; }

        void skipWs() {
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        Object value() {
            skipWs();
            if (pos >= src.length()) {
                throw new IllegalArgumentException("unexpected end of JSON");
            }
            char c = src.charAt(pos);
            switch (c) {
                case '{': return object();
                case '[': return array();
                case '"': return string();
                case 't': case 'f': return bool();
                case 'n': return nullLit();
                default: return number();
            }
        }

        Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            pos++; // {
            skipWs();
            if (peek() == '}') { pos++; return m; }
            while (true) {
                skipWs();
                if (peek() != '"') {
                    throw new IllegalArgumentException("expected string key at " + pos);
                }
                String key = string();
                skipWs();
                if (peek() != ':') {
                    throw new IllegalArgumentException("expected ':' at " + pos);
                }
                pos++;
                Object v = value();
                m.put(key, v);
                skipWs();
                char c = peek();
                if (c == ',') { pos++; continue; }
                if (c == '}') { pos++; break; }
                throw new IllegalArgumentException("expected ',' or '}' at " + pos);
            }
            return m;
        }

        List<Object> array() {
            List<Object> a = new ArrayList<>();
            pos++; // [
            skipWs();
            if (peek() == ']') { pos++; return a; }
            while (true) {
                Object v = value();
                a.add(v);
                skipWs();
                char c = peek();
                if (c == ',') { pos++; continue; }
                if (c == ']') { pos++; break; }
                throw new IllegalArgumentException("expected ',' or ']' at " + pos);
            }
            return a;
        }

        String string() {
            StringBuilder sb = new StringBuilder();
            pos++; // opening quote
            while (true) {
                if (pos >= src.length()) {
                    throw new IllegalArgumentException("unterminated string");
                }
                char c = src.charAt(pos++);
                if (c == '"') {
                    break;
                }
                if (c == '\\') {
                    char e = src.charAt(pos++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            int cp = Integer.parseInt(src.substring(pos, pos + 4), 16);
                            pos += 4;
                            sb.append((char) cp);
                            break;
                        default:
                            throw new IllegalArgumentException("bad escape \\" + e);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        Object number() {
            int start = pos;
            if (peek() == '-') { pos++; }
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    pos++;
                } else {
                    break;
                }
            }
            String tok = src.substring(start, pos);
            if (tok.isEmpty()) {
                throw new IllegalArgumentException("invalid number at " + start);
            }
            if (tok.indexOf('.') < 0 && tok.indexOf('e') < 0 && tok.indexOf('E') < 0) {
                try {
                    return Long.parseLong(tok);
                } catch (NumberFormatException ignore) {
                    // fall through to double for out-of-long-range integers
                }
            }
            return Double.parseDouble(tok);
        }

        Boolean bool() {
            if (src.startsWith("true", pos)) { pos += 4; return Boolean.TRUE; }
            if (src.startsWith("false", pos)) { pos += 5; return Boolean.FALSE; }
            throw new IllegalArgumentException("invalid literal at " + pos);
        }

        Object nullLit() {
            if (src.startsWith("null", pos)) { pos += 4; return null; }
            throw new IllegalArgumentException("invalid literal at " + pos);
        }

        char peek() {
            if (pos >= src.length()) {
                throw new IllegalArgumentException("unexpected end of JSON");
            }
            return src.charAt(pos);
        }
    }

    // --- writer ---

    public static String write(Object v) {
        StringBuilder sb = new StringBuilder();
        writeInto(v, sb);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void writeInto(Object v, StringBuilder sb) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String s) {
            writeString(s, sb);
        } else if (v instanceof Boolean b) {
            sb.append(b ? "true" : "false");
        } else if (v instanceof Long || v instanceof Integer) {
            sb.append(v.toString());
        } else if (v instanceof Double d) {
            if (d == Math.floor(d) && !d.isInfinite()) {
                sb.append(Long.toString(d.longValue()));
            } else {
                sb.append(d.toString());
            }
        } else if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                if (!first) { sb.append(','); }
                first = false;
                writeString(e.getKey(), sb);
                sb.append(':');
                writeInto(e.getValue(), sb);
            }
            sb.append('}');
        } else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object e : (List<Object>) v) {
                if (!first) { sb.append(','); }
                first = false;
                writeInto(e, sb);
            }
            sb.append(']');
        } else {
            throw new IllegalArgumentException("cannot serialize " + v.getClass());
        }
    }

    private static void writeString(String s, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }
}
