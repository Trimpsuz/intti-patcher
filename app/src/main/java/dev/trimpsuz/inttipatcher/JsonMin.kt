package dev.trimpsuz.inttipatcher

object JsonMin {

    fun parse(s: String): Any? {
        val p = Parser(s)
        p.skipWs()
        val v = p.value()
        p.skipWs()
        if (p.pos < p.s.length) throw RuntimeException("Trailing data at " + p.pos)
        return v
    }

    @Suppress("UNCHECKED_CAST")
    fun obj(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    fun arr(o: Any?): List<Any?> = o as List<Any?>

    fun str(o: Any?): String = o as String

    fun lng(o: Any?): Long = (o as Number).toLong()

    private class Parser(val s: String) {
        var pos = 0

        fun skipWs() {
            while (pos < s.length) {
                val c = s[pos]
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++
                else break
            }
        }

        fun value(): Any? {
            skipWs()
            if (pos >= s.length) throw RuntimeException("Unexpected end")
            when (s[pos]) {
                '{' -> return obj()
                '[' -> return array()
                '"' -> return string()
                't' -> { expect("true"); return true }
                'f' -> { expect("false"); return false }
                'n' -> { expect("null"); return null }
                else -> {
                    if (s[pos] == '-' || s[pos] in '0'..'9') return number()
                    throw RuntimeException("Unexpected char '" + s[pos] + "' at " + pos)
                }
            }
        }

        fun expect(lit: String) {
            if (!s.startsWith(lit, pos)) throw RuntimeException("Expected $lit at $pos")
            pos += lit.length
        }

        fun obj(): Map<String, Any?> {
            pos++
            val m = HashMap<String, Any?>()
            skipWs()
            if (pos < s.length && s[pos] == '}') { pos++; return m }
            while (true) {
                skipWs()
                val k = string()
                skipWs()
                if (s[pos] != ':') throw RuntimeException("Expected ':' at $pos")
                pos++
                m[k] = value()
                skipWs()
                if (s[pos] == ',') { pos++; continue }
                if (s[pos] == '}') { pos++; return m }
                throw RuntimeException("Expected ',' or '}' at $pos")
            }
        }

        fun array(): List<Any?> {
            pos++
            val l = ArrayList<Any?>()
            skipWs()
            if (pos < s.length && s[pos] == ']') { pos++; return l }
            while (true) {
                l.add(value())
                skipWs()
                if (s[pos] == ',') { pos++; continue }
                if (s[pos] == ']') { pos++; return l }
                throw RuntimeException("Expected ',' or ']' at $pos")
            }
        }

        fun string(): String {
            if (s[pos] != '"') throw RuntimeException("Expected '\"' at $pos")
            pos++
            val sb = StringBuilder()
            while (pos < s.length) {
                val c = s[pos]
                if (c == '"') { pos++; return sb.toString() }
                if (c == '\\') {
                    pos++
                    when (s[pos]) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            sb.append(Integer.parseInt(s.substring(pos + 1, pos + 5), 16).toChar())
                            pos += 4
                        }
                        else -> throw RuntimeException("Bad escape '\\" + s[pos] + "'")
                    }
                    pos++
                } else {
                    sb.append(c)
                    pos++
                }
            }
            throw RuntimeException("Unterminated string")
        }

        fun number(): Number {
            val start = pos
            while (pos < s.length) {
                val c = s[pos]
                if (c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E' || c in '0'..'9') pos++
                else break
            }
            val t = s.substring(start, pos)
            return if (t.indexOf('.') >= 0 || t.indexOf('e') >= 0 || t.indexOf('E') >= 0) {
                t.toDouble()
            } else {
                t.toLong()
            }
        }
    }
}