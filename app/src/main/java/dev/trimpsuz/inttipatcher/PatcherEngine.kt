package dev.trimpsuz.inttipatcher

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.Inflater
import kotlin.collections.iterator

object PatcherEngine {

    // helpers
    fun u16(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8)

    fun u32(b: ByteArray, o: Int): Long =
        (b[o].toLong() and 0xFF) or ((b[o + 1].toLong() and 0xFF) shl 8) or
                ((b[o + 2].toLong() and 0xFF) shl 16) or ((b[o + 3].toLong() and 0xFF) shl 24)

    fun putU16(b: ByteArray, o: Int, v: Int) {
        b[o] = (v and 0xFF).toByte()
        b[o + 1] = ((v ushr 8) and 0xFF).toByte()
    }

    fun putU32(b: ByteArray, o: Int, v: Long) {
        b[o] = (v and 0xFF).toByte()
        b[o + 1] = ((v ushr 8) and 0xFF).toByte()
        b[o + 2] = ((v ushr 16) and 0xFF).toByte()
        b[o + 3] = ((v ushr 24) and 0xFF).toByte()
    }

    fun sha256Hex(data: ByteArray): String {
        val d = MessageDigest.getInstance("SHA-256").digest(data)
        val sb = StringBuilder(d.size * 2)
        for (x in d) sb.append("%02x".format(x))
        return sb.toString()
    }

    fun crc32(data: ByteArray): Int {
        val c = CRC32()
        c.update(data)
        return c.value.toInt()
    }

    //  SO patching

    fun patchSo(so: ByteArray, patches: List<LongArray>) {
        for (p in patches) {
            val off = p[0].toInt()
            val orig = p[1]
            val repl = p[2]
            val cur = u32(so, off)
            if (cur != orig) {
                throw IllegalArgumentException(
                    "Original bytes mismatch at 0x" + Integer.toHexString(off) +
                            " (expected " + java.lang.Long.toHexString(orig) +
                            ", found " + java.lang.Long.toHexString(cur) + ")")
            }
            putU32(so, off, repl)
        }
    }

    //  AXML: strip attributes from the <manifest> element

    private const val RES_STRING_POOL = 0x0001
    private const val RES_XML_START_ELEMENT = 0x0102

    private class StringPool(private val file: ByteArray, chunkStart: Int) {
        val count: Int = u32(file, chunkStart + 8).toInt()
        private val flags: Int = u32(file, chunkStart + 16).toInt()
        private val stringsStart: Int = chunkStart + u32(file, chunkStart + 20).toInt()
        private val offsets: IntArray = IntArray(count)

        init {
            for (i in 0 until count) {
                offsets[i] = u32(file, chunkStart + 28 + i * 4).toInt()
            }
        }

        private fun readUtf8Len(pos: Int, p: IntArray): Int {
            var v = file[pos + p[0]].toInt() and 0xFF
            p[0]++
            if (v and 0x80 != 0) {
                v = (v and 0x7F shl 8) or (file[pos + p[0]].toInt() and 0xFF)
                p[0]++
            }
            return v
        }

        private fun readUtf16Len(pos: Int, p: IntArray): Int {
            var v = u16(file, pos + p[0])
            p[0] += 2
            if (v and 0x8000 != 0) {
                v = (v and 0x7FFF shl 16) or u16(file, pos + p[0])
                p[0] += 2
            }
            return v
        }

        fun get(idx: Int): String? {
            if (idx !in 0..<count) return null
            val off = stringsStart + offsets[idx]
            if (flags and 0x100 != 0) { // UTF-8: two length prefixes
                val p = intArrayOf(0)
                readUtf8Len(off, p)
                val byteLen = readUtf8Len(off, p)
                return String(file, off + p[0], byteLen, StandardCharsets.UTF_8)
            } else { // UTF-16
                val p = intArrayOf(0)
                val len = readUtf16Len(off, p)
                val sb = StringBuilder(len)
                for (i in 0 until len) sb.append(u16(file, off + p[0] + i * 2).toChar())
                return sb.toString()
            }
        }
    }

    private fun write16(b: ByteArrayOutputStream, v: Int) {
        b.write(v and 0xFF)
        b.write((v ushr 8) and 0xFF)
    }

    private fun write32(b: ByteArrayOutputStream, v: Long) {
        b.write((v and 0xFF).toInt())
        b.write(((v ushr 8) and 0xFF).toInt())
        b.write(((v ushr 16) and 0xFF).toInt())
        b.write(((v ushr 24) and 0xFF).toInt())
    }

    fun stripManifestAttrs(axml: ByteArray, removeNames: Array<String>): ByteArray {
        var axml = axml
        if (u16(axml, 0) != 0x0003) throw IllegalArgumentException("Not an AXML file (bad header)")

        var pool: StringPool? = null
        var pos = 8
        while (pos + 8 <= axml.size) {
            val type = u16(axml, pos)
            val size = u32(axml, pos + 4).toInt()
            if (size < 8 || pos + size > axml.size) break
            if (type == RES_STRING_POOL) {
                pool = StringPool(axml, pos)
                break
            }
            pos += size
        }
        if (pool == null) throw IllegalArgumentException("No string pool found")

        val removeSet = HashSet<String>()
        for (n in removeNames) removeSet.add(n)
        var removedBytes = 0

        pos = 8
        while (pos + 8 <= axml.size) {
            val type = u16(axml, pos)
            val hdrSize = u16(axml, pos + 2)
            val size = u32(axml, pos + 4).toInt()
            if (size < 8 || pos + size > axml.size) break

            if (type == RES_XML_START_ELEMENT) {
                val elName = pool.get(u32(axml, pos + 0x14).toInt())
                if ("manifest" == elName) {
                    val attrStart = u16(axml, pos + 0x18)
                    val attrSize = u16(axml, pos + 0x1A)
                    val attrCount = u16(axml, pos + 0x1C)
                    val attrOff = pos + 0x10 + attrStart

                    val remove = ArrayList<Int>()
                    for (a in 0 until attrCount) {
                        val aoff = attrOff + a * attrSize
                        val an = pool.get(u32(axml, aoff + 4).toInt())
                        if (an != null && removeSet.contains(an)) remove.add(a)
                    }

                    if (remove.isNotEmpty()) {
                        removedBytes = remove.size * attrSize

                        val bout = ByteArrayOutputStream()
                        write16(bout, type)
                        write16(bout, hdrSize)
                        write32(bout, (size - removedBytes).toLong())
                        bout.write(axml, pos + 8, 0x10) // line, comment, ns, name
                        write16(bout, attrStart)
                        write16(bout, attrSize)
                        write16(bout, attrCount - remove.size)
                        write16(bout, u16(axml, pos + 0x1E))
                        write16(bout, u16(axml, pos + 0x20))
                        write16(bout, u16(axml, pos + 0x22))
                        for (a in 0 until attrCount) {
                            if (remove.contains(a)) continue
                            bout.write(axml, attrOff + a * attrSize, attrSize)
                        }
                        val newChunk = bout.toByteArray()

                        val merged = ByteArray(axml.size - removedBytes)
                        System.arraycopy(axml, 0, merged, 0, pos)
                        System.arraycopy(newChunk, 0, merged, pos, newChunk.size)
                        System.arraycopy(axml, pos + size, merged, pos + newChunk.size,
                            axml.size - (pos + size))
                        axml = merged
                    }
                    break // only one <manifest> element
                }
            }
            pos += size
        }

        if (removedBytes == 0) {
            throw IllegalArgumentException("None of the requested manifest attributes were found")
        }
        putU32(axml, 4, u32(axml, 4) - removedBytes)
        return axml
    }

    fun renamePackage(axml: ByteArray, oldPkg: String, newPkg: String): ByteArray {
        if (u16(axml, 0) != 0x0003) throw IllegalArgumentException("Not an AXML file (bad header)")
        if (oldPkg == newPkg) return axml

        var poolPos = -1
        var pos = 8
        while (pos + 8 <= axml.size) {
            val type = u16(axml, pos)
            val size = u32(axml, pos + 4).toInt()
            if (size < 8 || pos + size > axml.size) break
            if (type == RES_STRING_POOL) {
                poolPos = pos
                break
            }
            pos += size
        }
        if (poolPos < 0) throw IllegalArgumentException("No string pool found")
        val pool = StringPool(axml, poolPos)
        val poolSize = u32(axml, poolPos + 4).toInt()

        // which existing pool indices must change, and to which new value
        val changed = LinkedHashMap<Int, String>()
        for (i in 0 until pool.count) {
            val s = pool.get(i) ?: continue
            if (s == oldPkg) changed[i] = newPkg
            else if (s.startsWith(oldPkg + ".")) changed[i] = newPkg + s.substring(oldPkg.length)
        }
        if (changed.isEmpty()) throw IllegalArgumentException("Package $oldPkg not found in the manifest")

        // dedupe new values; appended strings get indices after the existing ones
        val newValues = LinkedHashMap<String, Int>()
        val oldToNew = HashMap<Int, Int>()
        for ((oldIdx, value) in changed) {
            var ni = newValues[value]
            if (ni == null) {
                ni = pool.count + newValues.size
                newValues[value] = ni
            }
            oldToNew[oldIdx] = ni
        }

        // encode the appended strings in the pool's encoding
        val utf8 = u32(axml, poolPos + 16).toInt() and 0x100 != 0
        val encoded = ArrayList<ByteArray>(newValues.size)
        var newDataLen = 0
        for ((value, _) in newValues) {
            val b = ByteArrayOutputStream()
            if (utf8) {
                val bytes = value.toByteArray(StandardCharsets.UTF_8)
                write16(b, value.length)
                write16(b, bytes.size)
                b.write(bytes, 0, bytes.size)
                b.write(0)
            } else {
                write16(b, value.length)
                for (i in 0 until value.length) write16(b, value[i].code)
                write16(b, 0)
            }
            val raw = b.toByteArray()
            val pad = (4 - raw.size % 4) % 4
            val out = ByteArray(raw.size + pad)
            System.arraycopy(raw, 0, out, 0, raw.size)
            encoded.add(out)
            newDataLen += out.size
        }

        // rebuild the string pool chunk
        val headerSize = u16(axml, poolPos + 2)
        val styleCount = u32(axml, poolPos + 12).toInt()
        val flags = u32(axml, poolPos + 16).toInt()
        val oldStringsStart = u32(axml, poolPos + 20).toInt()
        // aapt2 writes stylesStart = 0 when the pool has no styles
        val oldStylesStart = if (styleCount > 0) u32(axml, poolPos + 24).toInt() else 0
        val oldStringDataLen = if (oldStylesStart > 0) oldStylesStart - oldStringsStart
        else poolSize - oldStringsStart
        val styleDataLen = if (oldStylesStart > 0) poolSize - oldStylesStart else 0
        val newCount = pool.count + newValues.size
        // the offsets array grew, so the string data moves accordingly
        val newStringsStart = headerSize + 4 * newCount + 4 * styleCount
        val newStylesStart = if (styleCount > 0) newStringsStart + oldStringDataLen + newDataLen else 0
        val newPoolSize = newStringsStart + oldStringDataLen + newDataLen + styleDataLen

        val nb = ByteArrayOutputStream()
        write16(nb, 0x0001)
        write16(nb, headerSize)
        write32(nb, newPoolSize.toLong())
        write32(nb, newCount.toLong())
        write32(nb, styleCount.toLong())
        write32(nb, flags.toLong())
        write32(nb, newStringsStart.toLong())
        write32(nb, newStylesStart.toLong())
        // existing string offsets
        for (i in 0 until pool.count) write32(nb, u32(axml, poolPos + headerSize + i * 4))
        // offsets for appended strings
        var off = oldStringDataLen
        for (i in encoded.indices) {
            write32(nb, off.toLong())
            off += encoded[i].size
        }
        // style offsets
        if (oldStylesStart > 0) {
            for (i in 0 until styleCount) write32(nb, u32(axml, poolPos + headerSize + pool.count * 4 + i * 4))
        }
        // string data
        nb.write(axml, poolPos + oldStringsStart, oldStringDataLen)
        for (e in encoded) nb.write(e, 0, e.size)
        if (oldStylesStart > 0) nb.write(axml, poolPos + oldStylesStart, styleDataLen)
        val newPool = nb.toByteArray()

        // rebuild the file
        val newAxml = ByteArray(axml.size - poolSize + newPool.size)
        System.arraycopy(axml, 0, newAxml, 0, poolPos)
        System.arraycopy(newPool, 0, newAxml, poolPos, newPool.size)
        System.arraycopy(axml, poolPos + poolSize, newAxml, poolPos + newPool.size,
            axml.size - poolPos - poolSize)
        putU32(newAxml, 4, newAxml.size.toLong())

        // repoint affected attribute values
        pos = 8
        while (pos + 8 <= newAxml.size) {
            val type = u16(newAxml, pos)
            val size = u32(newAxml, pos + 4).toInt()
            if (size < 8 || pos + size > newAxml.size) break
            if (type == RES_XML_START_ELEMENT) {
                val attrStart = u16(newAxml, pos + 0x18)
                val attrSize = u16(newAxml, pos + 0x1A)
                val attrCount = u16(newAxml, pos + 0x1C)
                val attrOff = pos + 0x10 + attrStart
                for (a in 0 until attrCount) {
                    val aoff = attrOff + a * attrSize
                    val raw = u32(newAxml, aoff + 8).toInt()
                    oldToNew[raw]?.let { putU32(newAxml, aoff + 8, it.toLong()) }
                    // typedValue: size(u16) res0(u8) dataType(u8) data(u32)
                    if (newAxml[aoff + 15].toInt() and 0xFF == 0x03) {
                        val idx = u32(newAxml, aoff + 16).toInt()
                        oldToNew[idx]?.let { putU32(newAxml, aoff + 16, it.toLong()) }
                    }
                }
            }
            pos += size
        }
        return newAxml
    }

    fun renamePackageResources(arsc: ByteArray, oldPkg: String, newPkg: String): ByteArray {
        if (newPkg.length > 127) throw IllegalArgumentException("Package name too long (max 127 chars)")
        if (oldPkg == newPkg) return arsc
        var found = false
        // chunks start after the RES_TABLE header (type, headerSize, size, packageCount)
        var pos = 12
        while (pos + 8 <= arsc.size) {
            val type = u16(arsc, pos)
            val size = u32(arsc, pos + 4).toInt()
            if (size < 8 || pos + size > arsc.size) break
            if (type == 0x0200) { // RES_TABLE_PACKAGE
                if (readFixedName(arsc, pos + 12) == oldPkg) {
                    for (i in 0 until 128) putU16(arsc, pos + 12 + i * 2, 0)
                    for (i in newPkg.indices) putU16(arsc, pos + 12 + i * 2, newPkg[i].code)
                    found = true
                }
            }
            pos += size
        }
        if (!found) throw IllegalArgumentException("resources.arsc has no package chunk for $oldPkg")
        return arsc
    }

    private fun readFixedName(b: ByteArray, off: Int): String {
        val sb = StringBuilder()
        for (i in 0 until 128) {
            val c = u16(b, off + i * 2)
            if (c == 0) break
            sb.append(c.toChar())
        }
        return sb.toString()
    }

    //  ZIP reading (raw, streaming) + aligned ZIP writing

    class ZipEntryInfo {
        var name: String = ""
        var method = 0
        var flags = 0
        var crc = 0
        var csize = 0
        var usize = 0
        var time = 0
        var date = 0
        var dataOffset = 0L
    }

    fun readCentralDir(raf: RandomAccessFile): List<ZipEntryInfo> {
        val len = raf.length()
        val back = minOf(len, 65557L).toInt()
        val buf = ByteArray(back)
        raf.seek(len - back)
        raf.readFully(buf)
        var eocd = -1L
        var i = buf.size - 22
        while (i >= 0) {
            if (buf[i] == 0x50.toByte() && buf[i + 1] == 0x4b.toByte() &&
                buf[i + 2] == 0x05.toByte() && buf[i + 3] == 0x06.toByte()) {
                eocd = len - back + i
                break
            }
            i--
        }
        if (eocd < 0) throw IOException("EOCD not found")

        val e = ByteArray(22)
        raf.seek(eocd)
        raf.readFully(e)
        val numEntries = u16(e, 10)
        val cdOffset = u32(e, 16)

        val out = ArrayList<ZipEntryInfo>(numEntries)
        raf.seek(cdOffset)
        for (n in 0 until numEntries) {
            val hdr = ByteArray(46)
            raf.readFully(hdr)
            val sig = u32(hdr, 0)
            if (sig != 0x02014b50L) {
                throw IOException("Bad central directory entry")
            }
            val zi = ZipEntryInfo()
            zi.flags = u16(hdr, 8)
            zi.method = u16(hdr, 10)
            zi.time = u16(hdr, 12)
            zi.date = u16(hdr, 14)
            zi.crc = u32(hdr, 16).toInt()
            zi.csize = u32(hdr, 20).toInt()
            zi.usize = u32(hdr, 24).toInt()
            val nameLen = u16(hdr, 28)
            val extraLen = u16(hdr, 30)
            val commentLen = u16(hdr, 32)
            val lo = u32(hdr, 42)
            val nameBytes = ByteArray(nameLen)
            raf.readFully(nameBytes)
            raf.skipBytes(extraLen + commentLen)
            val centralPos = raf.filePointer
            zi.name = String(nameBytes, StandardCharsets.UTF_8)

            val lh = ByteArray(30)
            raf.seek(lo)
            raf.readFully(lh)
            if (u32(lh, 0) != 0x04034b50L) throw IOException("Bad local header for " + zi.name)
            val lnl = u16(lh, 26)
            val lel = u16(lh, 28)
            zi.dataOffset = lo + 30 + lnl + lel
            raf.seek(centralPos)
            out.add(zi)
        }
        return out
    }

    private class ZipWriter(val out: RandomAccessFile) {
        val cd = ArrayList<ByteArray>()
        var offset = 0L

        fun writeBytes(b: ByteArray, n: Int) {
            out.write(b, 0, n)
            offset += n
        }

        fun localHeader(name: String, method: Int, crc: Int, csize: Int, usize: Int,
                        time: Int, date: Int, extraLen: Int) {
            val n = name.toByteArray(StandardCharsets.UTF_8)
            val h = ByteArray(30)
            putU32(h, 0, 0x04034b50L)
            putU16(h, 4, 20)
            putU16(h, 6, 0)
            putU16(h, 8, method)
            putU16(h, 10, time)
            putU16(h, 12, date)
            putU32(h, 14, crc.toLong())
            putU32(h, 18, csize.toLong())
            putU32(h, 22, usize.toLong())
            putU16(h, 26, n.size)
            putU16(h, 28, extraLen)
            writeBytes(h, 30)
            writeBytes(n, n.size)
            if (extraLen > 0) writeBytes(ByteArray(extraLen), extraLen)
        }

        fun writeStored(name: String, crc: Int, usize: Int, time: Int, date: Int, data: ByteArray) {
            val nameLen = name.toByteArray(StandardCharsets.UTF_8).size
            val pad = ((4 - ((offset + 30 + nameLen) % 4)) % 4).toInt()
            localHeader(name, 0, crc, usize, usize, time, date, pad)
            writeBytes(data, data.size)
            cd.add(centralEntry(name, 0, crc, usize, usize, time, date,
                offset - usize - (30 + nameLen + pad), 0))
        }

        fun writeStoredStream(name: String, crc: Int, usize: Int, time: Int, date: Int,
                              src: RandomAccessFile, srcOffset: Long) {
            val nameLen = name.toByteArray(StandardCharsets.UTF_8).size
            val pad = ((4 - ((offset + 30 + nameLen) % 4)) % 4).toInt()
            localHeader(name, 0, crc, usize, usize, time, date, pad)
            val dataStart = offset
            val buf = ByteArray(131072)
            src.seek(srcOffset)
            var left = usize.toLong()
            while (left > 0) {
                val n = minOf(buf.size.toLong(), left).toInt()
                src.readFully(buf, 0, n)
                out.write(buf, 0, n)
                offset += n
                left -= n
            }
            cd.add(centralEntry(name, 0, crc, usize, usize, time, date,
                dataStart - (30 + nameLen + pad), 0))
        }

        fun writeRaw(name: String, method: Int, crc: Int, csize: Int, usize: Int,
                     time: Int, date: Int, src: RandomAccessFile, srcOffset: Long) {
            val nameLen = name.toByteArray(StandardCharsets.UTF_8).size
            localHeader(name, method, crc, csize, usize, time, date, 0)
            val dataStart = offset
            val buf = ByteArray(131072)
            src.seek(srcOffset)
            var left = csize.toLong()
            while (left > 0) {
                val n = minOf(buf.size.toLong(), left).toInt()
                src.readFully(buf, 0, n)
                out.write(buf, 0, n)
                offset += n
                left -= n
            }
            cd.add(centralEntry(name, method, crc, csize, usize, time, date,
                dataStart - (30 + nameLen), 0))
        }

        fun writeDeflated(name: String, crc: Int, usize: Int, time: Int, date: Int, data: ByteArray) {
            val comp = deflate(data)
            localHeader(name, 8, crc, comp.size, usize, time, date, 0)
            writeBytes(comp, comp.size)
            cd.add(centralEntry(name, 8, crc, comp.size, usize, time, date,
                offset - comp.size - (30 + name.toByteArray(StandardCharsets.UTF_8).size), 0))
        }

        private fun centralEntry(name: String, method: Int, crc: Int, csize: Int, usize: Int,
                                 time: Int, date: Int, localOffset: Long, extraLen: Int): ByteArray {
            val n = name.toByteArray(StandardCharsets.UTF_8)
            val b = ByteArrayOutputStream()
            write32(b, 0x02014b50L)
            write16(b, 20)
            write16(b, 20)
            write16(b, 0)
            write16(b, method)
            write16(b, time)
            write16(b, date)
            write32(b, crc.toLong())
            write32(b, csize.toLong())
            write32(b, usize.toLong())
            write16(b, n.size)
            write16(b, extraLen)
            write16(b, 0)
            write16(b, 0)
            write16(b, 0)
            write32(b, 0)
            write32(b, localOffset)
            b.write(n, 0, n.size)
            return b.toByteArray()
        }

        fun finish() {
            val cdStart = offset
            for (rec in cd) writeBytes(rec, rec.size)
            val cdSize = offset - cdStart
            val e = ByteArray(22)
            putU32(e, 0, 0x06054b50L)
            putU16(e, 4, 0)
            putU16(e, 6, 0)
            putU16(e, 8, cd.size)
            putU16(e, 10, cd.size)
            putU32(e, 12, cdSize)
            putU32(e, 16, cdStart)
            putU16(e, 20, 0)
            writeBytes(e, 22)
        }
    }

    fun deflate(data: ByteArray): ByteArray {
        val d = Deflater(Deflater.DEFAULT_COMPRESSION, true)
        d.setInput(data)
        d.finish()
        val b = ByteArrayOutputStream()
        val buf = ByteArray(65536)
        while (!d.finished()) {
            val n = d.deflate(buf)
            b.write(buf, 0, n)
        }
        d.end()
        return b.toByteArray()
    }

    fun inflate(data: ByteArray): ByteArray {
        val inf = Inflater(true)
        inf.setInput(data)
        val b = ByteArrayOutputStream()
        val buf = ByteArray(65536)
        try {
            while (!inf.finished()) {
                val n = inf.inflate(buf)
                if (n == 0) break
                b.write(buf, 0, n)
            }
        } finally {
            inf.end()
        }
        return b.toByteArray()
    }

    //  Top-level build

    class Config {
        var libEntry = ""
        var libSha256 = ""
        var removeManifestAttrs: Array<String> = arrayOf()
        var patches: List<LongArray> = emptyList()
        var originalPackage = "com.OneGlitch.INTTI"
        var newPackage: String? = null
    }

    class Result {
        var output: File? = null
        var outputBytes = 0L
        var patchedLibSha256 = ""
        val log = ArrayList<String>()
    }

    fun build(baseApk: File, splitApk: File?, cfg: Config, out: File): Result {
        val r = Result()
        r.log.add("Reading " + baseApk.name)
        if (splitApk != null) r.log.add("Reading " + splitApk.name)

        RandomAccessFile(baseApk, "r").use { rafBase ->
            val rafSplit = if (splitApk != null) RandomAccessFile(splitApk, "r") else null
            try {
                val baseEntries = readCentralDir(rafBase)
                val splitEntries = if (rafSplit != null) readCentralDir(rafSplit) else emptyList()

                // locate lib entry in split (fall back to base)
                var soInfo = findEntry(splitEntries, cfg.libEntry)
                var soSrc = rafSplit
                if (soInfo == null) {
                    soInfo = findEntry(baseEntries, cfg.libEntry)
                    soSrc = rafBase
                }
                if (soInfo == null) throw IllegalArgumentException(
                    "libil2cpp.so not found in either APK.")

                val manifestInfo = findEntry(baseEntries, "AndroidManifest.xml")
                    ?: throw IllegalArgumentException("AndroidManifest.xml not found in base APK")
                if (findEntry(baseEntries, "resources.arsc") == null) {
                    throw IllegalArgumentException("resources.arsc not found - this is not the base APK")
                }

                // read + verify + patch .so
                val so = readEntry(soSrc!!, soInfo)
                r.log.add("libil2cpp.so: " + so.size + " bytes, sha256 " + sha256Hex(so))
                if (sha256Hex(so) != cfg.libSha256) {
                    throw IllegalArgumentException(
                        "Unsupported INTTI version: libil2cpp.so hash " + sha256Hex(so) +
                                " does not match expected " + cfg.libSha256 + ".")
                }
                patchSo(so, cfg.patches)
                r.patchedLibSha256 = sha256Hex(so)
                r.log.add("Applied " + cfg.patches.size + " byte patches -> sha256 " + r.patchedLibSha256)

                // patch manifest
                var manifest = readEntry(rafBase, manifestInfo)
                manifest = stripManifestAttrs(manifest, cfg.removeManifestAttrs)
                val manifestMethod = manifestInfo.method
                r.log.add("AndroidManifest.xml patched (removed " + cfg.removeManifestAttrs.joinToString(",") + ")")
                var patchedArsc: ByteArray? = null
                if (cfg.newPackage != null && cfg.newPackage != cfg.originalPackage) {
                    manifest = renamePackage(manifest, cfg.originalPackage, cfg.newPackage!!)
                    r.log.add("Package renamed: " + cfg.originalPackage + " -> " + cfg.newPackage)
                    val arscInfo = findEntry(baseEntries, "resources.arsc")
                        ?: throw IllegalArgumentException("resources.arsc not found in base APK")
                    var arsc = readEntry(rafBase, arscInfo)
                    arsc = renamePackageResources(arsc, cfg.originalPackage, cfg.newPackage!!)
                    patchedArsc = arsc
                    r.log.add("resources.arsc package renamed")
                }

                // write merged APK
                RandomAccessFile(out, "rw").use { rafOut ->
                    rafOut.setLength(0)
                    val w = ZipWriter(rafOut)

                    // split libs come first (so they are aligned and loadable)
                    val written = HashSet<String>()
                    for (zi in splitEntries) {
                        if (!zi.name.startsWith("lib/")) continue
                        written.add(zi.name)
                        if (zi.name == cfg.libEntry) {
                            val crc = crc32(so)
                            w.writeStored(zi.name, crc, so.size, zi.time, zi.date, so)
                        } else if (zi.method == 0) {
                            w.writeStoredStream(zi.name, zi.crc, zi.usize, zi.time, zi.date, rafSplit!!, zi.dataOffset)
                        } else {
                            w.writeRaw(zi.name, zi.method, zi.crc, zi.csize, zi.usize, zi.time, zi.date, rafSplit!!, zi.dataOffset)
                        }
                    }

                    for (zi in baseEntries) {
                        if (zi.name.startsWith("META-INF/")) continue
                        if (zi.name.startsWith("lib/")) continue
                        if (!written.add(zi.name)) continue
                        if (zi.name == "AndroidManifest.xml") {
                            val crc = crc32(manifest)
                            if (manifestMethod == 0) {
                                w.writeStored("AndroidManifest.xml", crc, manifest.size, zi.time, zi.date, manifest)
                            } else {
                                w.writeDeflated("AndroidManifest.xml", crc, manifest.size, zi.time, zi.date, manifest)
                            }
                        } else if (zi.name == "resources.arsc" && patchedArsc != null) {
                            val crc = crc32(patchedArsc)
                            if (zi.method == 0) {
                                w.writeStored("resources.arsc", crc, patchedArsc.size, zi.time, zi.date, patchedArsc)
                            } else {
                                w.writeDeflated("resources.arsc", crc, patchedArsc.size, zi.time, zi.date, patchedArsc)
                            }
                        } else if (zi.method == 0) {
                            w.writeStoredStream(zi.name, zi.crc, zi.usize, zi.time, zi.date, rafBase, zi.dataOffset)
                        } else {
                            w.writeRaw(zi.name, zi.method, zi.crc, zi.csize, zi.usize, zi.time, zi.date, rafBase, zi.dataOffset)
                        }
                    }

                    w.finish()
                    rafOut.setLength(rafOut.filePointer)
                    rafOut.fd.sync()
                }
            } finally {
                rafSplit?.close()
            }
        }
        r.output = out
        r.outputBytes = out.length()
        r.log.add("Wrote " + out.name + " (" + out.length() + " bytes)")
        return r
    }

    private fun findEntry(entries: List<ZipEntryInfo>, name: String): ZipEntryInfo? {
        for (e in entries) if (e.name == name) return e
        return null
    }

    fun readEntry(raf: RandomAccessFile, zi: ZipEntryInfo): ByteArray {
        val raw = ByteArray(zi.csize)
        raf.seek(zi.dataOffset)
        raf.readFully(raw)
        if (zi.method == 0) return raw
        if (zi.method == 8) return inflate(raw)
        throw IOException("Unsupported compression method " + zi.method + " for " + zi.name)
    }
}