package com.security.dnssinkhole

import java.nio.ByteBuffer

object DnsPacketParser {

    /**
     * Extracts QNAME (domain name) from raw DNS payload bytes starting at offset 0 of DNS packet.
     */
    fun parseDomainName(data: ByteArray, dnsOffset: Int): String {
        val sb = StringBuilder()
        var pos = dnsOffset + 12 // Skip 12-byte DNS Header (ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
        val maxPos = data.size

        while (pos < maxPos) {
            val len = data[pos].toInt() and 0xFF
            if (len == 0) break // End of labels

            // Check for pointer (compression)
            if ((len and 0xC0) == 0xC0) {
                pos += 2
                break
            }

            pos++
            if (pos + len > maxPos) break

            for (i in 0 until len) {
                sb.append(data[pos + i].toInt().toChar())
            }
            sb.append('.')
            pos += len
        }

        return sb.toString().removeSuffix(".")
    }

    /**
     * Builds a DNS response answering with 0.0.0.0 (Sinkhole)
     */
    fun buildSinkholeResponse(queryDns: ByteArray, length: Int): ByteArray {
        val response = ByteArray(length + 16)
        System.arraycopy(queryDns, 0, response, 0, length)

        // Set QR bit to 1 (Response), RCODE to 0 (No Error) or NXDOMAIN
        // Flags are at offset 2 & 3
        response[2] = (response[2].toInt() or 0x81).toByte() // Standard query response, recursion available
        response[3] = 0x80.toByte()

        // Set Answer Count (ANCOUNT) = 1 at offset 6 & 7
        response[6] = 0
        response[7] = 1

        // Append A-record answer
        var pos = length
        // Name pointer to QNAME (0xC00C)
        response[pos++] = 0xC0.toByte()
        response[pos++] = 0x0C.toByte()

        // Type A = 0x0001
        response[pos++] = 0x00
        response[pos++] = 0x01

        // Class IN = 0x0001
        response[pos++] = 0x00
        response[pos++] = 0x01

        // TTL = 60 seconds (0x0000003C)
        response[pos++] = 0x00
        response[pos++] = 0x00
        response[pos++] = 0x00
        response[pos++] = 0x3C

        // RDLENGTH = 4 bytes (0x0004)
        response[pos++] = 0x00
        response[pos++] = 0x04

        // RDATA = 0.0.0.0
        response[pos++] = 0x00
        response[pos++] = 0x00
        response[pos++] = 0x00
        response[pos++] = 0x00

        return response
    }
}
