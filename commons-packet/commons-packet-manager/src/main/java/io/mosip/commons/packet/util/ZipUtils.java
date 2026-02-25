package io.mosip.commons.packet.util;

import io.mosip.kernel.core.logger.spi.Logger;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOCase;
import org.apache.commons.io.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Class to unzip the packets
 */
public class ZipUtils {


    private static Logger LOGGER = PacketManagerLogger.getLogger(ZipUtils.class);

    /**
     * Method to unzip the file in-memeory and search the required file and return
     * it
     *
     * @param packet zip file to be unzipped
     * @param file   file to search within zip file
     * @return return the corresponding file as inputStream
     * @throws IOException if any error occored while unzipping the file
     */
    public static InputStream unzipAndGetFile(byte[] packet, String file) throws IOException {
        ByteArrayInputStream packetStream = new ByteArrayInputStream(packet);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        boolean flag = false;
        byte[] buffer = new byte[2048];
        try (ZipInputStream zis = new ZipInputStream(packetStream)) {
            ZipEntry ze = zis.getNextEntry();
            while (ze != null) {
                String fileName = ze.getName();
                String fileNameWithOutExt = FilenameUtils.removeExtension(fileName);
                if (FilenameUtils.equals(fileNameWithOutExt, file, true, IOCase.INSENSITIVE)) {
                    int len;
                    flag = true;
                    while ((len = zis.read(buffer)) > 0) {
                        out.write(buffer, 0, len);
                    }
                    break;
                }
                zis.closeEntry();
                ze = zis.getNextEntry();
            }
            zis.closeEntry();
        } finally {
            packetStream.close();
            out.close();
        }
        if (flag) {
            return new ByteArrayInputStream(out.toByteArray());
        }

        return null;
    }
    /**
     * Extracts a single file from an in-memory ZIP byte array using streaming.
     * Uses ZipArchiveInputStream (Apache Commons Compress) which works with InputStream.
     *
     * @param zipBytes   ZIP content as byte[]
     * @param fileName   exact name/path of file inside ZIP (case-sensitive)
     * @return byte[] of the file content, or null if not found
     * @throws IOException on corrupt ZIP or I/O error
     */
    public static byte[] unzipAndGetFileBytes(byte[] zipBytes, String fileName) throws IOException {
        if (zipBytes == null || zipBytes.length == 0) {
            LOGGER.warn(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, null,
                    "zipBytes is null or empty - cannot extract: " + fileName);
            return null;
        }
        if (fileName == null || fileName.trim().isEmpty()) {
            LOGGER.warn(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, null,
                    "fileName is null or empty");
            return null;
        }
        try (ByteArrayInputStream bais = new ByteArrayInputStream(zipBytes);
             ZipArchiveInputStream zipIn = new ZipArchiveInputStream(bais)) {
            ZipArchiveEntry entry;
            while ((entry = zipIn.getNextZipEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                if (fileName.equals(entry.getName())) {
                    // Found → read content
                    byte[] content = IOUtils.toByteArray(zipIn);
                    LOGGER.debug(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, null,
                            "Extracted: " + fileName + " (" + content.length + " bytes)");
                    return content;
                }
                // Optional: case-insensitive fallback
                if (fileName.equalsIgnoreCase(entry.getName())) {
                    byte[] content = IOUtils.toByteArray(zipIn);
                    LOGGER.debug(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, null,
                            "Extracted (case-insensitive): " + entry.getName() + " (" + content.length + " bytes)");
                    return content;
                }
            }
            LOGGER.debug(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, null,
                    "File not found in ZIP: " + fileName);
            return null;
        } catch (IOException e) {
            LOGGER.error(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, null,
                    "Failed to extract " + fileName + " from ZIP", e);
            throw e;
        }
    }
}
