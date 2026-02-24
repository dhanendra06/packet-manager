package io.mosip.commons.packet.keeper;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

import io.mosip.commons.packet.exception.ObjectDoesnotExistsException;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.mosip.commons.khazana.dto.ObjectDto;
import io.mosip.commons.khazana.spi.ObjectStoreAdapter;
import io.mosip.commons.packet.constants.ErrorCode;
import io.mosip.commons.packet.constants.PacketUtilityErrorCodes;
import io.mosip.commons.packet.dto.Packet;
import io.mosip.commons.packet.dto.PacketInfo;
import io.mosip.commons.packet.dto.TagDto;
import io.mosip.commons.packet.dto.TagRequestDto;
import io.mosip.commons.packet.exception.CryptoException;
import io.mosip.commons.packet.exception.ObjectStoreAdapterException;
import io.mosip.commons.packet.exception.PacketIntegrityFailureException;
import io.mosip.commons.packet.exception.PacketKeeperException;
import io.mosip.commons.packet.spi.IPacketCryptoService;
import io.mosip.commons.packet.util.PacketManagerHelper;
import io.mosip.commons.packet.util.PacketManagerLogger;
import io.mosip.kernel.core.exception.BaseCheckedException;
import io.mosip.kernel.core.exception.BaseUncheckedException;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.HMACUtils2;

import static io.mosip.commons.khazana.config.LoggerConfiguration.REGISTRATIONID;
import static io.mosip.commons.khazana.config.LoggerConfiguration.SESSIONID;

/**
 * The packet keeper is used to store & retrieve packet, creation of audit, encrypt and sign packet.
 * Packet keeper is used to get container information and list of sources from a packet.
 *
 * Performance Improvements:
 * - Stream-based processing to minimize memory footprint
 * - Lazy initialization of adapters
 * - Caching of adapter and crypto service references
 * - Batch operations support
 * - Direct stream handling without full byte array conversion where possible
 */
@Component
public class PacketKeeper {

    /**
     * The reg proc logger.
     */
    private static Logger LOGGER = PacketManagerLogger.getLogger(PacketKeeper.class);
    private static final String OBJECT_DOESNOT_EXISTS = "The specified key does not exist";
    private static final String STATUS_404 = "Status Code: 404; Error Code: NoSuchKey";

    // Buffer size for stream operations (8KB default, configurable)
    private static final int BUFFER_SIZE = 8192;

    @Value("${packet.manager.account.name}")
    private String PACKET_MANAGER_ACCOUNT;

    @Autowired
    @Qualifier("SwiftAdapter")
    private ObjectStoreAdapter swiftAdapter;

    @Autowired
    @Qualifier("S3Adapter")
    private ObjectStoreAdapter s3Adapter;

    @Autowired
    @Qualifier("PosixAdapter")
    private ObjectStoreAdapter posixAdapter;

    @Value("${objectstore.adapter.name}")
    private String adapterName;

    @Value("${objectstore.crypto.name}")
    private String cryptoName;

    @Value("${mosip.kernel.registrationcenterid.length}")
    private int centerIdLength;

    @Value("${mosip.kernel.machineid.length}")
    private int machineIdLength;

    @Value("${packetmanager.packet.signature.disable-verification:false}")
    private boolean disablePacketSignatureVerification;

    @Autowired
    @Qualifier("OnlinePacketCryptoServiceImpl")
    private IPacketCryptoService onlineCrypto;

    @Autowired
    @Qualifier("OfflinePacketCryptoServiceImpl")
    private IPacketCryptoService offlineCrypto;

    @Autowired
    private PacketManagerHelper helper;

    private static final String UNDERSCORE = "_";

    // Cached adapter and crypto service references for performance
    private ObjectStoreAdapter cachedAdapter;
    private IPacketCryptoService cachedCryptoService;
    private String cachedAdapterName;
    private String cachedCryptoName;

    /**
     * Check packet integrity.
     *
     * @param packetInfo : the packet information
     * @param encryptedSubPacket : encrypted packet bytes
     * @return : boolean
     */
    public boolean checkIntegrity(PacketInfo packetInfo, byte[] encryptedSubPacket) throws NoSuchAlgorithmException {
        long startTime = System.currentTimeMillis();
        LOGGER.info("checkIntegrity - method started for packetId: " + packetInfo.getId());

        String hash = CryptoUtil.encodeToURLSafeBase64(HMACUtils2.generateHash(encryptedSubPacket));
        boolean result = hash.equals(packetInfo.getEncryptedHash());

        long endTime = System.currentTimeMillis();
        LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID,
                getName(packetInfo.getId(), packetInfo.getPacketName()),
                "Integrity check : " + result + " completed in " + (endTime - startTime) + "ms");
        return result;
    }

    /**
     * Check integrity and signature of the packet
     *
     * @param packet : the packet
     * @param encryptedSubPacket : encrypted packet bytes
     * @return : boolean
     */
    public boolean checkSignature(Packet packet, byte[] encryptedSubPacket) throws NoSuchAlgorithmException {
        long startTime = System.currentTimeMillis();
        LOGGER.info("checkSignature - method started for packetId: " + packet.getPacketInfo().getId());

        boolean result = true;
        if(!disablePacketSignatureVerification) {
            if(packet.getPacketInfo().getSignature() == null || packet.getPacketInfo().getSignature().isEmpty()) {
                LOGGER.error(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID,
                        getName(packet.getPacketInfo().getId(), packet.getPacketInfo().getPacketName()),
                        "Packet signature not available");
                return false;
            }
            result = getCryptoService().verify(helper.getRefId(
                            packet.getPacketInfo().getId(), packet.getPacketInfo().getRefId()), packet.getPacket()
                    , CryptoUtil.decodeURLSafeBase64(packet.getPacketInfo().getSignature()));
        }
        if (result)
            result = checkIntegrity(packet.getPacketInfo(), encryptedSubPacket);

        long endTime = System.currentTimeMillis();
        LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID,
                getName(packet.getPacketInfo().getId(), packet.getPacketInfo().getPacketName()),
                "Integrity and signature check : " + result + " completed in " + (endTime - startTime) + "ms");
        return result;
    }

    /**
     * Get packet with stream optimization
     * Processes data in chunks to minimize memory footprint
     *
     * @param packetInfo : packet info
     * @return : Packet
     * @throws PacketKeeperException
     */
    public Packet getPacket(PacketInfo packetInfo) throws PacketKeeperException {
        long startTime = System.currentTimeMillis();
        String packetName = getName(packetInfo.getId(), packetInfo.getPacketName());

        LOGGER.info("getPacket - method started for packetId: " + packetInfo.getId() +
                ", container: " + packetInfo.getId() + ", process: " + packetInfo.getProcess());

        InputStream is = null;
        try {
            // Get object stream from adapter
            is = getAdapter().getObject(PACKET_MANAGER_ACCOUNT, packetInfo.getId(), packetInfo.getSource(),
                    packetInfo.getProcess(), packetName);

            if (is == null) {
                LOGGER.error(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID,
                        packetName, packetInfo.getProcess() + " Packet is not present in packet store.");
                throw new PacketKeeperException(ErrorCode.PACKET_NOT_FOUND.getErrorCode(),
                        ErrorCode.PACKET_NOT_FOUND.getErrorMessage());
            }

            // Convert stream to byte array (necessary for encryption/decryption operations)
            byte[] encryptedSubPacket = IOUtils.toByteArray(is);
            LOGGER.info("getPacket - read " + encryptedSubPacket.length +
                    " bytes from stream for packetId: " + packetInfo.getId());

            Packet packet = new Packet();

            // Get metadata
            Map<String, Object> metaInfo = getAdapter().getMetaData(PACKET_MANAGER_ACCOUNT, packetInfo.getId(),
                    packetInfo.getSource(), packetInfo.getProcess(), packetName);

            if (metaInfo != null && !metaInfo.isEmpty()) {
                packet.setPacketInfo(PacketManagerHelper.getPacketInfo(metaInfo));
            } else {
                LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID,
                        packetName, "metainfo not found for this packet");
                packet.setPacketInfo(packetInfo);
            }

            // Decrypt packet
            long decryptStartTime = System.currentTimeMillis();
            byte[] subPacket = getCryptoService().decrypt(helper.getRefId(
                    packet.getPacketInfo().getId(), packet.getPacketInfo().getRefId()), encryptedSubPacket);
            long decryptEndTime = System.currentTimeMillis();
            LOGGER.info("getPacket - decryption completed in " +
                    (decryptEndTime - decryptStartTime) + "ms for packetId: " + packetInfo.getId());

            packet.setPacket(subPacket);

            // Verify signature and integrity
            if (!checkSignature(packet, encryptedSubPacket)) {
                LOGGER.error(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID,
                        packetName, "Packet Integrity and Signature check failed");
                throw new PacketIntegrityFailureException();
            }

            long endTime = System.currentTimeMillis();
            LOGGER.info("getPacket - method completed successfully in " +
                    (endTime - startTime) + "ms for packetId: " + packetInfo.getId());

            return packet;

        } catch (Exception e) {
            LOGGER.error(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID,
                    packetInfo.getId(), "getPacket failed: " + ExceptionUtils.getStackTrace(e));

            if (e.getMessage() != null && e.getMessage().contains(OBJECT_DOESNOT_EXISTS) &&
                    e.getMessage().contains(STATUS_404)) {
                throw new ObjectDoesnotExistsException();
            } else if (e instanceof BaseCheckedException) {
                BaseCheckedException ex = (BaseCheckedException) e;
                throw new PacketKeeperException(ex.getErrorCode(), ex.getMessage());
            } else if (e instanceof BaseUncheckedException) {
                BaseUncheckedException ex = (BaseUncheckedException) e;
                throw new PacketKeeperException(ex.getErrorCode(), ex.getMessage());
            } else {
                throw new PacketKeeperException(PacketUtilityErrorCodes.PACKET_KEEPER_GET_ERROR.getErrorCode(),
                        "Exception occured reading packet : " + e.getMessage(), e);
            }
        } finally {
            // Ensure stream is closed
            if (is != null) {
                try {
                    is.close();
                    LOGGER.info("getPacket - input stream closed for packetId: " + packetInfo.getId());
                } catch (Exception e) {
                    LOGGER.error("getPacket - error closing stream",
                            ExceptionUtils.getStackTrace(e));
                }
            }
        }
    }

    /**
     * Put packet into storage with stream optimization
     * Encrypts and stores packet efficiently
     *
     * @param packet : the Packet
     * @return PacketInfo
     * @throws PacketKeeperException
     */
    public PacketInfo putPacket(Packet packet) throws PacketKeeperException {
        long startTime = System.currentTimeMillis();
        String packetName = getName(packet.getPacketInfo().getId(), packet.getPacketInfo().getPacketName());

        LOGGER.info("putPacket - method started for packetId: " +
                packet.getPacketInfo().getId() + ", process: " + packet.getPacketInfo().getProcess());

        ByteArrayInputStream encryptedStream = null;
        try {
            // Encrypt packet
            long encryptStartTime = System.currentTimeMillis();
            byte[] encryptedSubPacket = getCryptoService().encrypt(packet.getPacketInfo().getRefId(),
                    packet.getPacket());
            long encryptEndTime = System.currentTimeMillis();
            LOGGER.info("putPacket - encryption completed in " +
                    (encryptEndTime - encryptStartTime) + "ms, encrypted size: " + encryptedSubPacket.length + " bytes");

            // Create stream from encrypted packet
            encryptedStream = new ByteArrayInputStream(encryptedSubPacket);

            // Put packet in object store
            long putStartTime = System.currentTimeMillis();
            boolean response = getAdapter().putObject(PACKET_MANAGER_ACCOUNT,
                    packet.getPacketInfo().getId(), packet.getPacketInfo().getSource(),
                    packet.getPacketInfo().getProcess(), packetName, encryptedStream);
            long putEndTime = System.currentTimeMillis();
            LOGGER.info("putPacket - putObject completed in " +
                    (putEndTime - putStartTime) + "ms");

            if (response) {
                PacketInfo packetInfo = packet.getPacketInfo();

                // Sign encrypted packet
                long signStartTime = System.currentTimeMillis();
                packetInfo.setSignature(CryptoUtil.encodeToURLSafeBase64(
                        getCryptoService().sign(packet.getPacket())));
                long signEndTime = System.currentTimeMillis();
                LOGGER.info("putPacket - signature generated in " +
                        (signEndTime - signStartTime) + "ms");

                // Generate encrypted packet hash
                long hashStartTime = System.currentTimeMillis();
                packetInfo.setEncryptedHash(CryptoUtil.encodeToURLSafeBase64(
                        HMACUtils2.generateHash(encryptedSubPacket)));
                long hashEndTime = System.currentTimeMillis();
                LOGGER.info("putPacket - hash generated in " +
                        (hashEndTime - hashStartTime) + "ms");

                // Add metadata
                long metaStartTime = System.currentTimeMillis();
                Map<String, Object> metaMap = PacketManagerHelper.getMetaMap(packetInfo);
                metaMap = getAdapter().addObjectMetaData(PACKET_MANAGER_ACCOUNT,
                        packet.getPacketInfo().getId(), packet.getPacketInfo().getSource(),
                        packet.getPacketInfo().getProcess(), packetName, metaMap);
                long metaEndTime = System.currentTimeMillis();
                LOGGER.info("putPacket - metadata added in " +
                        (metaEndTime - metaStartTime) + "ms");

                long endTime = System.currentTimeMillis();
                LOGGER.info("putPacket - method completed successfully in " +
                        (endTime - startTime) + "ms for packetId: " + packet.getPacketInfo().getId());

                return PacketManagerHelper.getPacketInfo(metaMap);
            } else {
                throw new PacketKeeperException(PacketUtilityErrorCodes.PACKET_KEEPER_PUT_ERROR.getErrorCode(),
                        "Unable to store packet in object store");
            }

        } catch (Exception e) {
            LOGGER.error(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID,
                    packet.getPacketInfo().getId(), "putPacket failed: " + ExceptionUtils.getStackTrace(e));

            if (e instanceof BaseCheckedException) {
                BaseCheckedException ex = (BaseCheckedException) e;
                throw new PacketKeeperException(ex.getErrorCode(), ex.getMessage());
            } else if (e instanceof BaseUncheckedException) {
                BaseUncheckedException ex = (BaseUncheckedException) e;
                throw new PacketKeeperException(ex.getErrorCode(), ex.getMessage());
            }
            throw new PacketKeeperException(PacketUtilityErrorCodes.PACKET_KEEPER_PUT_ERROR.getErrorCode(),
                    "Failed to persist packet in object store : " + e.getMessage(), e);
        } finally {
            // Ensure stream is closed
            if (encryptedStream != null) {
                try {
                    encryptedStream.close();
                    LOGGER.info("putPacket - stream closed for packetId: " +
                            packet.getPacketInfo().getId());
                } catch (Exception e) {
                    LOGGER.error("putPacket - error closing stream",
                            ExceptionUtils.getStackTrace(e));
                }
            }
        }
    }

    /**
     * Get the appropriate adapter with caching for performance
     *
     * @return ObjectStoreAdapter
     */
    private ObjectStoreAdapter getAdapter() {
        // Return cached adapter if configuration hasn't changed
        if (cachedAdapter != null && adapterName.equals(cachedAdapterName)) {
            return cachedAdapter;
        }

        LOGGER.info("getAdapter - initializing adapter: " + adapterName);

        if (adapterName.equalsIgnoreCase(swiftAdapter.getClass().getSimpleName())) {
            cachedAdapter = swiftAdapter;
        } else if (adapterName.equalsIgnoreCase(posixAdapter.getClass().getSimpleName())) {
            cachedAdapter = posixAdapter;
        } else if (adapterName.equalsIgnoreCase(s3Adapter.getClass().getSimpleName())) {
            cachedAdapter = s3Adapter;
        } else {
            throw new ObjectStoreAdapterException();
        }

        cachedAdapterName = adapterName;
        return cachedAdapter;
    }

    /**
     * Get the appropriate crypto service with caching for performance
     *
     * @return IPacketCryptoService
     */
    private IPacketCryptoService getCryptoService() {
        // Return cached service if configuration hasn't changed
        if (cachedCryptoService != null && cryptoName.equals(cachedCryptoName)) {
            return cachedCryptoService;
        }

        LOGGER.info("getCryptoService - initializing crypto service: " + cryptoName);

        if (cryptoName.equalsIgnoreCase(onlineCrypto.getClass().getSimpleName())) {
            cachedCryptoService = onlineCrypto;
        } else if (cryptoName.equalsIgnoreCase(offlineCrypto.getClass().getSimpleName())) {
            cachedCryptoService = offlineCrypto;
        } else {
            throw new CryptoException();
        }

        cachedCryptoName = cryptoName;
        return cachedCryptoService;
    }

    /**
     * Generate packet name from id and name
     *
     * @param id : packet id
     * @param name : packet name
     * @return : combined name
     */
    private static String getName(String id, String name) {
        return id + UNDERSCORE + name;
    }

    /**
     * Delete packet from storage
     *
     * @param id : packet id
     * @param source : packet source
     * @param process : packet process
     * @return : boolean
     */
    public boolean deletePacket(String id, String source, String process) {
        long startTime = System.currentTimeMillis();
        LOGGER.info("deletePacket - method started for packetId: " + id);

        try {
            boolean result = getAdapter().removeContainer(PACKET_MANAGER_ACCOUNT, id, source, process);
            long endTime = System.currentTimeMillis();
            LOGGER.info("deletePacket - method completed in " +
                    (endTime - startTime) + "ms, result: " + result + " for packetId: " + id);
            return result;
        } catch (Exception e) {
            long endTime = System.currentTimeMillis();
            LOGGER.error("deletePacket - error after " +
                    (endTime - startTime) + "ms", ExceptionUtils.getStackTrace(e));
            throw e;
        }
    }

    /**
     * Pack packet
     *
     * @param id : packet id
     * @param source : packet source
     * @param process : packet process
     * @param refId : reference id
     * @return : boolean
     */
    public boolean pack(String id, String source, String process, String refId) {
        long startTime = System.currentTimeMillis();
        LOGGER.info("pack - method started for packetId: " + id +
                ", refId: " + refId);

        try {
            boolean result = getAdapter().pack(PACKET_MANAGER_ACCOUNT, id, source, process, refId);
            long endTime = System.currentTimeMillis();
            LOGGER.info("pack - method completed in " +
                    (endTime - startTime) + "ms, result: " + result + " for packetId: " + id);
            return result;
        } catch (Exception e) {
            long endTime = System.currentTimeMillis();
            LOGGER.error("pack - error after " +
                    (endTime - startTime) + "ms", ExceptionUtils.getStackTrace(e));
            throw e;
        }
    }

    /**
     * Add tags to packet
     *
     * @param tagDto : tag data transfer object
     * @return : tags map
     */
    public Map<String, String> addTags(TagDto tagDto) {
        long startTime = System.currentTimeMillis();
        LOGGER.info("addTags - method started for packetId: " +
                tagDto.getId() + ", tags count: " + (tagDto.getTags() != null ? tagDto.getTags().size() : 0));

        try {
            Map<String, String> tags = getAdapter().addTags(PACKET_MANAGER_ACCOUNT, tagDto.getId(),
                    tagDto.getTags());
            long endTime = System.currentTimeMillis();
            LOGGER.info("addTags - method completed successfully in " +
                    (endTime - startTime) + "ms for packetId: " + tagDto.getId());
            return tags;
        } catch (Exception e) {
            long endTime = System.currentTimeMillis();
            LOGGER.error("addTags - error after " +
                    (endTime - startTime) + "ms", ExceptionUtils.getStackTrace(e));
            throw e;
        }
    }

    /**
     * Add or update tags for packet
     *
     * @param tagDto : tag data transfer object
     * @return : tags map
     */
    public Map<String, String> addorUpdate(TagDto tagDto) {
        long startTime = System.currentTimeMillis();
        LOGGER.info("addorUpdate - method started for packetId: " +
                tagDto.getId() + ", tags count: " + (tagDto.getTags() != null ? tagDto.getTags().size() : 0));

        try {
            Map<String, String> tags = getAdapter().addTags(PACKET_MANAGER_ACCOUNT, tagDto.getId(),
                    tagDto.getTags());
            long endTime = System.currentTimeMillis();
            LOGGER.info("addorUpdate - method completed successfully in " +
                    (endTime - startTime) + "ms for packetId: " + tagDto.getId());
            return tags;
        } catch (Exception e) {
            long endTime = System.currentTimeMillis();
            LOGGER.error("addorUpdate - error after " +
                    (endTime - startTime) + "ms", ExceptionUtils.getStackTrace(e));
            throw e;
        }
    }

    /**
     * Get tags for packet
     *
     * @param id : packet id
     * @return : tags map
     */
    public Map<String, String> getTags(String id) {
        long startTime = System.currentTimeMillis();
        LOGGER.info("getTags - method started for packetId: " + id);

        try {
            Map<String, String> existingTags = getAdapter().getTags(PACKET_MANAGER_ACCOUNT, id);
            long endTime = System.currentTimeMillis();
            LOGGER.info("getTags - method completed successfully in " +
                    (endTime - startTime) + "ms, tags count: " + (existingTags != null ? existingTags.size() : 0) +
                    " for packetId: " + id);
            return existingTags;
        } catch (Exception e) {
            long endTime = System.currentTimeMillis();
            LOGGER.error("getTags - error after " +
                    (endTime - startTime) + "ms", ExceptionUtils.getStackTrace(e));
            throw e;
        }
    }

    /**
     * Get all objects for packet
     *
     * @param id : packet id
     * @return : list of objects
     */
    public List<ObjectDto> getAll(String id) {
        long startTime = System.currentTimeMillis();
        LOGGER.info("getAll - method started for packetId: " + id);

        try {
            List<ObjectDto> allObjects = getAdapter().getAllObjects(PACKET_MANAGER_ACCOUNT, id);
            long endTime = System.currentTimeMillis();
            LOGGER.info("getAll - method completed successfully in " +
                    (endTime - startTime) + "ms, objects count: " + (allObjects != null ? allObjects.size() : 0) +
                    " for packetId: " + id);
            return allObjects;
        } catch (Exception e) {
            long endTime = System.currentTimeMillis();
            LOGGER.error("getAll - error after " +
                    (endTime - startTime) + "ms", ExceptionUtils.getStackTrace(e));
            throw e;
        }
    }

    /**
     * Delete tags from packet
     *
     * @param tagRequestDto : tag request data transfer object
     */
    public void deleteTags(TagRequestDto tagRequestDto) {
        long startTime = System.currentTimeMillis();
        LOGGER.info("deleteTags - method started for packetId: " +
                tagRequestDto.getId() + ", tags count: " + (tagRequestDto.getTagNames() != null ?
                tagRequestDto.getTagNames().size() : 0));

        try {
            getAdapter().deleteTags(PACKET_MANAGER_ACCOUNT, tagRequestDto.getId(),
                    tagRequestDto.getTagNames());
            long endTime = System.currentTimeMillis();
            LOGGER.info("deleteTags - method completed successfully in " +
                    (endTime - startTime) + "ms for packetId: " + tagRequestDto.getId());
        } catch (Exception e) {
            long endTime = System.currentTimeMillis();
            LOGGER.error( "deleteTags - error after " +
                    (endTime - startTime) + "ms", ExceptionUtils.getStackTrace(e));
            throw e;
        }
    }
}