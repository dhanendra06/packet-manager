package io.mosip.commons.packet.test.impl;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.commons.packet.dto.packet.CryptomanagerResponseDto;
import io.mosip.commons.packet.dto.packet.DecryptResponseDto;
import io.mosip.commons.packet.exception.ApiNotAccessibleException;
import io.mosip.commons.packet.exception.PacketDecryptionFailureException;
import io.mosip.commons.packet.exception.SignatureException;
import io.mosip.commons.packet.impl.OnlinePacketCryptoServiceImpl;
import io.mosip.commons.packet.util.ZipUtils;
import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.JsonUtils;
import org.apache.commons.io.IOUtils;
import org.assertj.core.util.Lists;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.context.annotation.PropertySource;
import org.springframework.http.HttpHeaders;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.format.DateTimeParseException;
import java.util.*;

import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ZipUtils.class, IOUtils.class, JsonUtils.class})
@PropertySource("classpath:application-test.properties")
@PowerMockIgnore({"com.sun.org.apache.xerces.*", "javax.xml.*", "org.xml.*", "javax.management.*"})
public class OnlinePacketCryptoServiceTest {

    private static final String ID = "10001100770000320200720092256";

    @InjectMocks
    private OnlinePacketCryptoServiceImpl onlinePacketCryptoService;

    @Mock
    private WebClient webClient;

    @Mock
    private WebClient.RequestBodyUriSpec requestBodyUriSpec;

    @Mock
    private WebClient.RequestBodySpec requestBodySpec;

    @Mock
    @SuppressWarnings("rawtypes")
    private WebClient.RequestHeadersSpec requestHeadersSpec;

    @Mock
    private WebClient.ResponseSpec responseSpec;

    @Mock
    @SuppressWarnings("rawtypes")
    private WebClient.RequestHeadersUriSpec requestHeadersUriSpec;

    @Mock
    private ObjectMapper mapper;

    @Before
    @SuppressWarnings("unchecked")
    public void setup() {
        ReflectionTestUtils.setField(onlinePacketCryptoService, "DATETIME_PATTERN", "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        ReflectionTestUtils.setField(onlinePacketCryptoService, "APPLICATION_VERSION", "v1");
        ReflectionTestUtils.setField(onlinePacketCryptoService, "cryptomanagerDecryptUrl", "http://localhost");
        ReflectionTestUtils.setField(onlinePacketCryptoService, "cryptomanagerEncryptUrl", "http://localhost");
        ReflectionTestUtils.setField(onlinePacketCryptoService, "syncdataGetTpmKeyUrl", "http://localhost/");

        // POST chain: post() → uri() → bodyValue() → retrieve() → bodyToMono()
        when(webClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(anyString())).thenReturn(requestBodySpec);
        when(requestBodySpec.bodyValue(any())).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);

        // GET chain: get() → uri() → (reuses requestHeadersSpec) → retrieve() → bodyToMono()
        when(webClient.get()).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.uri(anyString())).thenReturn(requestHeadersSpec);
    }

    @Test
    public void signTest() throws IOException {
        String expected = "signature";
        LinkedHashMap<String, Object> submap = new LinkedHashMap<>();
        submap.put("data", CryptoUtil.encodeToURLSafeBase64(expected.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<String, Object> responseMap = new LinkedHashMap<>();
        responseMap.put("response", submap);

        ReflectionTestUtils.setField(onlinePacketCryptoService, "keymanagerCsSignUrl", "localhost");

        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just("hello"));
        when(mapper.readValue(anyString(), any(Class.class))).thenReturn(responseMap);

        byte[] result = onlinePacketCryptoService.sign("packet".getBytes());
        assertTrue(Arrays.equals(expected.getBytes(), result));
    }

    @Test(expected = SignatureException.class)
    public void signExceptionTest() throws IOException {
        byte[] packet = "packet".getBytes();
        ReflectionTestUtils.setField(onlinePacketCryptoService, "keymanagerCsSignUrl", "localhost");

        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just("hello"));
        when(mapper.readValue(anyString(), any(Class.class))).thenThrow(new JsonMappingException("exception"));

        onlinePacketCryptoService.sign(packet);
    }

    @Test
    public void encryptTest() throws IOException {
        byte[] packet = "10001100770000320200720092256_packetwithsignatureandaad".getBytes();
        CryptomanagerResponseDto cryptomanagerResponseDto = new CryptomanagerResponseDto();
        cryptomanagerResponseDto.setErrors(null);
        DecryptResponseDto decryptResponseDto = new DecryptResponseDto("packet");
        cryptomanagerResponseDto.setResponse(decryptResponseDto);

        ReflectionTestUtils.setField(onlinePacketCryptoService, "cryptomanagerEncryptUrl", "localhost");

        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just("hello"));
        when(mapper.readValue(anyString(), any(Class.class))).thenReturn(cryptomanagerResponseDto);

        byte[] result = onlinePacketCryptoService.encrypt(ID, packet);
        assertNotNull(result);
    }

    @Test(expected = ApiNotAccessibleException.class)
    public void encryptExceptionTest() throws IOException {
        byte[] packet = "packet".getBytes();
        ReflectionTestUtils.setField(onlinePacketCryptoService, "cryptomanagerEncryptUrl", "localhost");

        WebClientResponseException ex = WebClientResponseException.create(
                400, "Bad Request", HttpHeaders.EMPTY, "error".getBytes(), StandardCharsets.UTF_8);
        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.error(ex));

        onlinePacketCryptoService.encrypt(ID, packet);
    }

    @Test
    public void decryptTest() throws IOException {
        byte[] packet = "10001100770000320200720092256_packetwithsignatureandaad".getBytes();
        CryptomanagerResponseDto cryptomanagerResponseDto = new CryptomanagerResponseDto();
        cryptomanagerResponseDto.setErrors(null);
        DecryptResponseDto decryptResponseDto = new DecryptResponseDto(
                CryptoUtil.encodeToURLSafeBase64("packet".getBytes()));
        cryptomanagerResponseDto.setResponse(decryptResponseDto);

        ReflectionTestUtils.setField(onlinePacketCryptoService, "cryptomanagerDecryptUrl", "localhost");

        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just("hello"));
        when(mapper.readValue(anyString(), any(Class.class))).thenReturn(cryptomanagerResponseDto);

        byte[] result = onlinePacketCryptoService.decrypt(ID, packet);
        assertNotNull(result);
    }

    @Test(expected = ApiNotAccessibleException.class)
    public void decryptExceptionTest() throws IOException {
        // packet must be >= GCM_NONCE_LENGTH(12) + GCM_AAD_LENGTH(32) = 44 bytes
        byte[] packet = new byte[44];
        ReflectionTestUtils.setField(onlinePacketCryptoService, "cryptomanagerDecryptUrl", "localhost");

        WebClientResponseException ex = WebClientResponseException.create(
                400, "Bad Request", HttpHeaders.EMPTY, "error".getBytes(), StandardCharsets.UTF_8);
        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.error(ex));

        onlinePacketCryptoService.decrypt(ID, packet);
    }

    @Test
    public void verifyTest() throws IOException {
        byte[] packet = "packet".getBytes();

        LinkedHashMap<String, Object> publicKeyInner = new LinkedHashMap<>();
        publicKeyInner.put("signingPublicKey", "testPublicKey");
        LinkedHashMap<String, Object> publicKeyResponse = new LinkedHashMap<>();
        publicKeyResponse.put("response", publicKeyInner);

        LinkedHashMap<String, Object> verifyInner = new LinkedHashMap<>();
        verifyInner.put("verified", true);
        LinkedHashMap<String, Object> verifyResponse = new LinkedHashMap<>();
        verifyResponse.put("response", verifyInner);

        ReflectionTestUtils.setField(onlinePacketCryptoService, "keymanagerCsverifysignUrl", "localhost");
        ReflectionTestUtils.setField(onlinePacketCryptoService, "syncdataGetTpmKeyUrl", "http://localhost/");

        // First call: GET for public key; second call: POST for verify
        when(responseSpec.bodyToMono(String.class))
                .thenReturn(Mono.just("getKeyResponse"))
                .thenReturn(Mono.just("verifyResponse"));
        when(mapper.readValue(anyString(), any(Class.class)))
                .thenReturn(publicKeyResponse)
                .thenReturn(verifyResponse);

        boolean result = onlinePacketCryptoService.verify("10077_10077", packet, "signature".getBytes());
        assertTrue(result);
    }

    /**
     * Tests encrypt method when cryptomanager returns error response - should throw PacketDecryptionFailureException
     */
    @Test
    public void testEncrypt_WhenCryptomanagerReturnsError_ThrowsPacketDecryptionFailureException() throws IOException {
        byte[] packet = "test-packet".getBytes();
        String refId = "test-ref-id";

        CryptomanagerResponseDto errorResponse = new CryptomanagerResponseDto();
        List<ServiceError> errors = new ArrayList<>();
        ServiceError serviceError = new ServiceError();
        serviceError.setMessage("Encryption failed due to invalid data");
        errors.add(serviceError);
        errorResponse.setErrors(errors);

        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just("error-response"));
        when(mapper.readValue(anyString(), eq(CryptomanagerResponseDto.class))).thenReturn(errorResponse);

        assertThrows(PacketDecryptionFailureException.class, () -> {
            onlinePacketCryptoService.encrypt(refId, packet);
        });
    }

    /**
     * Tests encrypt method when response is null - should throw PacketDecryptionFailureException
     */
    @Test
    public void testEncrypt_WhenResponseIsNull_ThrowsPacketDecryptionFailureException() throws IOException {
        byte[] packet = "test-packet".getBytes();
        String refId = "test-ref-id";

        CryptomanagerResponseDto nullResponse = new CryptomanagerResponseDto();
        nullResponse.setResponse(null);
        nullResponse.setErrors(null);

        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just("null-response"));
        when(mapper.readValue(anyString(), eq(CryptomanagerResponseDto.class))).thenReturn(nullResponse);

        assertThrows(PacketDecryptionFailureException.class, () -> {
            onlinePacketCryptoService.encrypt(refId, packet);
        });
    }

    /**
     * Tests encrypt method when WebClient response error occurs - should throw ApiNotAccessibleException
     */
    @Test
    public void testEncrypt_WhenHttpClientError_ThrowsApiNotAccessibleException() {
        byte[] packet = "test-packet".getBytes();
        String refId = "test-ref-id";

        WebClientResponseException ex = WebClientResponseException.create(
                400, "Bad Request", HttpHeaders.EMPTY, "error".getBytes(), StandardCharsets.UTF_8);
        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.error(ex));

        assertThrows(ApiNotAccessibleException.class, () -> {
            onlinePacketCryptoService.encrypt(refId, packet);
        });
    }

    /**
     * Tests verify method when WebClient response error occurs - should throw SignatureException
     */
    @Test(expected = SignatureException.class)
    public void testVerify_WhenWebClientException_ThrowsSignatureException() throws IOException {
        String refId = "10077_10077";
        byte[] packet = "packet".getBytes();
        byte[] signature = "signature".getBytes();

        WebClientResponseException ex = WebClientResponseException.create(
                500, "Internal Server Error", HttpHeaders.EMPTY, "error".getBytes(), StandardCharsets.UTF_8);
        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.error(ex));

        onlinePacketCryptoService.verify(refId, packet, signature);
    }

    /**
     * Tests decrypt method when date time parse exception occurs - should throw PacketDecryptionFailureException
     */
    @Test(expected = PacketDecryptionFailureException.class)
    public void testDecrypt_WhenDateTimeParseException_ThrowsPacketDecryptionFailureException() throws IOException {
        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just("response"));
        doThrow(new DateTimeParseException("Invalid date", "2023-13-45", 0))
                .when(mapper).readValue(anyString(), any(Class.class));

        onlinePacketCryptoService.decrypt(ID, "packet".getBytes());
    }

    /**
     * Tests decrypt method when cryptomanager returns error response - should throw PacketDecryptionFailureException
     */
    @Test
    public void testDecrypt_WhenCryptomanagerReturnsError_ThrowsPacketDecryptionFailureException() throws IOException {
        CryptomanagerResponseDto errorResponse = new CryptomanagerResponseDto();
        List<ServiceError> errors = new ArrayList<>();
        ServiceError error = new ServiceError();
        error.setMessage("Decryption failed");
        errors.add(error);
        errorResponse.setErrors(errors);

        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just("response"));
        when(mapper.readValue(anyString(), eq(CryptomanagerResponseDto.class))).thenReturn(errorResponse);

        assertThrows(PacketDecryptionFailureException.class, () -> {
            onlinePacketCryptoService.decrypt(ID, "packet".getBytes());
        });
    }

    /**
     * Tests encrypt method when IO exception occurs - should throw PacketDecryptionFailureException
     */
    @Test(expected = PacketDecryptionFailureException.class)
    public void testEncrypt_WhenIOException_ThrowsPacketDecryptionFailureException() throws Exception {
        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just("response"));
        when(mapper.readValue(anyString(), eq(CryptomanagerResponseDto.class)))
                .thenThrow(new RuntimeException(new IOException("IO error")));

        onlinePacketCryptoService.encrypt("refId", "test".getBytes());
    }

    /**
     * Tests encrypt method when date time parse exception occurs - should throw PacketDecryptionFailureException
     */
    @Test(expected = PacketDecryptionFailureException.class)
    public void testEncrypt_WhenDateTimeParseException_ThrowsPacketDecryptionFailureException() throws Exception {
        ReflectionTestUtils.setField(onlinePacketCryptoService, "DATETIME_PATTERN", "invalid-pattern");

        onlinePacketCryptoService.encrypt("refId", "test".getBytes());
    }

    /**
     * Tests encrypt method when cryptomanager returns error in response - should throw PacketDecryptionFailureException
     */
    @Test(expected = PacketDecryptionFailureException.class)
    public void testEncrypt_WhenErrorInResponse_ThrowsPacketDecryptionFailureException() throws Exception {
        CryptomanagerResponseDto responseDto = new CryptomanagerResponseDto();
        ServiceError error = new ServiceError("ERROR_CODE", "Error message");
        responseDto.setErrors(Lists.newArrayList(error));

        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just("response"));
        when(mapper.readValue(anyString(), eq(CryptomanagerResponseDto.class))).thenReturn(responseDto);

        onlinePacketCryptoService.encrypt("refId", "test".getBytes());
    }

    /**
     * Tests encrypt method when WebClientResponseException occurs - should throw ApiNotAccessibleException
     */
    @Test(expected = ApiNotAccessibleException.class)
    public void testEncrypt_WhenWebClientResponseException_ThrowsApiNotAccessibleException() throws Exception {
        WebClientResponseException ex = WebClientResponseException.create(
                400, "Bad Request", HttpHeaders.EMPTY, "error body".getBytes(), StandardCharsets.UTF_8);
        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.error(ex));

        onlinePacketCryptoService.encrypt("refId", "test".getBytes());
    }

    /**
     * Tests encrypt method when WebClientResponseException (5xx) occurs - should throw ApiNotAccessibleException
     */
    @Test(expected = ApiNotAccessibleException.class)
    public void testEncrypt_WhenWebClientServerException_ThrowsApiNotAccessibleException() throws Exception {
        WebClientResponseException ex = WebClientResponseException.create(
                500, "Internal Server Error", HttpHeaders.EMPTY, "error body".getBytes(), StandardCharsets.UTF_8);
        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.error(ex));

        onlinePacketCryptoService.encrypt("refId", "test".getBytes());
    }

    /**
     * Tests decrypt method when IO exception occurs - should throw PacketDecryptionFailureException
     */
    @Test(expected = PacketDecryptionFailureException.class)
    public void testDecrypt_WhenIOException_ThrowsPacketDecryptionFailureException() throws Exception {
        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just("response"));
        when(mapper.readValue(anyString(), eq(CryptomanagerResponseDto.class)))
                .thenThrow(new RuntimeException(new IOException("IO error")));

        byte[] packet = new byte[32];
        onlinePacketCryptoService.decrypt("refId", packet);
    }

    /**
     * Tests decrypt method when cryptomanager returns error in response - should throw PacketDecryptionFailureException
     */
    @Test(expected = PacketDecryptionFailureException.class)
    public void testDecrypt_WhenErrorInResponse_ThrowsPacketDecryptionFailureException() throws Exception {
        CryptomanagerResponseDto responseDto = new CryptomanagerResponseDto();
        ServiceError error = new ServiceError("ERROR_CODE", "Error message");
        responseDto.setErrors(Lists.newArrayList(error));

        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just("response"));
        when(mapper.readValue(anyString(), eq(CryptomanagerResponseDto.class))).thenReturn(responseDto);

        byte[] packet = new byte[32];
        onlinePacketCryptoService.decrypt("refId", packet);
    }

    /**
     * Tests verify method when public key response is empty - should throw SignatureException
     */
    @Test(expected = SignatureException.class)
    public void testVerify_WhenPublicKeyResponseEmpty_ThrowsSignatureException() throws Exception {
        LinkedHashMap<String, Object> emptyResponse = new LinkedHashMap<>();

        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just("{}"));
        when(mapper.readValue(anyString(), eq(LinkedHashMap.class))).thenReturn(emptyResponse);

        onlinePacketCryptoService.verify("center_machine", "data".getBytes(), "signature".getBytes());
    }

    /**
     * Tests encrypt method when response data is null - should return null
     */
    @Test
    public void testEncrypt_WhenResponseDataIsNull_ReturnsNull() throws IOException {
        CryptomanagerResponseDto responseDto = new CryptomanagerResponseDto();
        DecryptResponseDto decryptResponse = new DecryptResponseDto();
        decryptResponse.setData(null);
        responseDto.setResponse(decryptResponse);
        responseDto.setErrors(null);

        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just("response"));
        when(mapper.readValue(anyString(), eq(CryptomanagerResponseDto.class))).thenReturn(responseDto);

        byte[] result = onlinePacketCryptoService.encrypt("refId", "test".getBytes());
        assertNull(result);
    }

    /**
     * Tests verify method when verify response is empty - should throw SignatureException
     */
    @Test(expected = SignatureException.class)
    public void testVerify_WhenVerifyResponseEmpty_ThrowsSignatureException() throws IOException {
        // Public key response has no "response" wrapper → getPublicKey() throws SignatureException
        LinkedHashMap<String, Object> noWrapperResponse = new LinkedHashMap<>();
        noWrapperResponse.put("signingPublicKey", "publicKey");

        when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just("response"));
        when(mapper.readValue(anyString(), eq(LinkedHashMap.class))).thenReturn(noWrapperResponse);

        onlinePacketCryptoService.verify("center_machine", "data".getBytes(), "signature".getBytes());
    }
}
