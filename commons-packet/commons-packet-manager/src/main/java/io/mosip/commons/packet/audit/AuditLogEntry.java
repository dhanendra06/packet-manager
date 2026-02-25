package io.mosip.commons.packet.audit;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import io.mosip.kernel.core.util.DateUtils2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import io.mosip.commons.packet.constants.LoggerFileConstant;
import io.mosip.commons.packet.dto.packet.AuditRequestDto;
import io.mosip.commons.packet.util.PacketManagerLogger;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.logger.spi.Logger;


@Component
public class AuditLogEntry {
	/** The logger. */
	private final Logger LOGGER = PacketManagerLogger.getLogger(AuditLogEntry.class);
	@Autowired
	@Lazy
	@Qualifier("selfTokenRestTemplate")
	private RestTemplate restTemplate;
	@Autowired
	private Environment env;
	@Value("${AUDIT_URL:null}")
	private String auditLogUrl;
	private static final String AUDIT_SERVICE_ID = "mosip.commons.packet.manager";
	private static final String APPLICATION_VERSION = "v1";
	private static final String DATETIME_PATTERN = "mosip.utc-datetime-pattern";
	/**
	 * Synchronous audit logging — blocks until the HTTP call completes or fails.
	 * Use this when you need to wait for audit confirmation (rare cases).
	 */
	@SuppressWarnings("unchecked")
	public String addAudit(String description, String eventId,
						   String eventName, String eventType, String moduleId, String moduleName, String id) {
		LOGGER.debug(String.valueOf(LoggerFileConstant.SESSIONID), String.valueOf(LoggerFileConstant.ID), id,
				"AuditLogEntry:: addAudit (sync)::entry");
		String result = addAuditInternal(description, eventId, eventName, eventType,
				moduleId, moduleName, id);
		LOGGER.debug(String.valueOf(LoggerFileConstant.SESSIONID), String.valueOf(LoggerFileConstant.ID), id,
				"AuditLogEntry:: addAudit (sync)::exit");
		return result;
	}
	/**
	 * Asynchronous audit logging — returns immediately, audit is sent in background.
	 * Preferred method for most cases (non-blocking).
	 */
	@Async("auditExecutor")
	public void addAuditAsync(String description, String eventId,
							  String eventName, String eventType,
							  String moduleId, String moduleName, String id) {
		LOGGER.debug(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
				"AuditLogEntry:: addAuditAsync::entry");
		addAuditInternal(description, eventId, eventName, eventType,
				moduleId, moduleName, id);
		LOGGER.debug(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
				"AuditLogEntry:: addAuditAsync::exit");
	}
	/**
	 * Shared internal logic for both sync and async calls.
	 * Returns the response body (for sync) or null (for async — ignored).
	 */
	private String addAuditInternal(String description, String eventId,
									String eventName, String eventType,
									String moduleId, String moduleName, String id) {
		AuditRequestDto auditRequestDto = new AuditRequestDto();
		RequestWrapper<AuditRequestDto> requestWrapper = new RequestWrapper<>();
		ResponseEntity<String> responseWrapper = null;
		try {
			auditRequestDto.setDescription(description);
			auditRequestDto.setActionTimeStamp(DateUtils2.getUTCCurrentDateTimeString());
			auditRequestDto.setApplicationId(LoggerFileConstant.MOSIP_4.toString());
			auditRequestDto.setApplicationName(LoggerFileConstant.PACKET_MANAGER.toString());
			auditRequestDto.setCreatedBy(LoggerFileConstant.SYSTEM.toString());
			auditRequestDto.setEventId(eventId);
			auditRequestDto.setEventName(eventName);
			auditRequestDto.setEventType(eventType);
			auditRequestDto.setHostIp(ServerUtil.getServerUtilInstance().getServerIp());
			auditRequestDto.setHostName(ServerUtil.getServerUtilInstance().getServerName());
			auditRequestDto.setId(id);
			auditRequestDto.setIdType(LoggerFileConstant.ID.toString());
			auditRequestDto.setModuleId(moduleId);
			auditRequestDto.setModuleName(moduleName);
			auditRequestDto.setSessionUserId(LoggerFileConstant.SYSTEM.toString());
			auditRequestDto.setSessionUserName(null);
			requestWrapper.setId(AUDIT_SERVICE_ID);
			requestWrapper.setMetadata(null);
			requestWrapper.setRequest(auditRequestDto);
			DateTimeFormatter format = DateTimeFormatter.ofPattern(env.getProperty(DATETIME_PATTERN));
			LocalDateTime localDateTime = LocalDateTime.parse(
					DateUtils2.getUTCCurrentDateTimeString(env.getProperty(DATETIME_PATTERN)), format);
			requestWrapper.setRequesttime(localDateTime);
			requestWrapper.setVersion(APPLICATION_VERSION);
			HttpEntity<RequestWrapper<AuditRequestDto>> httpEntity = new HttpEntity<>(requestWrapper);
			responseWrapper = restTemplate.exchange(auditLogUrl, HttpMethod.POST, httpEntity, String.class);
			if (responseWrapper != null && responseWrapper.getStatusCode().is2xxSuccessful()) {
				LOGGER.debug(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
						"Audit logged successfully");
			} else {
				LOGGER.warn(String.valueOf(LoggerFileConstant.SESSIONID), LoggerFileConstant.ID, id,
						"Audit response not successful: " +
								(responseWrapper != null ? responseWrapper.getStatusCode() : "null"));
			}
		} catch (Exception e) {
			LOGGER.error(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
					"Audit logging failed: " + ExceptionUtils.getStackTrace(e));
		}
		return responseWrapper != null ? responseWrapper.getBody() : null;
	}
}