package io.mosip.commons.packetmanager.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import io.mosip.commons.packet.constants.PacketUtilityErrorCodes;
import io.mosip.commons.packet.dto.TagDeleteResponseDto;
import io.mosip.commons.packet.dto.TagDto;
import io.mosip.commons.packet.dto.TagRequestDto;
import io.mosip.commons.packet.dto.TagResponseDto;
import io.mosip.commons.packet.exception.TagCreationException;
import io.mosip.commons.packet.exception.TagDeletionException;
import io.mosip.commons.packet.facade.PacketReader;
import io.mosip.commons.packet.facade.PacketWriter;
import io.mosip.commons.packet.util.PacketManagerLogger;
import io.mosip.kernel.core.exception.BaseCheckedException;
import io.mosip.kernel.core.exception.BaseUncheckedException;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.logger.spi.Logger;

@Component
public class PacketWriterService {
    private static Logger LOGGER = PacketManagerLogger.getLogger(PacketWriterService.class);
    
    @Autowired
    private PacketReader packetReader;
    
    @Autowired
    private PacketWriter packetWriter;
    
    
    public TagResponseDto addTags(TagDto tagDto) {
    	try {

			Map<String, String> existingTags = packetReader.getTags(tagDto.getId());
				for (Entry<String, String> entry : tagDto.getTags().entrySet()) {
					if (existingTags.containsKey(entry.getKey())) {

						throw new TagCreationException(PacketUtilityErrorCodes.TAG_ALREADY_EXIST.getErrorCode(),
								PacketUtilityErrorCodes.TAG_ALREADY_EXIST.getErrorMessage());
				}
				}

			Map<String, String> tags = packetWriter.addTags(tagDto,tagDto.getId());
			TagResponseDto tagResponseDto = new TagResponseDto();
			tagResponseDto.setTags(tags);
			return tagResponseDto;
		} catch (Exception e) {
				LOGGER.error(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, tagDto.getId(),
						ExceptionUtils.getStackTrace(e));
				if (e instanceof BaseCheckedException) {
					BaseCheckedException ex = (BaseCheckedException) e;
					throw new TagCreationException(ex.getErrorCode(), ex.getMessage());
				} else if (e instanceof BaseUncheckedException) {
					BaseUncheckedException ex = (BaseUncheckedException) e;
					throw new TagCreationException(ex.getErrorCode(), ex.getMessage());
				}
				throw new TagCreationException(e.getMessage());

			}
    }
    
    /** Reserved tag key that, when supplied to addOrUpdate, is intercepted and
     *  routed to the object store as the {@code anonymous.json} file.
     *  Callers can include this key alongside regular tags; the anonymous value
     *  is removed from the tag set before the rest is persisted as tags, so
     *  pre-existing tag-only flows continue to work unchanged. */
    private static final String ANONYMOUS_TAG_KEY = "anonymous";

    public TagResponseDto updateTags(TagDto tagDto) {
    	try {
			// Intercept the "anonymous" entry (if present): write its value to the
			// object store as a file and strip it from the tags map so it is NOT
			// persisted in the tag table. Existing callers that don't use this key
			// see no behaviour change.
			Map<String, String> incomingTags = tagDto.getTags();
			if (incomingTags != null && incomingTags.containsKey(ANONYMOUS_TAG_KEY)) {
				String anonymousJson = incomingTags.get(ANONYMOUS_TAG_KEY);
				if (anonymousJson != null) {
					packetWriter.putAnonymousProfile(tagDto.getId(), anonymousJson);
				}
				// Work on a copy so we don't mutate the caller's map
				Map<String, String> sanitized = new HashMap<>(incomingTags);
				sanitized.remove(ANONYMOUS_TAG_KEY);
				tagDto.setTags(sanitized);
			}

			Map<String, String> newTags = new HashMap<String, String>();
			Map<String, String> existingTags = packetReader.getTags(tagDto.getId());
			if (existingTags.isEmpty()) {
				newTags.putAll(tagDto.getTags());
			} else {
				for (Entry<String, String> entry : tagDto.getTags().entrySet()) {
					if (existingTags.containsKey(entry.getKey())) {
                        if(!existingTags.get(entry.getKey()).equalsIgnoreCase(entry.getValue()))
                         newTags.put(entry.getKey(), entry.getValue());
					} else {
						newTags.put(entry.getKey(), entry.getValue());
					}
				}
			}
			TagResponseDto tagResponseDto = new TagResponseDto();

			if (newTags.isEmpty()) {
				tagResponseDto.setTags(tagDto.getTags());
			} else {
				tagDto.setTags(newTags);
				Map<String, String> tags = packetWriter.addTags(tagDto, tagDto.getId());
				tagResponseDto.setTags(tags);
			}

			return tagResponseDto;
		} catch (Exception e) {
				LOGGER.error(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, tagDto.getId(),
						ExceptionUtils.getStackTrace(e));
				if (e instanceof BaseCheckedException) {
					BaseCheckedException ex = (BaseCheckedException) e;
					throw new TagCreationException(ex.getErrorCode(), ex.getMessage());
				} else if (e instanceof BaseUncheckedException) {
					BaseUncheckedException ex = (BaseUncheckedException) e;
					throw new TagCreationException(ex.getErrorCode(), ex.getMessage());
				}
				throw new TagCreationException(e.getMessage());

			}
    	
    }
    
    public TagDeleteResponseDto deleteTags(TagRequestDto tagRequestDto) {
    	try {
    		List<String> deleteTags = new ArrayList<String>();
			Map<String, String> existingTags = packetReader.getTags(tagRequestDto.getId());

				for (String tagName : tagRequestDto.getTagNames()) {
					if (existingTags.containsKey(tagName)) {
						deleteTags.add(tagName);
					} 
				}
			TagDeleteResponseDto tagDeleteResponseDto = new TagDeleteResponseDto();
			if (!deleteTags.isEmpty()) {
				tagRequestDto.setTagNames(deleteTags);
				packetWriter.deleteTags(tagRequestDto,tagRequestDto.getId());
			}

			tagDeleteResponseDto.setStatus("Deleted Successfully");
			return tagDeleteResponseDto;

		} catch (Exception e) {
			LOGGER.error(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, tagRequestDto.getId(),
					ExceptionUtils.getStackTrace(e));
			if (e instanceof BaseCheckedException) {
				BaseCheckedException ex = (BaseCheckedException) e;
				throw new TagDeletionException(ex.getErrorCode(), ex.getMessage());
			} else if (e instanceof BaseUncheckedException) {
				BaseUncheckedException ex = (BaseUncheckedException) e;
				throw new TagDeletionException(ex.getErrorCode(), ex.getMessage());
			}
			throw new TagDeletionException(e.getMessage());

		}
    	
    }
}
