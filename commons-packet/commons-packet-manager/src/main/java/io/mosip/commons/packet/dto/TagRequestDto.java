package io.mosip.commons.packet.dto;

import java.io.Serializable;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@EqualsAndHashCode
@NoArgsConstructor
@AllArgsConstructor
public class TagRequestDto implements Serializable {

	private String id;
	private List<String> tagNames;

	/**
	 * Optional retrieval type. Supported values:
	 * <ul>
	 *   <li>{@code null} / empty — default behaviour (existing flow; backward compatible).</li>
	 *   <li>{@code "anonymous"} — return only the anonymous profile JSON under key {@code "anonymous"}.</li>
	 *   <li>{@code "all"} — return packet tags plus the anonymous file, no filtering.</li>
	 * </ul>
	 */
	private String type;

	/**
	 * Backward-compatible 2-arg constructor. Existing callers that pre-date the
	 * {@code type} field continue to compile and behave exactly as before
	 * ({@code type} defaults to {@code null} — same as the default tag-retrieval flow).
	 * JSON consumers that omit the {@code type} field are unaffected; Jackson leaves
	 * the property null.
	 */
	public TagRequestDto(String id, List<String> tagNames) {
		this.id = id;
		this.tagNames = tagNames;
		this.type = null;
	}
}
