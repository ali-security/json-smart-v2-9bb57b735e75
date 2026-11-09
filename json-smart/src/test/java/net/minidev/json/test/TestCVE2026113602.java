package net.minidev.json.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

import org.junit.jupiter.api.Test;

/**
 * CVE-2026-113602: a literal 0x1A char (the internal EOI marker) must not be
 * handled as the end of input by the strict trailing data check.
 */
public class TestCVE2026113602 {

	private static final String[] MALICIOUS = { //
			"{}\u001A{garbage", //
			"{\"a\":1}\u001A{bad}", //
			"[1]\u001Axx", //
			"1\u001Axx", //
			"1.5\u001Axx", //
			"true\u001Afalse", //
			"null\u001Axx", //
			"\"s\"\u001Axx", //
			"{} \u001A garbage", //
			"{}\u001A", //
			"{} \u001A", //
	};

	private static final String[] VALID = { "{}", "[1]", "1", "1.5", "true", "null", "\"s\"", "{\"a\":1}" };

	private static final int[] STRICT_MODES = { JSONParser.MODE_RFC4627, JSONParser.MODE_STRICTEST };

	private static byte[] bytes(String s) {
		return s.getBytes(StandardCharsets.UTF_8);
	}

	@Test
	public void isValidJsonStrictStringRejectsLiteralEOI() {
		for (String s : MALICIOUS)
			assertFalse(JSONValue.isValidJsonStrict(s), "must be invalid: " + s);
	}

	@Test
	public void isValidJsonStrictReaderRejectsLiteralEOI() throws Exception {
		for (String s : MALICIOUS)
			assertFalse(JSONValue.isValidJsonStrict(new StringReader(s)), "must be invalid: " + s);
	}

	@Test
	public void parseStrictStringRejectsLiteralEOI() {
		for (String s : MALICIOUS)
			assertThrows(ParseException.class, () -> JSONValue.parseStrict(s), "must throw: " + s);
	}

	@Test
	public void parseStrictReaderRejectsLiteralEOI() {
		for (String s : MALICIOUS)
			assertThrows(ParseException.class, () -> JSONValue.parseStrict(new StringReader(s)), "must throw: " + s);
	}

	@Test
	public void strictModesRejectLiteralEOIOnAllInputs() {
		for (int mode : STRICT_MODES) {
			for (String s : MALICIOUS) {
				final JSONParser p = new JSONParser(mode);
				assertThrows(ParseException.class, () -> p.parse(s), "String must throw: " + s);
				assertThrows(ParseException.class, () -> p.parse(bytes(s)), "byte[] must throw: " + s);
				assertThrows(ParseException.class, () -> p.parse(new StringReader(s)), "Reader must throw: " + s);
				assertThrows(ParseException.class, () -> p.parse(new ByteArrayInputStream(bytes(s))),
						"InputStream must throw: " + s);
			}
		}
	}

	@Test
	public void literalEOIIsReportedAsUnexpectedToken() {
		String s = "{\"a\":1}\u001A{bad}";
		JSONParser p = new JSONParser(JSONParser.MODE_RFC4627);
		ParseException e = assertThrows(ParseException.class, () -> p.parse(s));
		assertEquals(ParseException.ERROR_UNEXPECTED_TOKEN, e.getErrorType());
		e = assertThrows(ParseException.class, () -> p.parse(bytes(s)));
		assertEquals(ParseException.ERROR_UNEXPECTED_TOKEN, e.getErrorType());
		e = assertThrows(ParseException.class, () -> p.parse(new StringReader(s)));
		assertEquals(ParseException.ERROR_UNEXPECTED_TOKEN, e.getErrorType());
		e = assertThrows(ParseException.class, () -> p.parse(new ByteArrayInputStream(bytes(s))));
		assertEquals(ParseException.ERROR_UNEXPECTED_TOKEN, e.getErrorType());
	}

	@Test
	public void strictModesStillAcceptValidJson() throws Exception {
		for (int mode : STRICT_MODES) {
			JSONParser p = new JSONParser(mode);
			for (String s : VALID) {
				p.parse(s);
				p.parse(bytes(s));
				p.parse(new StringReader(s));
				p.parse(new ByteArrayInputStream(bytes(s)));
				assertTrue(JSONValue.isValidJsonStrict(s), "must be valid: " + s);
				assertTrue(JSONValue.isValidJsonStrict(new StringReader(s)), "must be valid: " + s);
			}
		}
		// trailing spaces are still accepted in RFC4627 mode
		JSONParser p = new JSONParser(JSONParser.MODE_RFC4627);
		assertEquals(new JSONObject(), p.parse("{} "));
		assertEquals(new JSONObject(), p.parse(bytes("{} \n")));
		assertEquals(new JSONObject(), p.parse(new StringReader("{}\t ")));
		assertEquals(new JSONObject(), p.parse(new ByteArrayInputStream(bytes("{}\r\n"))));
	}

	@Test
	public void parserReuseKeepsCheckingLiteralEOI() throws Exception {
		final JSONParser p = new JSONParser(JSONParser.MODE_RFC4627);
		JSONArray a = (JSONArray) p.parse(new StringReader("[1]"));
		assertEquals(1, a.size());
		assertThrows(ParseException.class, () -> p.parse(new StringReader("[1]\u001Axx")));
		a = (JSONArray) p.parse(new StringReader("[1]"));
		assertEquals(1, a.size());
		assertThrows(ParseException.class, () -> p.parse(new ByteArrayInputStream(bytes("[1]\u001Axx"))));
		assertNull(p.parse(new ByteArrayInputStream(bytes("null"))));
	}

	@Test
	public void permissiveModeIsUnchanged() throws Exception {
		// permissive mode accepts trailing data, literal 0x1A included
		JSONParser p = new JSONParser(JSONParser.MODE_PERMISSIVE);
		assertEquals(new JSONObject(), p.parse("{}\u001Agarbage"));
		assertEquals(new JSONObject(), p.parse(new StringReader("{}\u001Agarbage")));
	}
}
