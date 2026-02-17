package id.sigilum.sdk;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.*;

class SigilumRFC9421ConformanceTest {
  private static final ObjectMapper MAPPER = new ObjectMapper();

  @Test
  void rfc9421ProfileVectorsAndStrictChecks() throws Exception {
    Path fixturePath = Path.of("..", "test-vectors", "http-signatures-rfc9421.json");
    JsonNode fixture = MAPPER.readTree(Files.readString(fixturePath, StandardCharsets.UTF_8));
    long created = fixture.get("fixed").get("created").asLong();
    String nonce = fixture.get("fixed").get("nonce").asText();

    String home = System.getProperty("java.io.tmpdir") + "/sigilum-java-" + System.nanoTime();
    Sigilum.InitIdentityOptions init = new Sigilum.InitIdentityOptions();
    init.namespace = "alice";
    init.homeDir = home;
    Sigilum.initIdentity(init);
    Sigilum.SigilumIdentity identity = Sigilum.loadIdentity(new Sigilum.LoadIdentityOptions("alice", home));

    Iterator<JsonNode> vectors = fixture.get("vectors").elements();
    while (vectors.hasNext()) {
      JsonNode vector = vectors.next();
      String name = vector.get("name").asText();
      String bodyValue = vector.get("body").isNull() ? null : vector.get("body").asText();

      Sigilum.SignRequestInput input = new Sigilum.SignRequestInput();
      input.url = vector.get("url").asText();
      input.method = vector.get("method").asText();
      input.body = bodyValue == null ? null : bodyValue.getBytes(StandardCharsets.UTF_8);
      input.created = created;
      input.nonce = nonce;

      Sigilum.SignedRequest signed = Sigilum.signHttpRequest(identity, input);
      assertEquals(vector.get("expected_target_uri").asText(), signed.url, name + ": target URI");

      String signatureInput = signed.headers.get("signature-input");
      assertNotNull(signatureInput, name + ": missing signature-input");
      assertTrue(signatureInput.contains("created=" + created), name + ": created mismatch");
      assertTrue(signatureInput.contains("nonce=\"" + nonce + "\""), name + ": nonce mismatch");

      StringBuilder expectedComponents = new StringBuilder("(");
      Iterator<JsonNode> components = vector.get("expected_components").elements();
      boolean first = true;
      while (components.hasNext()) {
        if (!first) expectedComponents.append(" ");
        expectedComponents.append("\"").append(components.next().asText()).append("\"");
        first = false;
      }
      expectedComponents.append(")");
      assertTrue(signatureInput.contains(expectedComponents), name + ": component list mismatch");

      if (vector.has("expected_content_digest")) {
        assertEquals(vector.get("expected_content_digest").asText(), signed.headers.get("content-digest"), name + ": digest");
      }

      Sigilum.VerifySignatureInput verify = new Sigilum.VerifySignatureInput();
      verify.url = signed.url;
      verify.method = signed.method;
      verify.headers = signed.headers;
      verify.body = signed.body;
      verify.expectedNamespace = "alice";
      verify.nowEpochSeconds = created + 5;
      verify.maxAgeSeconds = 60L;
      verify.seenNonces = new HashSet<>();

      Sigilum.VerifySignatureResult ok = Sigilum.verifyHttpSignature(verify);
      assertTrue(ok.valid, name + ": strict verify should pass");

      Sigilum.VerifySignatureResult replay = Sigilum.verifyHttpSignature(verify);
      assertFalse(replay.valid, name + ": replay should fail");
      assertNotNull(replay.reason);
      assertTrue(replay.reason.toLowerCase().contains("replay"), name + ": replay reason");

      Sigilum.VerifySignatureInput staleVerify = new Sigilum.VerifySignatureInput();
      staleVerify.url = signed.url;
      staleVerify.method = signed.method;
      staleVerify.headers = signed.headers;
      staleVerify.body = signed.body;
      staleVerify.expectedNamespace = "alice";
      staleVerify.nowEpochSeconds = created + 500;
      staleVerify.maxAgeSeconds = 60L;

      Sigilum.VerifySignatureResult stale = Sigilum.verifyHttpSignature(staleVerify);
      assertFalse(stale.valid, name + ": stale should fail");
      assertNotNull(stale.reason);
      String staleReason = stale.reason.toLowerCase();
      assertTrue(staleReason.contains("expired") || staleReason.contains("valid"), name + ": stale reason");
    }
  }
}
