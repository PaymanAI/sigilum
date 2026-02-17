package id.sigilum.sdk;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SigilumTest {
  @Test
  void initAndLoadIdentity() {
    String home = System.getProperty("java.io.tmpdir") + "/sigilum-java-" + System.nanoTime();

    Sigilum.InitIdentityOptions options = new Sigilum.InitIdentityOptions();
    options.namespace = "alice";
    options.homeDir = home;

    Sigilum.InitIdentityResult created = Sigilum.initIdentity(options);
    assertTrue(created.created);
    assertEquals("alice", created.namespace);

    Sigilum.InitIdentityResult reused = Sigilum.initIdentity(options);
    assertFalse(reused.created);
    assertEquals(created.publicKey, reused.publicKey);

    Sigilum.LoadIdentityOptions load = new Sigilum.LoadIdentityOptions("alice", home);
    Sigilum.SigilumIdentity identity = Sigilum.loadIdentity(load);
    assertEquals("alice", identity.namespace);
  }

  @Test
  void signAndVerify() {
    String home = System.getProperty("java.io.tmpdir") + "/sigilum-java-" + System.nanoTime();

    Sigilum.InitIdentityOptions init = new Sigilum.InitIdentityOptions();
    init.namespace = "alice";
    init.homeDir = home;
    Sigilum.initIdentity(init);

    Sigilum.SigilumIdentity identity = Sigilum.loadIdentity(new Sigilum.LoadIdentityOptions("alice", home));

    Sigilum.SignRequestInput input = new Sigilum.SignRequestInput();
    input.url = "https://api.sigilum.local/v1/namespaces/alice/claims";
    input.method = "POST";
    input.headers = Map.of("content-type", "application/json");
    input.body = "{\"action\":\"approve\"}".getBytes();

    Sigilum.SignedRequest signed = Sigilum.signHttpRequest(identity, input);

    Sigilum.VerifySignatureInput verify = new Sigilum.VerifySignatureInput();
    verify.url = signed.url;
    verify.method = signed.method;
    verify.headers = signed.headers;
    verify.body = signed.body;
    verify.expectedNamespace = "alice";

    Sigilum.VerifySignatureResult result = Sigilum.verifyHttpSignature(verify);
    assertTrue(result.valid, result.reason);
  }
}
