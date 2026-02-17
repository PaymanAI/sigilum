package id.sigilum.sdk;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Sigilum {
  private Sigilum() {}

  public static final int IDENTITY_RECORD_VERSION = 1;
  public static final int CERTIFICATE_VERSION = 1;
  public static final String IDENTITIES_DIR = "identities";
  public static final String DEFAULT_API_BASE_URL = "https://api.sigilum.id";

  private static final Pattern NAMESPACE_PATTERN = Pattern.compile("^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$");
  private static final Pattern SIGNATURE_INPUT_PATTERN = Pattern.compile(
      "^sig1=\\(([^)]*)\\);created=(\\d+);keyid=\"([^\"]+)\";alg=\"([^\"]+)\";nonce=\"([^\"]+)\"$");
  private static final Pattern SIGNATURE_PATTERN = Pattern.compile("^sig1=:([^:]+):$");
  private static final byte[] ED25519_X509_PREFIX = hex("302a300506032b6570032100");
  private static final byte[] ED25519_PKCS8_PREFIX = hex("302e020100300506032b657004220420");

  private static final ObjectMapper MAPPER = new ObjectMapper();

  public static String defaultSigilumHome() {
    return Paths.get(System.getProperty("user.home"), ".sigilum").toString();
  }

  public static String getNamespaceApiBase(String apiBaseUrl, String namespace) {
    return trimRightSlash(apiBaseUrl) + "/v1/namespaces/" + urlEncode(namespace);
  }

  public static InitIdentityResult init(InitIdentityOptions options) {
    return initIdentity(options);
  }

  public static InitIdentityResult init(String namespace) {
    InitIdentityOptions options = new InitIdentityOptions();
    options.namespace = namespace;
    return initIdentity(options);
  }

  public static InitIdentityResult initIdentity(InitIdentityOptions options) {
    String namespace = normalizeNamespace(options.namespace);
    String homeDir = getHomeDir(options.homeDir);
    Path identityPath = identityPath(homeDir, namespace);

    if (Files.exists(identityPath) && !options.force) {
      SigilumIdentity loaded = loadIdentity(new LoadIdentityOptions(namespace, homeDir));
      InitIdentityResult result = new InitIdentityResult();
      result.namespace = loaded.namespace;
      result.did = loaded.did;
      result.keyId = loaded.keyId;
      result.publicKey = loaded.publicKey;
      result.created = false;
      result.homeDir = homeDir;
      result.identityPath = identityPath.toString();
      return result;
    }

    IdentityRecord record = createIdentityRecord(namespace);
    writeIdentityRecord(homeDir, namespace, record);

    InitIdentityResult result = new InitIdentityResult();
    result.namespace = record.namespace;
    result.did = record.did;
    result.keyId = record.keyId;
    result.publicKey = record.publicKey;
    result.created = true;
    result.homeDir = homeDir;
    result.identityPath = identityPath.toString();
    return result;
  }

  public static List<String> listNamespaces(String explicitHomeDir) {
    String homeDir = getHomeDir(explicitHomeDir);
    Path root = Paths.get(homeDir, IDENTITIES_DIR);
    if (!Files.exists(root)) {
      return new ArrayList<>();
    }
    try {
      List<String> namespaces = new ArrayList<>();
      try (Stream<Path> paths = Files.list(root)) {
        paths
            .filter(Files::isDirectory)
            .forEach(path -> {
              Path identity = path.resolve("identity.json");
              if (Files.exists(identity)) {
                namespaces.add(path.getFileName().toString());
              }
            });
      }
      namespaces.sort(Comparator.naturalOrder());
      return namespaces;
    } catch (IOException e) {
      throw new IllegalStateException("Failed to list namespaces", e);
    }
  }

  public static SigilumIdentity loadIdentity(LoadIdentityOptions options) {
    String homeDir = getHomeDir(options.homeDir);
    String namespace = resolveNamespace(options.namespace, homeDir);
    Path identityPath = identityPath(homeDir, namespace);

    if (!Files.exists(identityPath)) {
      throw new IllegalArgumentException(
          "Sigilum identity not found for namespace '" + namespace + "' at " + identityPath +
              ". Run `sigilum init " + namespace + "` first.");
    }

    IdentityRecord record;
    try {
      record = MAPPER.readValue(Files.readString(identityPath), IdentityRecord.class);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to parse identity file " + identityPath, e);
    }

    if (record.version != IDENTITY_RECORD_VERSION) {
      throw new IllegalArgumentException("Unsupported identity record version: " + record.version);
    }

    if (record.namespace == null || record.did == null || record.keyId == null || record.publicKey == null ||
        record.privateKey == null || record.certificate == null) {
      throw new IllegalArgumentException("Identity file is missing required fields: " + identityPath);
    }

    SigilumCertificate certificate = record.certificate;
    if (!verifyCertificate(certificate)) {
      throw new IllegalArgumentException("Identity certificate verification failed: " + identityPath);
    }

    if (!namespace.equals(record.namespace)) {
      throw new IllegalArgumentException("Identity namespace mismatch in " + identityPath);
    }

    if (!namespace.equals(certificate.namespace) ||
        !record.did.equals(certificate.did) ||
        !record.keyId.equals(certificate.keyId) ||
        !record.publicKey.equals(certificate.publicKey)) {
      throw new IllegalArgumentException("Identity record and certificate mismatch in " + identityPath);
    }

    byte[] storedPrivateKey = Base64.getDecoder().decode(record.privateKey);
    byte[] privateSeed = extractRawPrivateSeed(storedPrivateKey);
    PrivateKey privateKey = privateKeyFromStored(privateSeed);
    PublicKey publicKey = publicKeyFromEncoded(record.publicKey);
    byte[] probe = "sigilum-private-key-check".getBytes(StandardCharsets.UTF_8);
    byte[] probeSignature = signEd25519(privateKey, probe);
    if (!verifyEd25519(publicKey, probe, probeSignature)) {
      throw new IllegalArgumentException("Private key does not match public key in identity file");
    }

    SigilumIdentity identity = new SigilumIdentity();
    identity.namespace = record.namespace;
    identity.did = record.did;
    identity.keyId = record.keyId;
    identity.publicKey = record.publicKey;
    identity.privateKey = privateSeed;
    identity.certificate = certificate;
    identity.homeDir = homeDir;
    identity.identityPath = identityPath.toString();
    return identity;
  }

  public static boolean verifyCertificate(SigilumCertificate certificate) {
    if (certificate == null) {
      return false;
    }
    if (certificate.version != CERTIFICATE_VERSION) {
      return false;
    }
    if (certificate.proof == null || !"ed25519".equals(certificate.proof.alg)) {
      return false;
    }

    try {
      PublicKey publicKey = publicKeyFromEncoded(certificate.publicKey);
      byte[] payload = certificatePayload(certificate);
      byte[] signature = base64UrlDecode(certificate.proof.sig);
      return verifyEd25519(publicKey, payload, signature);
    } catch (Exception e) {
      return false;
    }
  }

  public static String encodeCertificateHeader(SigilumCertificate certificate) {
    try {
      return base64UrlEncode(MAPPER.writeValueAsBytes(certificate));
    } catch (Exception e) {
      throw new IllegalStateException("Failed to encode certificate header", e);
    }
  }

  public static SigilumCertificate decodeCertificateHeader(String value) {
    try {
      return MAPPER.readValue(base64UrlDecode(value), SigilumCertificate.class);
    } catch (Exception e) {
      throw new IllegalArgumentException("Invalid certificate header", e);
    }
  }

  public static SignedRequest signHttpRequest(SigilumIdentity identity, SignRequestInput input) {
    if (input.url == null || input.url.trim().isEmpty()) {
      throw new IllegalArgumentException("request URL is required");
    }

    String method = normalizeMethod(input.method);
    String normalizedUrl = normalizeTargetUri(input.url);
    Map<String, String> headers = normalizeHeaders(input.headers);
    byte[] body = input.body == null ? null : input.body;

    if (body != null && body.length > 0) {
      headers.put("content-digest", contentDigest(body));
    }

    headers.put("sigilum-namespace", identity.namespace);
    headers.put("sigilum-agent-key", identity.publicKey);
    headers.put("sigilum-agent-cert", encodeCertificateHeader(identity.certificate));

    List<String> components = new ArrayList<>();
    components.add("@method");
    components.add("@target-uri");
    if (body != null && body.length > 0) {
      components.add("content-digest");
    }
    components.add("sigilum-namespace");
    components.add("sigilum-agent-key");
    components.add("sigilum-agent-cert");

    long created = input.created != null ? input.created : Instant.now().getEpochSecond();
    String nonce = !isBlank(input.nonce) ? input.nonce : UUID.randomUUID().toString();
    String signatureParams = signatureParams(components, created, identity.keyId, nonce);
    byte[] signingBase = signingBase(components, method, normalizedUrl, headers, signatureParams);

    byte[] signature = signEd25519(privateKeyFromStored(identity.privateKey), signingBase);

    headers.put("signature-input", "sig1=" + signatureParams);
    headers.put("signature", "sig1=:" + Base64.getEncoder().encodeToString(signature) + ":");

    SignedRequest output = new SignedRequest();
    output.url = normalizedUrl;
    output.method = method;
    output.headers = headers;
    output.body = body;
    return output;
  }

  public static VerifySignatureResult verifyHttpSignature(VerifySignatureInput input) {
    VerifySignatureResult result = new VerifySignatureResult();

    try {
      Map<String, String> headers = normalizeHeaders(input.headers);
      String signatureInput = headers.get("signature-input");
      String signatureHeader = headers.get("signature");

      if (isBlank(signatureInput) || isBlank(signatureHeader)) {
        return result.invalid("Missing Signature-Input or Signature header");
      }

      Matcher inputMatch = SIGNATURE_INPUT_PATTERN.matcher(signatureInput);
      if (!inputMatch.matches()) {
        return result.invalid("Invalid Signature-Input format");
      }

      String rawComponents = inputMatch.group(1);
      String createdRaw = inputMatch.group(2);
      String keyId = inputMatch.group(3);
      String alg = inputMatch.group(4);
      String nonce = inputMatch.group(5);
      long created = Long.parseLong(createdRaw);

      if (!"ed25519".equalsIgnoreCase(alg)) {
        return result.invalid("Unsupported signature algorithm");
      }
      if (created <= 0) {
        return result.invalid("Invalid Signature-Input created timestamp");
      }
      if (input.maxAgeSeconds != null) {
        long now = input.nowEpochSeconds != null ? input.nowEpochSeconds : Instant.now().getEpochSecond();
        long age = now - created;
        if (age < 0 || age > input.maxAgeSeconds) {
          return result.invalid("Signature expired or not yet valid");
        }
      }
      if (input.seenNonces != null) {
        if (input.seenNonces.contains(nonce)) {
          return result.invalid("Replay detected: nonce already seen");
        }
        input.seenNonces.add(nonce);
      }

      Matcher sigMatch = SIGNATURE_PATTERN.matcher(signatureHeader);
      if (!sigMatch.matches()) {
        return result.invalid("Invalid Signature format");
      }
      byte[] signature = Base64.getDecoder().decode(sigMatch.group(1));

      String certHeader = headers.get("sigilum-agent-cert");
      if (isBlank(certHeader)) {
        return result.invalid("Missing sigilum-agent-cert header");
      }
      SigilumCertificate certificate = decodeCertificateHeader(certHeader);
      if (!verifyCertificate(certificate)) {
        return result.invalid("Invalid agent certificate");
      }

      String namespaceHeader = headers.get("sigilum-namespace");
      if (!certificate.namespace.equals(namespaceHeader)) {
        return result.invalid("Namespace header mismatch");
      }
      if (!isBlank(input.expectedNamespace) && !input.expectedNamespace.equals(namespaceHeader)) {
        return result.invalid("Namespace mismatch: expected " + input.expectedNamespace + ", got " + namespaceHeader);
      }

      String keyHeader = headers.get("sigilum-agent-key");
      if (!certificate.publicKey.equals(keyHeader)) {
        return result.invalid("Certificate public key mismatch");
      }
      if (!certificate.keyId.equals(keyId)) {
        return result.invalid("keyid mismatch");
      }

      byte[] body = input.body == null ? null : input.body;
      if (body != null && body.length > 0) {
        String expectedDigest = contentDigest(body);
        if (!expectedDigest.equals(headers.get("content-digest"))) {
          return result.invalid("Content digest mismatch");
        }
      }

      List<String> components = parseComponents(rawComponents);
      String signatureParams = signatureParams(components, created, keyId, nonce);
      byte[] signingBase = signingBase(components, normalizeMethod(input.method), normalizeTargetUri(input.url), headers, signatureParams);

      PublicKey publicKey = publicKeyFromEncoded(keyHeader);
      if (!verifyEd25519(publicKey, signingBase, signature)) {
        return result.invalid("Signature verification failed");
      }

      result.valid = true;
      result.namespace = certificate.namespace;
      result.keyId = certificate.keyId;
      result.reason = null;
      return result;
    } catch (Exception e) {
      return result.invalid(e.getMessage());
    }
  }

  public static SigilumBindings certify(CertifyOptions options) {
    SigilumIdentity identity = loadIdentity(new LoadIdentityOptions(options.namespace, options.homeDir));
    return new SigilumBindings(identity, resolveApiBaseUrl(options.apiBaseUrl), options.httpClient);
  }

  private static String resolveApiBaseUrl(String explicit) {
    if (!isBlank(explicit)) {
      return explicit;
    }
    String env = System.getenv("SIGILUM_API_URL");
    if (!isBlank(env)) {
      return env;
    }
    return DEFAULT_API_BASE_URL;
  }

  private static String resolveUrl(String value, String base) {
    if (value.startsWith("http://") || value.startsWith("https://")) {
      return value;
    }
    return trimRightSlash(base) + "/" + trimLeftSlash(value);
  }

  private static IdentityRecord createIdentityRecord(String namespace) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
      KeyPair keyPair = generator.generateKeyPair();

      byte[] rawPublicKey = extractRawPublicKey(keyPair.getPublic().getEncoded());
      String publicKeyBase64 = Base64.getEncoder().encodeToString(rawPublicKey);
      String did = "did:sigilum:" + namespace;
      String keyId = did + "#ed25519-" + fingerprint(rawPublicKey);
      String now = Instant.now().toString();

      SigilumCertificate certificate = new SigilumCertificate();
      certificate.version = CERTIFICATE_VERSION;
      certificate.namespace = namespace;
      certificate.did = did;
      certificate.keyId = keyId;
      certificate.publicKey = "ed25519:" + publicKeyBase64;
      certificate.issuedAt = now;
      certificate.expiresAt = null;
      certificate.proof = new SigilumCertificateProof();
      certificate.proof.alg = "ed25519";
      certificate.proof.sig = "";

      byte[] certSig = signEd25519(keyPair.getPrivate(), certificatePayload(certificate));
      certificate.proof.sig = base64UrlEncode(certSig);

      IdentityRecord record = new IdentityRecord();
      record.version = IDENTITY_RECORD_VERSION;
      record.namespace = namespace;
      record.did = did;
      record.keyId = keyId;
      record.publicKey = "ed25519:" + publicKeyBase64;
      record.privateKey = Base64.getEncoder().encodeToString(extractRawPrivateSeed(keyPair.getPrivate().getEncoded()));
      record.certificate = certificate;
      record.createdAt = now;
      record.updatedAt = now;
      return record;
    } catch (Exception e) {
      throw new IllegalStateException("Failed to create identity record", e);
    }
  }

  private static void writeIdentityRecord(String homeDir, String namespace, IdentityRecord record) {
    try {
      Path dir = identityDir(homeDir, namespace);
      Files.createDirectories(dir);
      Path path = identityPath(homeDir, namespace);
      String json = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(record) + "\n";
      Files.writeString(path, json, StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to write identity record", e);
    }
  }

  private static Path identityDir(String homeDir, String namespace) {
    return Paths.get(homeDir, IDENTITIES_DIR, namespace);
  }

  private static Path identityPath(String homeDir, String namespace) {
    return identityDir(homeDir, namespace).resolve("identity.json");
  }

  private static String getHomeDir(String explicit) {
    if (!isBlank(explicit)) {
      return explicit;
    }
    String env = System.getenv("SIGILUM_HOME");
    if (!isBlank(env)) {
      return env;
    }
    return defaultSigilumHome();
  }

  private static String resolveNamespace(String explicit, String homeDir) {
    if (!isBlank(explicit)) {
      return normalizeNamespace(explicit);
    }
    String env = System.getenv("SIGILUM_NAMESPACE");
    if (!isBlank(env)) {
      return normalizeNamespace(env);
    }

    List<String> namespaces = listNamespaces(homeDir);
    if (namespaces.size() == 1) {
      return namespaces.get(0);
    }
    if (namespaces.isEmpty()) {
      throw new IllegalArgumentException("No Sigilum identity found. Run `sigilum init <namespace>` first.");
    }
    throw new IllegalArgumentException("Multiple identities found (" + String.join(", ", namespaces) +
        "). Pass namespace explicitly or set SIGILUM_NAMESPACE.");
  }

  private static String normalizeNamespace(String raw) {
    if (raw == null) {
      throw new IllegalArgumentException("Namespace is required");
    }
    String namespace = raw.trim().toLowerCase(Locale.ROOT);
    if (!NAMESPACE_PATTERN.matcher(namespace).matches()) {
      throw new IllegalArgumentException(
          "Namespace must match ^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$ (3-64 chars, lowercase)");
    }
    return namespace;
  }

  private static String signatureParams(List<String> components, long created, String keyId, String nonce) {
    StringBuilder builder = new StringBuilder();
    builder.append("(");
    for (int i = 0; i < components.size(); i++) {
      if (i > 0) {
        builder.append(" ");
      }
      builder.append("\"").append(components.get(i)).append("\"");
    }
    builder
        .append(");created=")
        .append(created)
        .append(";keyid=\"")
        .append(keyId)
        .append("\";alg=\"ed25519\";nonce=\"")
        .append(nonce)
        .append("\"");
    return builder.toString();
  }

  private static byte[] signingBase(
      List<String> components,
      String method,
      String url,
      Map<String, String> headers,
      String signatureParams
  ) {
    List<String> lines = new ArrayList<>();
    for (String component : components) {
      String value = componentValue(component, method, url, headers);
      lines.add("\"" + component + "\": " + value);
    }
    lines.add("\"@signature-params\": " + signatureParams);
    return String.join("\n", lines).getBytes(StandardCharsets.UTF_8);
  }

  private static String componentValue(String component, String method, String url, Map<String, String> headers) {
    if ("@method".equals(component)) {
      return method.toLowerCase(Locale.ROOT);
    }
    if ("@target-uri".equals(component)) {
      return normalizeTargetUri(url);
    }
    String value = headers.get(component);
    if (isBlank(value)) {
      throw new IllegalArgumentException("Missing required signed header: " + component);
    }
    return value;
  }

  private static List<String> parseComponents(String raw) {
    if (isBlank(raw)) {
      return new ArrayList<>();
    }
    String[] parts = raw.trim().split("\\s+");
    List<String> components = new ArrayList<>();
    for (String part : parts) {
      if (!part.startsWith("\"") || !part.endsWith("\"")) {
        throw new IllegalArgumentException("Invalid component in Signature-Input: " + part);
      }
      components.add(part.substring(1, part.length() - 1));
    }
    return components;
  }

  private static String contentDigest(byte[] body) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] sum = digest.digest(body);
      return "sha-256=:" + Base64.getEncoder().encodeToString(sum) + ":";
    } catch (Exception e) {
      throw new IllegalStateException("Failed to compute content digest", e);
    }
  }

  private static byte[] certificatePayload(SigilumCertificate certificate) {
    String expiresAt = certificate.expiresAt == null ? "" : certificate.expiresAt;
    String payload = String.join("\n",
        "sigilum-certificate-v1",
        "namespace:" + certificate.namespace,
        "did:" + certificate.did,
        "key-id:" + certificate.keyId,
        "public-key:" + certificate.publicKey,
        "issued-at:" + certificate.issuedAt,
        "expires-at:" + expiresAt
    );
    return payload.getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] signEd25519(PrivateKey privateKey, byte[] payload) {
    try {
      Signature signature = Signature.getInstance("Ed25519");
      signature.initSign(privateKey);
      signature.update(payload);
      return signature.sign();
    } catch (Exception e) {
      throw new IllegalStateException("Failed to sign payload", e);
    }
  }

  private static boolean verifyEd25519(PublicKey publicKey, byte[] payload, byte[] signatureBytes) {
    try {
      Signature signature = Signature.getInstance("Ed25519");
      signature.initVerify(publicKey);
      signature.update(payload);
      return signature.verify(signatureBytes);
    } catch (Exception e) {
      return false;
    }
  }

  private static PublicKey publicKeyFromEncoded(String encoded) {
    if (isBlank(encoded) || !encoded.startsWith("ed25519:")) {
      throw new IllegalArgumentException("Unsupported public key format");
    }
    byte[] raw = Base64.getDecoder().decode(encoded.substring("ed25519:".length()));
    if (raw.length != 32) {
      throw new IllegalArgumentException("Invalid public key length");
    }

    byte[] x509 = new byte[ED25519_X509_PREFIX.length + raw.length];
    System.arraycopy(ED25519_X509_PREFIX, 0, x509, 0, ED25519_X509_PREFIX.length);
    System.arraycopy(raw, 0, x509, ED25519_X509_PREFIX.length, raw.length);

    try {
      KeyFactory factory = KeyFactory.getInstance("Ed25519");
      return factory.generatePublic(new X509EncodedKeySpec(x509));
    } catch (Exception e) {
      throw new IllegalArgumentException("Invalid public key", e);
    }
  }

  private static PrivateKey privateKeyFromStored(byte[] storedPrivateKey) {
    try {
      byte[] pkcs8;
      if (storedPrivateKey.length == 32) {
        pkcs8 = new byte[ED25519_PKCS8_PREFIX.length + storedPrivateKey.length];
        System.arraycopy(ED25519_PKCS8_PREFIX, 0, pkcs8, 0, ED25519_PKCS8_PREFIX.length);
        System.arraycopy(storedPrivateKey, 0, pkcs8, ED25519_PKCS8_PREFIX.length, storedPrivateKey.length);
      } else {
        pkcs8 = storedPrivateKey;
      }
      KeyFactory factory = KeyFactory.getInstance("Ed25519");
      return factory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    } catch (Exception e) {
      throw new IllegalArgumentException("Invalid private key", e);
    }
  }

  private static byte[] extractRawPublicKey(byte[] x509Encoded) {
    if (x509Encoded.length < ED25519_X509_PREFIX.length + 32) {
      throw new IllegalArgumentException("Invalid X509 public key");
    }
    byte[] raw = new byte[32];
    System.arraycopy(x509Encoded, x509Encoded.length - 32, raw, 0, 32);
    return raw;
  }

  private static byte[] extractRawPrivateSeed(byte[] storedPrivateKey) {
    if (storedPrivateKey.length == 32) {
      return storedPrivateKey;
    }
    if (storedPrivateKey.length >= ED25519_PKCS8_PREFIX.length + 32) {
      boolean matchesPrefix = true;
      for (int i = 0; i < ED25519_PKCS8_PREFIX.length; i++) {
        if (storedPrivateKey[i] != ED25519_PKCS8_PREFIX[i]) {
          matchesPrefix = false;
          break;
        }
      }
      if (matchesPrefix) {
        byte[] seed = new byte[32];
        System.arraycopy(storedPrivateKey, storedPrivateKey.length - 32, seed, 0, 32);
        return seed;
      }
    }
    throw new IllegalArgumentException("Invalid private key format");
  }

  private static String fingerprint(byte[] publicKey) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] sum = digest.digest(publicKey);
      StringBuilder builder = new StringBuilder();
      for (int i = 0; i < 8; i++) {
        builder.append(String.format("%02x", sum[i]));
      }
      return builder.toString();
    } catch (Exception e) {
      throw new IllegalStateException("Failed to compute fingerprint", e);
    }
  }

  private static Map<String, String> normalizeHeaders(Map<String, String> headers) {
    if (headers == null) {
      return new LinkedHashMap<>();
    }
    Map<String, String> normalized = new LinkedHashMap<>();
    for (Map.Entry<String, String> entry : headers.entrySet()) {
      normalized.put(entry.getKey().toLowerCase(Locale.ROOT), entry.getValue());
    }
    return normalized;
  }

  private static String normalizeMethod(String method) {
    if (isBlank(method)) {
      return "GET";
    }
    return method.toUpperCase(Locale.ROOT);
  }

  private static String trimRightSlash(String value) {
    if (value == null) {
      return "";
    }
    return value.replaceAll("/+$", "");
  }

  private static String trimLeftSlash(String value) {
    if (value == null) {
      return "";
    }
    return value.replaceAll("^/+", "");
  }

  private static String normalizeTargetUri(String value) {
    try {
      URI parsed = URI.create(value);
      return new URI(
          parsed.getScheme(),
          parsed.getAuthority(),
          parsed.getPath(),
          parsed.getQuery(),
          null
      ).toString();
    } catch (Exception ignored) {
      return value;
    }
  }

  private static String urlEncode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
  }

  private static String base64UrlEncode(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private static byte[] base64UrlDecode(String value) {
    return Base64.getUrlDecoder().decode(value);
  }

  private static byte[] hex(String hex) {
    int len = hex.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
    }
    return out;
  }

  private static boolean isBlank(String value) {
    return value == null || value.trim().isEmpty();
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static class IdentityRecord {
    public int version;
    public String namespace;
    public String did;
    public String keyId;
    public String publicKey;
    public String privateKey;
    public SigilumCertificate certificate;
    public String createdAt;
    public String updatedAt;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class SigilumCertificateProof {
    public String alg;
    public String sig;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class SigilumCertificate {
    public int version;
    public String namespace;
    public String did;
    public String keyId;
    public String publicKey;
    public String issuedAt;
    public String expiresAt;
    public SigilumCertificateProof proof;
  }

  public static class SigilumIdentity {
    public String namespace;
    public String did;
    public String keyId;
    public String publicKey;
    public byte[] privateKey;
    public SigilumCertificate certificate;
    public String homeDir;
    public String identityPath;
  }

  public static class InitIdentityOptions {
    public String namespace;
    public String homeDir;
    public boolean force;
  }

  public static class InitIdentityResult {
    public String namespace;
    public String did;
    public String keyId;
    public String publicKey;
    public boolean created;
    public String homeDir;
    public String identityPath;
  }

  public static class LoadIdentityOptions {
    public String namespace;
    public String homeDir;

    public LoadIdentityOptions() {}

    public LoadIdentityOptions(String namespace, String homeDir) {
      this.namespace = namespace;
      this.homeDir = homeDir;
    }
  }

  public static class SignRequestInput {
    public String url;
    public String method;
    public Map<String, String> headers;
    public byte[] body;
    public Long created;
    public String nonce;
  }

  public static class SignedRequest {
    public String url;
    public String method;
    public Map<String, String> headers;
    public byte[] body;
  }

  public static class VerifySignatureInput {
    public String url;
    public String method;
    public Map<String, String> headers;
    public byte[] body;
    public String expectedNamespace;
    public Long nowEpochSeconds;
    public Long maxAgeSeconds;
    public Set<String> seenNonces;
  }

  public static class VerifySignatureResult {
    public boolean valid;
    public String namespace;
    public String keyId;
    public String reason;

    public VerifySignatureResult invalid(String message) {
      this.valid = false;
      this.reason = message;
      this.namespace = null;
      this.keyId = null;
      return this;
    }
  }

  public static class CertifyOptions {
    public String namespace;
    public String homeDir;
    public String apiBaseUrl;
    public HttpClient httpClient;
  }

  public static class SigilumBindings {
    private final SigilumIdentity identity;
    public final String namespace;
    public final String did;
    public final String keyId;
    public final String publicKey;
    public final SigilumCertificate certificate;
    public final String apiBaseUrl;
    private final HttpClient httpClient;

    public SigilumBindings(SigilumIdentity identity, String apiBaseUrl, HttpClient httpClient) {
      this.identity = identity;
      this.namespace = identity.namespace;
      this.did = identity.did;
      this.keyId = identity.keyId;
      this.publicKey = identity.publicKey;
      this.certificate = identity.certificate;
      this.apiBaseUrl = apiBaseUrl;
      this.httpClient = httpClient != null ? httpClient : HttpClient.newHttpClient();
    }

    public SignedRequest sign(String url, String method, Map<String, String> headers, byte[] body) {
      SignRequestInput input = new SignRequestInput();
      input.url = resolveUrl(url, apiBaseUrl);
      input.method = method;
      input.headers = headers;
      input.body = body;
      return signHttpRequest(identity, input);
    }

    public HttpResponse<String> fetch(String url, String method, Map<String, String> headers, byte[] body) {
      try {
        SignedRequest signed = sign(url, method, headers, body);
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(signed.url));
        for (Map.Entry<String, String> entry : signed.headers.entrySet()) {
          builder.header(entry.getKey(), entry.getValue());
        }
        if (signed.body != null && signed.body.length > 0) {
          builder.method(signed.method, HttpRequest.BodyPublishers.ofByteArray(signed.body));
        } else {
          builder.method(signed.method, HttpRequest.BodyPublishers.noBody());
        }
        return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
      } catch (Exception e) {
        throw new IllegalStateException("Sigilum fetch failed", e);
      }
    }

    public HttpResponse<String> request(String path, String method, Map<String, String> headers, byte[] body) {
      String base = getNamespaceApiBase(apiBaseUrl, namespace);
      String url = resolveUrl(path, base);
      return fetch(url, method, headers, body);
    }
  }
}
