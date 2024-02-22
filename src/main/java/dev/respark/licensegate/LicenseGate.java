package dev.respark.licensegate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * A Java wrapper for communicating with LicenseGate - supports cloud and self-hosted setups.
 * This class provides methods to set up license verification parameters, perform the verification,
 * and handle the responses from the verification server.
 */
public class LicenseGate {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String DEFAULT_SERVER = "https://licensegate.com";

    private String userId;
    private String publicRsaKey;
    private String validationServer = DEFAULT_SERVER;
    private boolean useChallenges = false;
    private boolean debug = false;

    /**
     * Create a new LicenseGate instance with your user ID.
     *
     * @param userId The user ID of the license owner's LicenseGate account.
     */
    public LicenseGate(String userId) {
        this.userId = userId;
    }

    /**
     * Create a new LicenseGate instance with your user ID and public RSA key.
     * Using this constructor enables the use of challenges for added security (recommended for client-side verification).
     *
     * @param userId       The user ID of the license owner's LicenseGate account.
     * @param publicRsaKey The public RSA key of the license owner's LicenseGate account.
     */
    public LicenseGate(String userId, String publicRsaKey) {
        this.userId = userId;
        this.publicRsaKey = publicRsaKey;
        this.useChallenges = true;
    }

    /**
     * Set the public RSA key of the license owner's LicenseGate account.
     *
     * @param publicRsaKey The public RSA key of the license owner's LicenseGate account.
     * @return The LicenseGate instance.
     */
    public LicenseGate setPublicRsaKey(String publicRsaKey) {
        this.publicRsaKey = publicRsaKey;
        return this;
    }

    /**
     * Set the validation server URL.
     * Use this method to set the URL of your self-hosted LicenseGate server.
     * Default: LicenseGate cloud server
     * Example: "https://license.yourdomain.com"
     *
     * @param validationServer The URL of the validation server.
     * @return The LicenseGate instance.
     */
    public LicenseGate setValidationServer(String validationServer) {
        this.validationServer = validationServer;
        return this;
    }

    /**
     * Enable the use and verification of challenges.
     *
     * @return The LicenseGate instance.
     */
    public LicenseGate useChallenges() {
        useChallenges = true;
        return this;
    }

    /**
     * Enable debug mode to print request, response and error information to the console.
     *
     * @return The LicenseGate instance.
     */
    public LicenseGate debug() {
        debug = true;
        return this;
    }

    /**
     * Verify a license key.
     *
     * @param licenseKey The license key to verify.
     * @return The validation result.
     */
    public ValidationType verify(String licenseKey) {
        return verify(licenseKey, null, null);
    }

    /**
     * Verify a license key with a specific scope.
     *
     * @param licenseKey The license key to verify.
     * @param scope      The scope to verify the license key against.
     * @return The validation result.
     */
    public ValidationType verify(String licenseKey, String scope) {
        return verify(licenseKey, scope, null);
    }

    /**
     * Verify a license key with a specific scope and metadata that should be associated with the verification request.
     *
     * @param licenseKey The license key to verify.
     * @param scope      The scope to verify the license key against.
     * @param metadata   The metadata to associate with the verification request.
     * @return The validation result.
     */
    public ValidationType verify(String licenseKey, String scope, String metadata) {
        try {
            String challenge = this.useChallenges ? String.valueOf(System.currentTimeMillis()) : null;
            ObjectNode response = requestServer(buildUrl(licenseKey, scope, metadata, challenge));

            if (response.has("error") || !response.has("result")) {
                if (debug) System.out.println("Error: " + response.get("error").asText());
                return ValidationType.SERVER_ERROR;
            }

            // Non-valid response don't need a signed challenge
            if (response.has("valid") && !response.get("valid").asBoolean()) {
                ValidationType result = ValidationType.valueOf(response.get("result").asText());
                if (result == ValidationType.VALID) {
                    return ValidationType.SERVER_ERROR;
                } else {
                    return result;
                }
            }

            if (useChallenges) {
                if (!response.has("signedChallenge")) {
                    if (debug) System.out.println("Error: No challenge result");
                    return ValidationType.FAILED_CHALLENGE;
                }

                if (!verifyChallenge(challenge, response.get("signedChallenge").asText())) {
                    if (debug) System.out.println("Error: Challenge verification failed");
                    return ValidationType.FAILED_CHALLENGE;
                }
            }

            return ValidationType.valueOf(response.get("result").asText());
        } catch (IOException e) {
            if (debug) e.printStackTrace();
            return ValidationType.CONNECTION_ERROR;
        }
    }

    /**
     * Verify a license key and return a boolean indicating whether the license key is valid.
     *
     * @param licenseKey The license key to verify.
     * @return True if the license key is valid, false otherwise.
     */
    public boolean verifySimple(String licenseKey) {
        return verify(licenseKey) == ValidationType.VALID;
    }

    /**
     * Verify a license key with a specific scope and return a boolean indicating whether the license key is valid.
     *
     * @param licenseKey The license key to verify.
     * @param scope      The scope to verify the license key against.
     * @return True if the license key is valid, false otherwise.
     */
    public boolean verifySimple(String licenseKey, String scope) {
        return verify(licenseKey, scope) == ValidationType.VALID;
    }

    /**
     * Verify a license key with a specific scope and metadata that should be associated with the verification request.
     *
     * @param licenseKey The license key to verify.
     * @param scope      The scope to verify the license key against.
     * @param metadata   The metadata to associate with the verification request.
     * @return True if the license key is valid, false otherwise.
     */
    public boolean verifySimple(String licenseKey, String scope, String metadata) {
        return verify(licenseKey, scope, metadata) == ValidationType.VALID;
    }

    private String buildUrl(String licenseKey, String scope, String metadata, String challenge) throws UnsupportedEncodingException {
        String queryString = "";

        // Add metadata and scope to url query if not null (parsed as query parameters)
        if (metadata != null) {
            queryString += "?metadata=" + URLEncoder.encode(metadata, StandardCharsets.UTF_8.name());
        }

        if (scope != null) {
            queryString += (queryString.isEmpty() ? "?" : "&") + "scope=" + URLEncoder.encode(scope, StandardCharsets.UTF_8.name());
        }

        if (useChallenges && challenge != null) {
            queryString += (queryString.isEmpty() ? "?" : "&") + "challenge=" + URLEncoder.encode(challenge, StandardCharsets.UTF_8.name());
        }

        return validationServer + "/license/" + userId + "/" + licenseKey + "/verify" + queryString;
    }

    private ObjectNode requestServer(String urlStr) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.setRequestProperty("User-Agent", "Mozilla/5.0");
        con.setDoOutput(true);

        int responseCode = con.getResponseCode();
        if (debug) {
            System.out.println("\nSending request to URL : " + url);
            System.out.println("Response Code : " + responseCode);
        }

        try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
            String inputLine;
            StringBuilder response = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }

            final String jsonStr = response.toString();

            if (debug) {
                System.out.println("Response: " + jsonStr);
            }

            // Parse JSON response
            return OBJECT_MAPPER.readValue(jsonStr, ObjectNode.class);
        }
    }

    private boolean verifyChallenge(String challenge, String signedChallengeBase64) {
        try {
            // Remove the PEM header and footer if present
            String pemHeader = "-----BEGIN PUBLIC KEY-----";
            String pemFooter = "-----END PUBLIC KEY-----";
            String base64PublicKey = this.publicRsaKey.replace(pemHeader, "").replace(pemFooter, "").replaceAll("\\s+", ""); // Remove all whitespace (new lines, spaces, tabs)


            // Convert Base64 encoded public key to PublicKey object
            byte[] publicKeyBytes = Base64.getDecoder().decode(base64PublicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            // Base64 decode the signed challenge
            byte[] signatureBytes = Base64.getDecoder().decode(signedChallengeBase64);

            // Initialize a Signature object for verification
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(challenge.getBytes());

            // Verify the signature
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            if (debug) e.printStackTrace();
            return false;
        }
    }

    /**
     * The result of a license verification.
     * Most of these types are the same as the ones returned by the LicenseGate server. Check the official documentation for more information.
     * <ul>
     *     <li>CONNECTION_ERROR: The request to the LicenseGate server failed.</li>
     *     <li>SERVER_ERROR: The LicenseGate server returned an invalid response.</li>
     *     <li>FAILED_CHALLENGE: The challenge verification failed.</li>
     * </ul>
     */
    public enum ValidationType {

        VALID(true), NOT_FOUND, NOT_ACTIVE, EXPIRED, LICENSE_SCOPE_FAILED, IP_LIMIT_EXCEEDED, RATE_LIMIT_EXCEEDED, FAILED_CHALLENGE, SERVER_ERROR, CONNECTION_ERROR;

        ValidationType(boolean valid) {
            this.valid = valid;
        }

        ValidationType() {
            this(false);
        }

        private boolean valid;

        /**
         * Returns whether the result is valid. This is true for VALID and false for all other types.
         *
         * @return Whether the result is valid.
         */
        public boolean isValid() {
            return valid;
        }

    }
}
