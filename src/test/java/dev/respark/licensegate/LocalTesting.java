package dev.respark.licensegate;


public class LocalTesting {
    static String PUBLIC_KEY = "-----BEGIN PUBLIC KEY----- MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkiwElZAohnDqwxLZH2UR bickGkg2HWQ/hc9HH6+Xh3i45RF7lzYbZYBU9OkgKZED4k3z7dDerd7hdwzc1RrE f7jXU2tfOB+wQhnuKZuIkirBs35+8S643Jmf2NkRWOhJg49mCJnVQ/9KicYdT335 3WJwOFhYjdjnC4XVi1UgH/wI/JblegXPxWlFjkpbB1nfKBS8gU9L3zjnexuzUtsu 8saqxd51jeQYWmcMoiEHQWA22cw/b73znRQFDlGxQBIwsVVuv+mZqI/JW5pDXdAz NMps/HAALGdsvVAHvLlVwd2rwnRky3k9zYAFEhzhuqFg+s22JmXwoNk0VNZJ7GVN nwIDAQAB -----END PUBLIC KEY-----";

    public static void main(String[] args) {
        System.out.println(new LicenseGate("d32af1")
                .setValidationServer("http://localhost:8080")
                .debug()
                .verify("test123"));
    }
}