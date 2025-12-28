import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;

enum SafetyStatus {
    SAFE("SAFE"),
    SUSPICIOUS("SUSPICIOUS");

    private final String label;

    SafetyStatus(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}

class URLCheckResult {
    private final String url;
    private final SafetyStatus status;
    private final List<String> reasons;

    public URLCheckResult(String url, SafetyStatus status, List<String> reasons) {
        this.url = url;
        this.status = status;
        this.reasons = reasons;
    }

    public void printReport() {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("URL: " + url);
        System.out.println("Status: " + status.getLabel());

        if (!reasons.isEmpty()) {
            System.out.println("\nReasons:");
            for (String reason : reasons) {
                System.out.println("  • " + reason);
            }
        }
        System.out.println("=".repeat(60));
    }
}

class URLSafetyChecker {

    private static final String[] SUSPICIOUS_KEYWORDS = {
            "phishing", "malware", "virus", "hack", "crack", "exploit",
            "login-verify", "account-verify", "secure-update", "urgent-action",
            "free-download", "click-here", "prize", "winner", "claim-now",
            "banking-alert", "suspended-account", "verify-identity"
    };

    private static final String[] SUSPICIOUS_TLDS = {
            ".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".xyz"
    };

    private static final Pattern URL_PATTERN = Pattern.compile(
            "^(https?://)([\\w.-]+)(:[0-9]+)?(/.*)?$",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern IP_PATTERN = Pattern.compile(
            "^https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
    );

    public URLCheckResult checkURL(String url) {
        List<String> reasons = new ArrayList<>();

        url = url.trim();

        if (!URL_PATTERN.matcher(url).matches()) {
            reasons.add("Invalid URL format");
            return new URLCheckResult(url, SafetyStatus.SUSPICIOUS, reasons);
        }

        if (!url.toLowerCase().startsWith("https://")) {
            reasons.add("Not using HTTPS (insecure connection)");
        }

        String lowerURL = url.toLowerCase();
        for (String keyword : SUSPICIOUS_KEYWORDS) {
            if (lowerURL.contains(keyword)) {
                reasons.add("Contains suspicious keyword: '" + keyword + "'");
            }
        }

        for (String tld : SUSPICIOUS_TLDS) {
            if (lowerURL.contains(tld)) {
                reasons.add("Contains suspicious domain extension: '" + tld + "'");
            }
        }

        if (IP_PATTERN.matcher(url).find()) {
            reasons.add("Uses IP address instead of domain name");
        }

        String domain = extractDomain(url);
        if (domain != null && countOccurrences(domain, '.') > 3) {
            reasons.add("Excessive number of subdomains");
        }

        if (url.contains("@")) {
            reasons.add("Contains '@' symbol (possible URL obfuscation)");
        }

        if (url.matches(".*:\\d{2,5}(/|$).*")) {
            String port = url.replaceAll(".*:(\\d{2,5})(/|$).*", "$1");
            int portNum = Integer.parseInt(port);
            if (portNum != 80 && portNum != 443 && portNum != 8080) {
                reasons.add("Uses unusual port number: " + port);
            }
        }

        SafetyStatus status = reasons.isEmpty() ? SafetyStatus.SAFE : SafetyStatus.SUSPICIOUS;

        if (status == SafetyStatus.SAFE) {
            reasons.add("All security checks passed");
        }

        return new URLCheckResult(url, status, reasons);
    }

    private String extractDomain(String url) {
        try {
            String domain = url.replaceFirst("^https?://", "");
            domain = domain.split("/")[0];
            domain = domain.split(":")[0];
            return domain;
        } catch (Exception e) {
            return null;
        }
    }

    private int countOccurrences(String str, char ch) {
        return (int) str.chars().filter(c -> c == ch).count();
    }
}

public class URLSafetyCheckerApp {

    public static void main(String[] args) {
        URLSafetyChecker checker = new URLSafetyChecker();
        Scanner scanner = new Scanner(System.in);

        System.out.println("\n" + "=".repeat(60));
        System.out.println("URL SAFETY CHECKER");
        System.out.println("=".repeat(60));
        System.out.println("This tool checks URLs for common security issues.");
        System.out.println("Type 'exit' to quit.\n");

        while (true) {
            System.out.print("Enter URL to check: ");
            String input = scanner.nextLine().trim();

            if (input.equalsIgnoreCase("exit")) {
                System.out.println("\nThank you for using URL Safety Checker!");
                break;
            }

            if (input.isEmpty()) {
                System.out.println("Please enter a valid URL.\n");
                continue;
            }

            URLCheckResult result = checker.checkURL(input);
            result.printReport();
            System.out.println();
        }

        scanner.close();
    }
}
