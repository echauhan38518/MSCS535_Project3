
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class SecurePaymentSystem {

    // Entry point for payment processing
    public static void main(String[] args) {
        UserInput input = new UserInput("102", "Enjal <script>alert('hack');</script> Chauhan", "200.00", "1234567890123456", "12/27");
        processPayment(input);
    }

    // Function to process payment
    public static void processPayment(UserInput userInput) {
        // Step 1: Validate and sanitize input
        UserInput sanitizedInput = validateAndSanitizeInput(userInput);

        // Step 2: Connect securely to database
        try (Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/paymentsdb", "root", "root@123")) {

            // Step 3: Use prepared statements (prevents SQL injection)
            String query = "INSERT INTO payments (user_id, user_name, amount, card_number, expiry_date) VALUES (?, ?, ?, ?, ?)";
            PreparedStatement stmt = conn.prepareStatement(query);
            stmt.setInt(1, Integer.parseInt(sanitizedInput.userID));
            stmt.setString(2, sanitizedInput.userName);
            stmt.setBigDecimal(3, new java.math.BigDecimal(sanitizedInput.amount));
            stmt.setString(4, sanitizedInput.cardNumber);
            stmt.setString(5, sanitizedInput.expiryDate);

            stmt.executeUpdate();

            // Step 4: Escape output before displaying (prevents XSS)
            String safeMessage = escapeOutput("Payment processed successfully for " + sanitizedInput.userName);
            System.out.println(safeMessage);

            // Step 5: Log securely
            logEvent("Payment completed for user " + sanitizedInput.userID);

        } catch (SQLException e) {
            System.err.println("Error processing payment: " + e.getMessage());
        }
    }

    // Validate and sanitize user input
    public static UserInput validateAndSanitizeInput(UserInput input) {
        // Validate numeric fields
        if (!input.userID.matches("\\d+")) {
            throw new IllegalArgumentException("Invalid user ID");
        }
        if (!input.amount.matches("\\d+(\\.\\d{1,2})?")) {
            throw new IllegalArgumentException("Invalid amount format");
        }

        // Sanitize user name (remove script tags)
        input.userName = removeScriptTags(input.userName);

        // Allow only digits for card number
        input.cardNumber = input.cardNumber.replaceAll("[^0-9]", "");

        return input;
    }

    // Remove <script> tags to prevent malicious JS
    public static String removeScriptTags(String text) {
        return text.replaceAll("(?i)<script.*?>.*?</script>", "");
    }

    // Escape HTML special characters for output
    public static String escapeOutput(String text) {
        if (text == null) return null;
        return text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }

    // Log event securely (could be to a file or monitoring system)
    public static void logEvent(String message) {
        System.out.println("[LOG] " + message);
    }
}

// Helper class to hold user input
class UserInput {
    String userID;
    String userName;
    String amount;
    String cardNumber;
    String expiryDate;

    public UserInput(String userID, String userName, String amount, String cardNumber, String expiryDate) {
        this.userID = userID;
        this.userName = userName;
        this.amount = amount;
        this.cardNumber = cardNumber;
        this.expiryDate = expiryDate;
    }
}