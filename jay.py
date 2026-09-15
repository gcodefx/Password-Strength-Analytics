import csv
import datetime
import string


def check_password_strength(password):
    """Analyzes the password and returns a score out of 5 and feedback list."""
    score = 0
    feedback = []

    # 1. Length Check
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Make it at least 8 characters long.")

    # 2. Uppercase Check
    has_upper = any(char.isupper() for char in password)
    if has_upper:
        score += 1
    else:
        feedback.append("Add at least one uppercase letter (A-Z).")

    # 3. Lowercase Check
    has_lower = any(char.islower() for char in password)
    if has_lower:
        score += 1
    else:
        feedback.append("Add at least one lowercase letter (a-z).")

    # 4. Number Check
    has_digit = any(char.isdigit() for char in password)
    if has_digit:
        score += 1
    else:
        feedback.append("Add at least one number (0-9).")

    # 5. Special Character Check
    # string.punctuation contains characters like !, @, #, $, %, etc.
    has_special = any(char in string.punctuation for char in password)
    if has_special:
        score += 1
    else:
        feedback.append("Add at least one special character (e.g., !, @, #).")

    return score, feedback


def log_data(password_length, score):
    """Saves the data to a CSV file for analytics (The Data Science Part)."""
    file_name = "password_logs.csv"
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Check if file exists to write headers
    try:
        with open(file_name, "x", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "Password_Length", "Safety_Score"])
    except FileExistsError:
        pass  # If file exists, do nothing and proceed to append data

    # Append the new log entry
    with open(file_name, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([current_time, password_length, score])


# --- Main Program Loop ---
print("--- Welcome to the Cyber Security Password Analyzer ---")

while True:
    user_password = input(
        "\nEnter a password to test (or type 'exit' to quit): "
    )

    if user_password.lower() == "exit":
        print("Goodbye! Check your 'password_logs.csv' file for the data.")
        break

    if not user_password:
        print("Password cannot be empty!")
        continue

    # Run the security analysis
    safety_score, suggestions = check_password_strength(user_password)
    password_len = len(user_password)

    # Print the security results
    print(f"\n[RESULTS] Length: {password_len} characters")
    print(f"[RESULTS] Security Score: {safety_score}/5")

    if safety_score == 5:
        print("🟢 Verdict: Strong Password! Excellent job.")
    elif safety_score >= 3:
        print("🟡 Verdict: Moderate Password. Could be better.")
    else:
        print("🔴 Verdict: Weak Password! Highly vulnerable.")

    # Show tips if the password isn't perfect
    if suggestions:
        print("\nSuggestions to improve:")
        for tip in suggestions:
            print(f" -> {tip}")

    # Log the data for our data science analytics
    log_data(password_len, safety_score)
    print("\n✓ Analysis logged to 'password_logs.csv'")
