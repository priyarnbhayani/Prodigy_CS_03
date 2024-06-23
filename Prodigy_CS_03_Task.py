import re

def check_password_strength(password):
    length_error = len(password) < 8
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    digit_error = re.search(r"\d", password) is None
    special_char_error = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is None
    
    # Determine password strength
    if length_error:
        return "Password is too short. It should be at least 8 characters."
    elif uppercase_error or lowercase_error or digit_error or special_char_error:
        errors = []
        if uppercase_error:
            errors.append("Password should include at least one uppercase letter (A-Z).")
        if lowercase_error:
            errors.append("Password should include at least one lowercase letter (a-z).")
        if digit_error:
            errors.append("Password should include at least one numeric digit (0-9).")
        if special_char_error:
            errors.append("Password should include at least one special character (!@#$%^&*(),.?\":{}|<>).")
        return "\n".join(errors)
    else:
        return "Password is strong."

# Example usage:
if __name__ == "__main__":
    password = input("Enter a password to check its strength: ")
    strength_result = check_password_strength(password)
    print(strength_result)
