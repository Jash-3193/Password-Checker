import tkinter as tk
from tkinter import messagebox
import re
import string
import random
import time
import math

# A simple mock database of past passwords (remove step 6 as requested)
password_history = set()

# A mock dictionary of common passwords
common_passwords = {'password', '12345', 'letmein', 'qwerty', 'password123', 'welcome'}

# Function to calculate password entropy
def calculate_entropy(password):
    n = len(password)
    possible_characters = 26 + 26 + 10 + 32  # lowercase, uppercase, digits, special chars
    entropy = n * (math.log2(possible_characters))  # Entropy calculation using log2
    return entropy

# Function to check password strength
def check_password_strength(password):
    # Check length
    if len(password) < 8:
        return "Weak", "red"
    if len(password) < 12:
        return "Moderate", "blue"  # changed to blue for moderate

    # Check character types
    score = 0
    if re.search(r'[a-z]', password): score += 1
    if re.search(r'[A-Z]', password): score += 1
    if re.search(r'[0-9]', password): score += 1
    if re.search(r'[@#$%^&+=!]', password): score += 1

    if score == 4:
        return "Strong", "green"
    elif score == 3:
        return "Moderate", "blue"
    else:
        return "Weak", "red"

# Function to check for common dictionary words or leetspeak
def check_leetspeak(password):
    for common in common_passwords:
        if common.lower() in password.lower():
            return True
    return False

# Function to give feedback on the password
def analyze_password():
    password = password_entry.get()

    # Check for empty input
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password")
        return

    # Check password strength
    strength, color = check_password_strength(password)

    # Check for leetspeak
    if check_leetspeak(password):
        leetspeak_message = "Warning: Your password contains common leetspeak or dictionary words."
    else:
        leetspeak_message = ""

    # Calculate entropy
    entropy = calculate_entropy(password)
    entropy_message = f"Password Entropy: {entropy:.2f} bits (Higher is better)"

    # Security Tips and Best Practices
    tips_message = ("Tips:\n"
                    "- Use a mix of uppercase, lowercase, digits, and special characters.\n"
                    "- Avoid common patterns or dictionary words.\n"
                    "- Consider using a passphrase (e.g., 'MyDog@123!').\n"
                    "- Add multi-factor authentication (MFA) for extra security.")

    # Update the UI with feedback
    strength_label.config(text=f"Password Strength: {strength}", fg=color)
    leetspeak_label.config(text=leetspeak_message)
    entropy_label.config(text=entropy_message)
    tips_label.config(text=tips_message)

    # Suggest multi-factor authentication (MFA)
    mfa_label.config(text="Consider enabling Multi-factor Authentication (MFA) for added security!")

# Function to toggle password visibility
def toggle_password():
    if show_password_var.get():
        password_entry.config(show="")  # Show the password
    else:
        password_entry.config(show="*")  # Hide the password

# Set up the Tkinter window
root = tk.Tk()
root.title("Advanced Password Strength Checker")

# Set up the GUI components
password_label = tk.Label(root, text="Enter Password:")
password_label.pack(pady=5)

password_entry = tk.Entry(root, show="*", width=40)
password_entry.pack(pady=5)

# Checkbox for showing/hiding the password
show_password_var = tk.BooleanVar()
show_password_checkbox = tk.Checkbutton(root, text="Show Password", variable=show_password_var, command=toggle_password)
show_password_checkbox.pack(pady=5)

check_button = tk.Button(root, text="Check Password", command=analyze_password)
check_button.pack(pady=10)

strength_label = tk.Label(root, text="Password Strength: ", font=("Arial", 12))
strength_label.pack(pady=5)

leetspeak_label = tk.Label(root, text="", font=("Arial", 10), fg="red")
leetspeak_label.pack(pady=5)

entropy_label = tk.Label(root, text="Password Entropy: ", font=("Arial", 10))
entropy_label.pack(pady=5)

mfa_label = tk.Label(root, text="Consider enabling Multi-factor Authentication (MFA) for added security!", font=("Arial", 10, "italic"))
mfa_label.pack(pady=5)

tips_label = tk.Label(root, text="Tips: ", font=("Arial", 10))
tips_label.pack(pady=10)

# Start the GUI loop
root.mainloop()
