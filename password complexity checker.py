import sys
import time
import secrets
import string
from typing import List, Tuple, Dict, Union
from colorama import Fore, Style, init
import re
import math

# Initialize colorama for colored output
init(autoreset=True)

class PasswordComplexityChecker:
    """Advanced Password Complexity Checker Tool"""

    COLOR_PURPLE = Fore.MAGENTA
    COLOR_PINK = Fore.LIGHTMAGENTA_EX
    COLOR_BRIGHT_GREEN = Fore.LIGHTGREEN_EX
    COLOR_BRIGHT_YELLOW = Fore.LIGHTYELLOW_EX
    COLOR_BRIGHT_BLUE = Fore.LIGHTBLUE_EX
    COLOR_BRIGHT_CYAN = Fore.CYAN
    COLOR_RESET = Style.RESET_ALL
    COLOR_CYAN = Fore.CYAN
    COLOR_RED = Fore.RED

    def __init__(self, min_length: int = 8, max_length: int = 128, blacklist: set = None):
        """Initialize the password checker with configurable parameters."""
        self.min_length = min_length
        self.max_length = max_length
        self.common_passwords = self._load_common_passwords()
        self.dictionary_words = self._load_dictionary_words()
        self.common_sequences = [
            "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
            "qwerty", "asdfgh", "zxcvbn", "password", "abcdef",
            "01234", "98765", "9876543210", "fedcba"
        ]
        self.blacklist = blacklist if blacklist is not None else set()
        self.checked_passwords = []

    def _load_common_passwords(self) -> List[str]:
        """Load a small set of common passwords."""
        return [
            "password", "123456", "12345678", "qwerty", "abc123",
            "letmein", "monkey", "admin", "welcome", "password1"
        ]

    def _load_dictionary_words(self) -> List[str]:
        """Load common dictionary words."""
        return [
            "password", "welcome", "hello", "office", "secret",
            "system", "computer", "internet", "server", "network"
        ]

    def check_length(self, password: str) -> Tuple[bool, str, int]:
        """Check if password meets length requirements."""
        length = len(password)
        if length < self.min_length:
            return False, f"Password is too short (minimum {self.min_length} characters)", 0
        elif length > self.max_length:
            return False, f"Password is too long (maximum {self.max_length} characters)", 0
        else:
            score = min(25, int(length / self.max_length * 25))
            return True, f"Password length ({length}) is adequate", score

    def check_character_categories(self, password: str) -> Tuple[bool, str, int]:
        """Check if password contains characters from multiple categories."""
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

        categories_present = sum([has_lowercase, has_uppercase, has_digit, has_special])
        if categories_present < 3:
            return False, f"Password uses only {categories_present} character categories (need at least 3)", 0

        score = int(categories_present * 6.25)
        category_details = []
        if has_lowercase: category_details.append("lowercase letters")
        if has_uppercase: category_details.append("uppercase letters")
        if has_digit: category_details.append("numbers")
        if has_special: category_details.append("special characters")

        category_str = ", ".join(category_details)
        return True, f"Password uses {categories_present} categories: {category_str}", score

    def check_common_password(self, password: str) -> Tuple[bool, str, int]:
        """Check if password is in the list of common passwords."""
        password_lower = password.lower()
        if password_lower in self.common_passwords:
            return False, "Password is in the list of common passwords", 0
        return True, "Password is not in the common passwords list", 15

    def check_sequences(self, password: str) -> Tuple[bool, str, int]:
        """Check if password contains common sequences."""
        password_lower = password.lower()
        for sequence in self.common_sequences:
            if sequence in password_lower:
                return False, f"Password contains a common sequence: '{sequence}'", 0

        keyboard_rows = ["qwertyuiop", "asdfghjkl", "zxcvbn"]
        for row in keyboard_rows:
            for i in range(len(row) - 2):
                if row[i:i+3] in password_lower:
                    return False, f"Password contains a keyboard sequence: '{row[i:i+3]}'", 0

        if re.search(r'(.)\1{2,}', password):
            return False, "Password contains repeated characters (3 or more)", 5
        return True, "Password doesn't contain obvious sequences", 15

    def check_dictionary_words(self, password: str) -> Tuple[bool, str, int]:
        """Check if password contains dictionary words."""
        password_lower = password.lower()
        for word in self.dictionary_words:
            if len(word) > 3 and word in password_lower:
                return False, f"Password contains a common dictionary word: '{word}'", 0
        return True, "Password doesn't contain obvious dictionary words", 10

    def check_blacklist(self, password: str) -> Tuple[bool, str, int]:
        """Check if the password is in the blacklist."""
        if password in self.blacklist:
            return False, "Password is blacklisted", 0
        return True, "Password is not blacklisted", 10

    def calculate_entropy(self, password: str) -> Tuple[float, int]:
        """Calculate the entropy of the password."""
        char_pool = 0
        if re.search(r'[a-z]', password): char_pool += 26
        if re.search(r'[A-Z]', password): char_pool += 26
        if re.search(r'\d', password): char_pool += 10
        if re.search(r'[^a-zA-Z0-9]', password): char_pool += 33
        entropy = math.log2(char_pool ** len(password)) if char_pool > 0 else 0
        entropy_score = min(25, int(entropy / 100 * 25))
        return entropy, entropy_score

    def evaluate_password(self, password: str) -> Dict[str, Union[bool, str, int, float]]:
        """Evaluate password complexity and return detailed results."""
        results = {}
        total_score = 0

        length_ok, length_msg, length_score = self.check_length(password)
        results["length"] = {"pass": length_ok, "message": length_msg, "score": length_score}
        total_score += length_score

        categories_ok, categories_msg, categories_score = self.check_character_categories(password)
        results["categories"] = {"pass": categories_ok, "message": categories_msg, "score": categories_score}
        total_score += categories_score

        common_ok, common_msg, common_score = self.check_common_password(password)
        results["common_password"] = {"pass": common_ok, "message": common_msg, "score": common_score}
        total_score += common_score

        sequences_ok, sequences_msg, sequences_score = self.check_sequences(password)
        results["sequences"] = {"pass": sequences_ok, "message": sequences_msg, "score": sequences_score}
        total_score += sequences_score

        dictionary_ok, dictionary_msg, dictionary_score = self.check_dictionary_words(password)
        results["dictionary"] = {"pass": dictionary_ok, "message": dictionary_msg, "score": dictionary_score}
        total_score += dictionary_score

        blacklist_ok, blacklist_msg, blacklist_score = self.check_blacklist(password)
        results["blacklist"] = {"pass": blacklist_ok, "message": blacklist_msg, "score": blacklist_score}
        total_score += blacklist_score

        entropy, entropy_score = self.calculate_entropy(password)
        results["entropy"] = {"pass": entropy_score > 0, "value": entropy, "message": f"Password entropy: {entropy:.2f} bits", "score": entropy_score}
        total_score += entropy_score

        results["total_score"] = total_score
        if total_score < 30:
            strength = "Weak"
        elif total_score < 60:
            strength = "Moderate"
        elif total_score < 80:
            strength = "Strong"
        else:
            strength = "Very Strong"
        results["strength"] = strength

        self.checked_passwords.append((password, results))
        return results

    def generate_password(self, length: int = 12, use_uppercase: bool = True, use_digits: bool = True, use_special: bool = True) -> str:
        """Generate a strong, random password."""
        if length < self.min_length:
            raise ValueError(f"Password length should be at least {self.min_length}")

        characters = string.ascii_lowercase
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_digits:
            characters += string.digits
        if use_special:
            characters += string.punctuation

        if not any([use_uppercase, use_digits, use_special]):
            raise ValueError("At least one additional character category must be selected")

        # Ensure at least one character from each selected category is included
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase) if use_uppercase else None,
            secrets.choice(string.digits) if use_digits else None,
            secrets.choice(string.punctuation) if use_special else None
        ]
        password = [char for char in password if char is not None]

        # Fill the rest of the password length with random choices from the character set
        password += [secrets.choice(characters) for _ in range(length - len(password))]

        # Shuffle to prevent predictable patterns
        secrets.SystemRandom().shuffle(password)

        return ''.join(password)

    def generate_feedback(self, results: Dict) -> List[str]:
        """Generate feedback and suggestions based on evaluation results."""
        feedback = []
        if not results["length"]["pass"]:
            if "too short" in results["length"]["message"]:
                feedback.append(f"Increase password length to at least {self.min_length} characters")
            else:
                feedback.append(f"Decrease password length to maximum {self.max_length} characters")
        if not results["categories"]["pass"]:
            feedback.append("Include a mix of uppercase letters, lowercase letters, numbers, and special characters")
        if not results["common_password"]["pass"]:
            feedback.append("Avoid using common passwords that are easy to guess")
        if not results["sequences"]["pass"]:
            feedback.append("Avoid using sequential characters or keyboard patterns")
        if not results["dictionary"]["pass"]:
            feedback.append("Avoid using common dictionary words")
        if not results["blacklist"]["pass"]:
            feedback.append("Avoid using blacklisted passwords")
        if results["entropy"]["value"] < 60:
            feedback.append("Increase complexity by using more character types and length")
        if not feedback:
            feedback.append("Your password meets all basic security requirements")
            if results["total_score"] < 80:
                feedback.append("For even stronger security, consider increasing length or complexity")
        return feedback

class PasswordChecker:
    """Menu-driven interface for the password complexity checker"""

    def __init__(self, blacklist_path: str = None):
        """Initialize the CLI interface."""
        self.blacklist = self.load_blacklist(blacklist_path) if blacklist_path else set()
        self.checker = PasswordComplexityChecker(blacklist=self.blacklist)

    def load_blacklist(self, file_path: str) -> set:
        """Load the blacklist from a file into a set."""
        blacklist = set()
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    password = line.strip()
                    if password:
                        blacklist.add(password)
        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found")
        except Exception as e:
            print(f"Error loading blacklist: {e}")
        return blacklist

    def display_banner(self):
        """Display the ASCII art banner with animation."""
        neon_colors = [self.checker.COLOR_PURPLE, self.checker.COLOR_PINK, self.checker.COLOR_BRIGHT_GREEN,
                       self.checker.COLOR_BRIGHT_YELLOW, self.checker.COLOR_BRIGHT_BLUE, self.checker.COLOR_BRIGHT_CYAN]

        banner_lines = [
            f"{neon_colors[0]}██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗      ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗{self.checker.COLOR_RESET}",
            f"{neon_colors[1]}██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝{self.checker.COLOR_RESET}",
            f"{neon_colors[2]}██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║    ██║     ███████║█████╗  ██║     █████╔╝ {self.checker.COLOR_RESET}",
            f"{neon_colors[3]}██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║    ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ {self.checker.COLOR_RESET}",
            f"{neon_colors[4]}██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝    ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗{self.checker.COLOR_RESET}",
            f"{neon_colors[5]}╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝      ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝{self.checker.COLOR_RESET}",
            f"{self.checker.COLOR_BRIGHT_CYAN}                        ADVANCED PASSWORD CHECKER{self.checker.COLOR_RESET}"
        ]

        try:
            # Line-by-line animation effect
            for line in banner_lines:
                sys.stdout.write(line + '\n')
                sys.stdout.flush()
                time.sleep(0.2)  # Delay between lines
            print()

            # Display developer credit
            print(f"{self.checker.COLOR_BRIGHT_CYAN}Password Complexity Checker Menu:{self.checker.COLOR_RESET}")
            print("1. Check Single Password")
            print("2. Generate Password")
            print("3. Check Passwords from File")
            print("4. View Statistics")
            print("5. Clear History")
            print("6. Exit")
            print("\nSelect an option:")

        except KeyboardInterrupt:
            # In case user interrupts the banner animation
            print(f"\n{self.checker.COLOR_BRIGHT_CYAN}Banner display interrupted. Moving on...{self.checker.COLOR_RESET}")

    def _print_colored(self, message: str, color=None):
        """Print colored output."""
        if color:
            print(f"{color}{message}{Style.RESET_ALL}")
        else:
            print(message)

    def _print_result(self, label: str, result: Dict[str, Union[bool, str, int, float]], indent: int = 0):
        """Print a formatted result with color coding."""
        indent_str = " " * indent
        if "pass" in result:
            if result["pass"]:
                status = "✓"
                color = Fore.GREEN
            else:
                status = "✗"
                color = Fore.RED
            self._print_colored(f"{indent_str}{status} {label}: {result['message']}", color)
        else:
            self._print_colored(f"{indent_str}• {label}: {result['message']}", Fore.BLUE)

    def _print_feedback(self, feedback: List[str]):
        """Print feedback with formatting."""
        print("\nSuggestions to improve your password:")
        for i, suggestion in enumerate(feedback, 1):
            self._print_colored(f"{i}. {suggestion}", Fore.YELLOW)

    def _print_score_bar(self, score: int):
        """Print a visual representation of the password score."""
        bar_length = 40
        filled_length = int(score / 100 * bar_length)
        if score < 30:
            color = Fore.RED
        elif score < 60:
            color = Fore.YELLOW
        elif score < 80:
            color = Fore.BLUE
        else:
            color = Fore.GREEN
        bar = "█" * filled_length + "░" * (bar_length - filled_length)
        print(f"Score: {color}{score}/100 {Style.RESET_ALL}[{color}{bar}{Style.RESET_ALL}]")

    def safe_input(self, prompt):
        """Handle keyboard interrupts during input calls"""
        try:
            return input(prompt).strip()
        except KeyboardInterrupt:
            print(f"\n{self.checker.COLOR_BRIGHT_CYAN}Operation cancelled by user.{self.checker.COLOR_RESET}")
            return ""
        except Exception as e:
            print(f"{self.checker.COLOR_RED}Input error: {str(e)}{self.checker.COLOR_RESET}")
            return ""

    def check_single_password(self):
        """Check and display results for a single password."""
        password = self.safe_input("Enter password to check: ")
        if not password:
            self._print_colored("Please enter a password to check", Fore.YELLOW)
            return
        results = self.checker.evaluate_password(password)

        print("\n===== Password Complexity Analysis =====\n")
        if len(password) > 2:
            masked = password[0] + "*" * (len(password) - 2) + password[-1]
        else:
            masked = "**"
        print(f"Password: {masked}\n")

        length_result = results.get("length", {"pass": False, "message": "", "score": 0})
        self._print_result("Length", length_result)
        entropy_result = {
            "pass": results["entropy"].get("pass", False) if isinstance(results["entropy"], dict) else False,
            "message": results["entropy"]["message"] if isinstance(results["entropy"], dict) else "",
            "score": results["entropy"].get("score", 0) if isinstance(results["entropy"], dict) else 0
        }
        self._print_result("Entropy", entropy_result)
        self._print_result("Common Password Check", results.get("common_password", {"pass": False, "message": "", "score": 0}))
        self._print_result("Sequence Check", results["sequences"])
        self._print_result("Dictionary Check", results["dictionary"])
        entropy_result = {
            "pass": results["entropy"]["pass"],
            "message": results["entropy"]["message"] if isinstance(results["entropy"], dict) else "",
            "score": results["entropy"].get("score", 0) if isinstance(results["entropy"], dict) else 0
        }
        self._print_result("Entropy", entropy_result)
        self._print_result("Character Categories", results.get("categories", {}))
        self._print_result("Common Password Check", results["common_password"])
        self._print_result("Sequence Check", results["sequences"])
        self._print_result("Dictionary Check", results["dictionary"])
        self._print_result("Blacklist Check", results["blacklist"])
        self._print_result("Entropy", results["entropy"])

        print("\n----- Overall Assessment -----")
        self._print_score_bar(int(results["total_score"]))
        strength = results["strength"]
        color = Fore.RED if strength == "Weak" else Fore.YELLOW if strength == "Moderate" else Fore.BLUE if strength == "Strong" else Fore.GREEN
        print(f"Strength: {color}{strength}{Style.RESET_ALL}")

        feedback = self.checker.generate_feedback(results)
        self._print_feedback(feedback)

    def generate_password_menu(self):
        """Generate a new password based on user preferences."""
        try:
            length = int(self.safe_input("Enter the desired password length: "))
            use_uppercase = self.safe_input("Include uppercase letters? (y/n): ").strip().lower() == 'y'
            use_digits = self.safe_input("Include digits? (y/n): ").strip().lower() == 'y'
            use_special = self.safe_input("Include special characters? (y/n): ").strip().lower() == 'y'

            password = self.checker.generate_password(length, use_uppercase, use_digits, use_special)
            print(f"\nGenerated Password: {password}")

            # Evaluate the generated password
            results = self.checker.evaluate_password(password)
            feedback = self.checker.generate_feedback(results)
            self._print_feedback(feedback)

        except ValueError as e:
            self._print_colored(f"Error: {e}", Fore.RED)

    def check_passwords_from_file(self):
        """Check multiple passwords from a file."""
        filename = self.safe_input("Enter the path to the password file: ")
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
                passwords = [line.strip() for line in file if line.strip()]

            print(f"\nAnalyzing {len(passwords)} passwords from '{filename}'...")
            results = []
            for password in passwords:
                result = self.checker.evaluate_password(password)
                results.append((password, result))

            print("\n===== Password Analysis Summary =====\n")
            print(f"{'Password':<20} {'Score':<10} {'Strength':<15}")
            print("-" * 45)

            for password, result in results:
                if len(password) > 16:
                    masked = password[:8] + "..." + password[-5:]
                elif len(password) > 2:
                    masked = password[0] + "*" * (len(password) - 2) + password[-1]
                else:
                    masked = "**"
                strength = result["strength"]
                score = result["total_score"]
                color = Fore.RED if strength == "Weak" else Fore.YELLOW if strength == "Moderate" else Fore.BLUE if strength == "Strong" else Fore.GREEN
                print(f"{masked:<20} {score:<10} {color}{strength}{Style.RESET_ALL}")

            print("\nAnalysis complete. Results have been added to history for statistics.")

        except FileNotFoundError:
            self._print_colored(f"Error: File '{filename}' not found", Fore.RED)
        except Exception as e:
            self._print_colored(f"Error processing file: {e}", Fore.RED)

    def view_statistics(self):
        """Display statistics of all checked passwords."""
        if not self.checker.checked_passwords:
            self._print_colored("No passwords have been checked yet.", Fore.YELLOW)
            return

        print("\n===== Password Analysis Statistics =====\n")
        strengths = [r[1]["strength"] for r in self.checker.checked_passwords]
        scores = [r[1]["total_score"] for r in self.checker.checked_passwords]

        print(f"Total Passwords Checked: {len(self.checker.checked_passwords)}")
        print(f"Average Score: {sum(scores) / len(scores):.2f}/100")
        print(f"Weak: {strengths.count('Weak')} ({strengths.count('Weak') / len(strengths) * 100:.1f}%)")
        print(f"Moderate: {strengths.count('Moderate')} ({strengths.count('Moderate') / len(strengths) * 100:.1f}%)")
        print(f"Strong: {strengths.count('Strong')} ({strengths.count('Strong') / len(strengths) * 100:.1f}%)")
        print(f"Very Strong: {strengths.count('Very Strong')} ({strengths.count('Very Strong') / len(strengths) * 100:.1f}%)")

    def clear_history(self):
        """Clear the history of checked passwords."""
        self.checker.checked_passwords = []
        self._print_colored("Password history cleared.", Fore.GREEN)

    def display_menu(self):
        """Display the menu options."""
        self.display_banner()

    def run(self):
        """Run the menu-driven interface."""
        while True:
            self.display_menu()
            choice = self.safe_input("")

            if choice == '1':
                self.check_single_password()
            elif choice == '2':
                self.generate_password_menu()
            elif choice == '3':
                self.check_passwords_from_file()
            elif choice == '4':
                self.view_statistics()
            elif choice == '5':
                self.clear_history()
            elif choice == '6':
                self._print_colored("Exiting Password Complexity Checker. Goodbye!", Fore.CYAN)
                break
            else:
                self._print_colored("Invalid option. Please select a number between 1 and 6.", Fore.RED)

if __name__ == "__main__":
    use_blacklist = input("Do you want to use a blacklist file? (y/n): ").strip().lower() == 'y'
    blacklist_path = None
    
    if use_blacklist:
        print(f"{Fore.CYAN}Suggested blacklist files:{Style.RESET_ALL}")
        print("* rockyou.txt")
        print("* SecLists")
        print("* darkweb2017.txt")
        print("* probable-v2-top12000.txt")
        print("* john.txt")
        print("* fuzzing-lowercase.txt")
        print("* doxing-wordlists")
        print("* xato-net-10-million.txt")
        print("* crunch")
        print("* common-passwords.txt")
        print("* phpbb.txt")
        print("* elitehacker.txt")
        print("* facebook-phished.txt")
        print("* wpa.txt")
        
        blacklist_path = input("\nEnter the path to the blacklist file (e.g., path/to/rockyou.txt): ").strip()
        if not blacklist_path:
            print(f"{Fore.YELLOW}No blacklist path provided. Proceeding without blacklist.{Style.RESET_ALL}")
    
    checker = PasswordChecker(blacklist_path=blacklist_path)
    checker.run()