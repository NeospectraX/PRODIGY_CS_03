# 🔒 Password Complexity Checker

An advanced tool to evaluate password strength and generate secure passwords. Built with Python, this project provides detailed feedback on password complexity, including entropy, character categories, and common patterns to avoid.

---

## 🔥 Features
✅ **Password Strength Analysis:**
- Checks password length, entropy, sequences, and common patterns  
✅ **Password Generator:**
- Generates strong, random passwords with customizable options  
✅ **File Analysis:**
- Analyzes multiple passwords from a file  
✅ **Statistics Viewer:**
- Provides detailed password strength metrics  
✅ **Colorful CLI Interface:**
- Enhanced display powered by `colorama`  
✅ **Blacklist Support:**
- Optional feature to block common weak passwords  

---

## 📋 Prerequisites
- Python 3.8 or higher  
- Dependencies listed in `requirements.txt`

---

## 💻 Installation

1. **Clone the Repository:**
```bash
git clone https://github.com/NeospectraX/PRODIGY_CS_03.git
cd password-complexity-checker
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run the tool:**
```bash
python password_checker.py
```

---

## 🚀 Usage

1. **Launch the tool:**
```bash
python password_checker.py
```

2. **Choose an option from the menu:**

🔹 **Check a Single Password:** Evaluate one password's strength  
🔹 **Generate a Random Password:** Create a strong, secure password  
🔹 **Analyze Passwords from a File:** Review multiple password strengths  
🔹 **View Statistics:** Display detailed analysis metrics  
🔹 **Clear History:** Erase previously stored data  
🔹 **Exit:** Quit the program  

---

## 📖 Example Usage

### 🧾 Check a Single Password
```
Enter password to check: MyP@ssw0rd
Password: M********d

✓ Length: Password length (9) is adequate
✓ Entropy: Password entropy: 53.46 bits
✗ Common Password Check: Password is not in the common passwords list
✓ Sequence Check: Password doesn't contain obvious sequences
✗ Dictionary Check: Password contains a common dictionary word: 'password'
✓ Blacklist Check: Password is not blacklisted

Score: 45/100 [███████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░]
Strength: Moderate
```

---

## 📦 Requirements
See `requirements.txt` for the full list of dependencies.

---

## 📝 License
This project is licensed under the **MIT License**.

💬 _Contributions are welcome! Feel free to fork, improve, and submit pull requests._

