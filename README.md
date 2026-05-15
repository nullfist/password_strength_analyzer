# 🛡️ Advanced Password Strength Analyzer

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: Enterprise](https://img.shields.io/badge/Security-Enterprise--Grade-red.svg)]()

A production-grade Password Strength Analysis Platform designed for cybersecurity professionals. This tool evaluates passwords using modern security engineering methodologies, entropy analysis, and attack simulation logic.

Developed by **Syed**.

## 🚀 Features

- **Entropy Analysis**: Implements Shannon Entropy calculations to determine theoretical crack resistance.
- **Pattern Detection**: Detects sequential characters, keyboard walks, common substitutions, and predictable human structures.
- **Attack Simulation**: Estimates crack time for Offline GPU attacks, Online throttled attacks, and Distributed systems.
- **Secure Generator**: Cryptographically secure password generation using the Python `secrets` module.
- **Complexity Scoring**: Weighted scoring engine (0-100) with threat levels (CRITICAL to MILITARY-GRADE).

## 🛠️ Tech Stack

- **Core**: Python 3.11+
- **Security**: `zxcvbn`, `bcrypt`, `secrets`
- **Data/Math**: `numpy`, `math`
- **UI/Terminal**: `rich`

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/nullfist/password-analyzer.git
   cd password-analyzer
   ```

2. Setup virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 🖥️ Usage

Run the evaluation engine:
```bash
python analyzer.py
```

## 📊 Security Intelligence

The engine classifies passwords into five threat levels:
- 🔴 **CRITICAL**: Vulnerable to instant dictionary attacks.
- 🟠 **HIGH RISK**: Weak entropy, easily cracked by home hardware.
- 🟡 **MODERATE**: Reasonable length but lacks complexity.
- 🟢 **SECURE**: Strong entropy, resistant to most attacks.
- 💎 **MILITARY-GRADE**: Extremely high entropy, cryptographically robust.

## 🤝 Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## 📜 License
Distributed under the MIT License. See `LICENSE` for more information.
