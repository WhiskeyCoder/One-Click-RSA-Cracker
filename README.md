# One CLick RSA Cracking Tool

A comprehensive, one-click tool for breaking RSA encryption using multiple attack vectors. Simply provide a ciphertext and minimal key information, and the tool will attempt all possible attacks to break the encryption.

## Features

- **Automatic Attack Selection**: Tries multiple attack strategies based on the provided parameters
- **Key Format Support**: Handles various key formats (PEM, certificates, SSH keys, numeric formats)
- **Online Factorization**: Optional integration with online factorization services
- **Multiple Attack Vectors**:
  - Small prime factor attacks
  - Small exponent attacks (cube root when e=3)
  - Wiener's attack for small private exponents
  - Hastad's broadcast attack
  - Common modulus attack
  - Franklin-Reiter related message attack
  - Advanced factorization methods

## Installation

### Requirements

- Python 3.6 or higher
- Basic dependencies: None required for core functionality

### Optional Dependencies

Install these for enhanced functionality:

```bash
pip install gmpy2 cryptography sympy pycryptodome factordb tqdm
```

- `gmpy2`: Faster mathematical operations and root finding
- `cryptography`: Better key parsing and handling
- `sympy`: Additional attack implementations
- `pycryptodome`: Enhanced cryptographic operations
- `factordb`: API integration with FactorDB
- `tqdm`: Progress bars for long-running operations

## Quick Start

### One-Click Mode

The simplest way to use the tool is in auto mode, which requires minimal input:

```bash
python rsa_cracker.py --auto
```

This will prompt you for the necessary information and attempt all possible attacks.

### Command-Line Usage

For more control, specify parameters directly:

```bash
python rsa_cracker.py --ciphertext 12345... --n 98765... --e 65537
```

### Using Key Files

Instead of specifying n and e directly, you can provide a key file:

```bash
python rsa_cracker.py --ciphertext 12345... --key-file public_key.pem
```

## Advanced Usage

### Multiple Attack Vectors

#### For Hastad's Broadcast Attack

When the same message is encrypted with the same small exponent to multiple recipients:

```bash
python rsa_cracker.py --multiple-ciphertexts "c1" "c2" "c3" --multiple-moduli "n1" "n2" "n3" --e 3
```

#### For Common Modulus Attack

When the same message is encrypted with different exponents but the same modulus:

```bash
python rsa_cracker.py --ciphertext "c1" --e "e1" --second-ciphertext "c2" --second-exponent "e2" --n "modulus"
```

### Advanced Configuration

```bash
# Enable deep scan with more time-consuming attacks
python rsa_cracker.py --ciphertext 12345... --n 98765... --deep-scan

# Disable online factorization services
python rsa_cracker.py --ciphertext 12345... --n 98765... --no-online-lookup

# Set timeout for attack methods
python rsa_cracker.py --ciphertext 12345... --n 98765... --timeout 600

# Control parallel execution
python rsa_cracker.py --ciphertext 12345... --n 98765... --max-workers 8
```

## Output Options

```bash
# Save results to a file
python rsa_cracker.py --ciphertext 12345... --n 98765... --output-file results.json

# Choose output format
python rsa_cracker.py --ciphertext 12345... --n 98765... --output-format text --output-file results.txt

# Enable verbose output
python rsa_cracker.py --ciphertext 12345... --n 98765... --verbose
```

## Example Use Cases

### Capture The Flag (CTF) Challenges

Perfect for CTF challenges involving RSA where you have limited information:

```bash
python rsa_cracker.py --ciphertext 12345... --n 98765... --e 3 --auto
```

### Educational Use

Demonstrates various RSA vulnerabilities for security education:

```bash
python rsa_cracker.py --key-file vulnerable_key.pem --ciphertext 12345... --verbose
```

### Security Auditing

Test the security of RSA implementations:

```bash
python rsa_cracker.py --ciphertext 12345... --n 98765... --e 65537 --deep-scan --output-file audit_report.json
```

## Security Considerations

This tool is designed for **educational purposes** and security research. It demonstrates known weaknesses in RSA implementations and should not be used to attack systems without proper authorization.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
