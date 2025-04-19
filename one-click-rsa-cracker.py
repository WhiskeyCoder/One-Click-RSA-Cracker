#!/usr/bin/env python3
"""
Enhanced RSA Cracking Tool

A comprehensive, automated tool for breaking RSA encryption using multiple attack vectors.
Just provide a public key, certificate, or ciphertext, and the tool will attempt all possible
attack methods to break the encryption.

Author: [Your Name]
Date: April 2025
"""

import argparse
import base64
import binascii
import json
import math
import os
import re
import requests
import subprocess
import sys
import tempfile
import time
from typing import Dict, Tuple, List, Optional, Union, Any
from urllib.parse import quote_plus


class RSACrackingTool:
    """
    Comprehensive tool for automatic RSA cryptanalysis.
    """

    def __init__(self, verbose: bool = False, online_lookup: bool = True, max_workers: int = 4,
                 deep_scan: bool = False, timeout: int = 300):
        """
        Initialize the RSA cracking tool.

        Args:
            verbose: Whether to print detailed information
            online_lookup: Whether to use online services for factorization
            max_workers: Maximum number of parallel workers for attacks
            deep_scan: Whether to try more exhaustive/time-consuming attacks
            timeout: Maximum time in seconds for each attack method
        """
        self.verbose = verbose
        self.online_lookup = online_lookup
        self.max_workers = max_workers
        self.deep_scan = deep_scan
        self.timeout = timeout

        # Track attempted attack methods
        self.attempted_methods = set()

        # Try to import optional dependencies
        self.optional_deps = self._check_optional_dependencies()

    def log(self, message: str, level: str = 'INFO') -> None:
        """Print a message if verbose mode is enabled or for important messages."""
        if self.verbose or level in ['WARNING', 'ERROR', 'SUCCESS']:
            prefix = f"[{level}]"
            if level == 'SUCCESS':
                prefix = "[✓]"
            elif level == 'ERROR':
                prefix = "[✗]"
            elif level == 'WARNING':
                prefix = "[!]"
            print(f"{prefix} {message}")

    def _check_optional_dependencies(self) -> Dict[str, bool]:
        """Check which optional dependencies are available."""
        dependencies = {
            'gmpy2': False,
            'cryptography': False,
            'sympy': False,
            'pycryptodome': False,
            'factordb': False,
            'tqdm': False
        }

        # Try to import each dependency
        try:
            import gmpy2
            dependencies['gmpy2'] = True
        except ImportError:
            pass

        try:
            import cryptography
            dependencies['cryptography'] = True
        except ImportError:
            pass

        try:
            import sympy
            dependencies['sympy'] = True
        except ImportError:
            pass

        try:
            import Crypto
            dependencies['pycryptodome'] = True
        except ImportError:
            pass

        try:
            import factordb.factordb
            dependencies['factordb'] = True
        except ImportError:
            pass

        try:
            import tqdm
            dependencies['tqdm'] = True
        except ImportError:
            pass

        return dependencies

    # ===== Utility Methods =====

    @staticmethod
    def int_to_string(value: int) -> str:
        """
        Convert an integer to its string representation.

        Args:
            value: Integer to convert

        Returns:
            String representation of the integer

        Raises:
            ValueError: If the integer cannot be converted to a valid string
        """
        try:
            # Ensure the hex representation has an even number of digits
            hex_string = format(value, "x")
            if len(hex_string) % 2 != 0:
                hex_string = '0' + hex_string

            return binascii.unhexlify(hex_string.encode("utf-8")).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as e:
            raise ValueError(f"Failed to convert integer to string: {str(e)}")

    @staticmethod
    def string_to_int(message: Union[str, bytes]) -> int:
        """
        Convert a string or bytes to an integer representation.

        Args:
            message: Input string or bytes to convert

        Returns:
            Integer representation of the input
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        return int(binascii.hexlify(message), 16)

    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """
        Extended Euclidean Algorithm to find gcd(a, b) and coefficients x, y
        such that ax + by = gcd(a, b).

        Args:
            a: First integer
            b: Second integer

        Returns:
            Tuple of (gcd, x, y) where ax + by = gcd
        """
        if a == 0:
            return b, 0, 1

        # Initialize variables
        last_remainder, remainder = abs(a), abs(b)
        x, last_x, y, last_y = 0, 1, 1, 0

        # Compute extended GCD iteratively
        while remainder:
            quotient, remainder = divmod(last_remainder, remainder)
            x, last_x = last_x - quotient * x, x
            y, last_y = last_y - quotient * y, y
            last_remainder = remainder

        # Adjust signs based on input
        return (
            last_remainder,
            last_x * (-1 if a < 0 else 1),
            last_y * (-1 if b < 0 else 1)
        )

    @staticmethod
    def mod_inverse(a: int, m: int) -> int:
        """
        Calculate the modular multiplicative inverse of a modulo m.

        Args:
            a: Integer to find inverse for
            m: Modulus

        Returns:
            Modular multiplicative inverse

        Raises:
            ValueError: If a and m are not coprime (inverse doesn't exist)
        """
        gcd, x, y = RSACrackingTool.extended_gcd(a, m)

        # Inverse exists only if gcd is 1
        if gcd != 1:
            raise ValueError(f"Modular inverse does not exist (gcd={gcd})")

        # Ensure the result is in the range [0, m-1]
        return x % m

    @staticmethod
    def is_prime(n: int, k: int = 10) -> bool:
        """
        Check if a number is prime using Miller-Rabin primality test.

        Args:
            n: Number to check for primality
            k: Number of test rounds (higher values increase accuracy)

        Returns:
            True if the number is probably prime, False otherwise
        """
        import random

        # Handle small cases
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        # Express n as 2^r * d + 1
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # Witness loop
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def perfect_eth_root(n: int, e: int) -> Optional[int]:
        """
        Check if n is a perfect eth power and return its eth root if true.

        Args:
            n: Number to check
            e: Exponent to check

        Returns:
            The eth root of n if n is a perfect eth power, None otherwise
        """
        # Try to use gmpy2 for better performance if available
        try:
            import gmpy2
            root = gmpy2.iroot(n, e)
            if root[1]:  # iroot returns (root, is_exact)
                return int(root[0])
            return None
        except ImportError:
            pass

        # Fallback to pure Python implementation
        # Calculate an approximate root
        root = round(n ** (1 / e))

        # Check if this is indeed an eth root
        if root ** e == n:
            return root

        # Try a few values around the approximation
        for i in range(1, 1000):
            if (root + i) ** e == n:
                return root + i
            if (root - i) ** e == n:
                return root - i

        return None

    @staticmethod
    def newton_method_root(n: int, k: int, precision: int = 100) -> int:
        """
        Calculate the kth root of n using Newton's method.

        Args:
            n: The number to find the root of
            k: The root to find (e.g., 2 for square root, 3 for cube root)
            precision: Number of iterations for convergence

        Returns:
            The kth root of n as an integer
        """
        u, s = n, n + 1
        while u < s:
            s = u
            t = (k - 1) * s + n // pow(s, k - 1)
            u = t // k
        return s

    # ===== Key Parsing Methods =====

    def parse_pem_key(self, pem_data: str) -> Dict[str, int]:
        """
        Parse a PEM-formatted RSA key file.

        Args:
            pem_data: The PEM key data

        Returns:
            Dictionary of RSA parameters
        """
        # Try using cryptography library if available
        if self.optional_deps['cryptography']:
            try:
                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

                try:
                    # Try as private key first
                    key = load_pem_private_key(pem_data.encode(), password=None, backend=default_backend())
                    if isinstance(key, rsa.RSAPrivateKey):
                        private_numbers = key.private_numbers()
                        public_numbers = private_numbers.public_numbers

                        return {
                            'n': public_numbers.n,
                            'e': public_numbers.e,
                            'd': private_numbers.d,
                            'p': private_numbers.p,
                            'q': private_numbers.q,
                            'dp': private_numbers.dmp1,
                            'dq': private_numbers.dmq1,
                            'qinv': private_numbers.iqmp,
                        }
                except Exception:
                    pass

                try:
                    # Try as public key
                    key = load_pem_public_key(pem_data.encode(), backend=default_backend())
                    if isinstance(key, rsa.RSAPublicKey):
                        public_numbers = key.public_numbers()

                        return {
                            'n': public_numbers.n,
                            'e': public_numbers.e
                        }
                except Exception:
                    pass
            except Exception as e:
                self.log(f"Error parsing PEM with cryptography: {str(e)}", level="WARNING")

        # Fallback to manual parsing
        params = {}

        # Check for public key format
        modulus_match = re.search(r'Modulus:\s*([0-9a-fA-F:]+)', pem_data)
        exponent_match = re.search(r'Exponent:\s*([0-9]+)', pem_data)

        if modulus_match and exponent_match:
            modulus_hex = modulus_match.group(1).replace(':', '')
            params['n'] = int(modulus_hex, 16)
            params['e'] = int(exponent_match.group(1))
            return params

        # Extract base64-encoded data
        base64_data = ''
        in_key = False

        for line in pem_data.splitlines():
            line = line.strip()
            if line.startswith('-----BEGIN ') and line.endswith('-----'):
                in_key = True
                continue
            if line.startswith('-----END ') and line.endswith('-----'):
                in_key = False
                continue
            if in_key:
                base64_data += line

        if not base64_data:
            raise ValueError("No base64-encoded key data found in PEM")

        # Try to decode and extract parameters using ASN.1
        try:
            key_bytes = base64.b64decode(base64_data)

            # Use PyCryptodome if available
            if self.optional_deps['pycryptodome']:
                try:
                    from Crypto.PublicKey import RSA
                    key = RSA.import_key(pem_data)

                    if key.has_private():
                        return {
                            'n': key.n,
                            'e': key.e,
                            'd': key.d,
                            'p': key.p,
                            'q': key.q
                        }
                    else:
                        return {
                            'n': key.n,
                            'e': key.e
                        }
                except Exception as e:
                    self.log(f"Error parsing PEM with PyCryptodome: {str(e)}", level="WARNING")

            # Fallback to basic ASN.1 parsing for common formats
            # This is a simplified implementation and won't handle all cases
            if key_bytes[0] == 0x30:  # ASN.1 SEQUENCE
                # Check if it's likely a public key
                if b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01' in key_bytes:  # OID for RSA
                    self.log("Detected RSA public key format in ASN.1 data", level="INFO")
                    # This is a rudimentary parser and won't work for all cases
                    pass

        except Exception as e:
            self.log(f"Failed to parse key bytes: {str(e)}", level="WARNING")

        # If we couldn't parse anything
        if not params:
            raise ValueError("Failed to extract RSA parameters from PEM data")

        return params

    def parse_certificate(self, cert_data: str) -> Dict[str, int]:
        """
        Parse an X.509 certificate to extract RSA parameters.

        Args:
            cert_data: The certificate data

        Returns:
            Dictionary of RSA parameters
        """
        # Try using cryptography library if available
        if self.optional_deps['cryptography']:
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives.asymmetric import rsa

                cert = x509.load_pem_x509_certificate(cert_data.encode(), default_backend())
                pubkey = cert.public_key()

                if isinstance(pubkey, rsa.RSAPublicKey):
                    public_numbers = pubkey.public_numbers()
                    return {
                        'n': public_numbers.n,
                        'e': public_numbers.e
                    }
            except Exception as e:
                self.log(f"Error parsing certificate with cryptography: {str(e)}", level="WARNING")

        # Use OpenSSL as fallback
        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp:
                temp.write(cert_data.encode())
                temp_name = temp.name

            command = ['openssl', 'x509', '-in', temp_name, '-text', '-noout']
            result = subprocess.run(command, capture_output=True, text=True)
            os.unlink(temp_name)

            if result.returncode == 0:
                output = result.stdout

                # Extract modulus
                modulus_match = re.search(r'Modulus:\s*([0-9a-fA-F:]+)', output)
                exponent_match = re.search(r'Exponent:\s*([0-9]+)', output)

                if modulus_match and exponent_match:
                    modulus_hex = modulus_match.group(1).replace(':', '')
                    n = int(modulus_hex, 16)
                    e = int(exponent_match.group(1))

                    return {'n': n, 'e': e}

        except Exception as e:
            self.log(f"Error parsing certificate with OpenSSL: {str(e)}", level="WARNING")

        raise ValueError("Failed to extract RSA parameters from certificate")

    def parse_ssh_key(self, key_data: str) -> Dict[str, int]:
        """
        Parse an SSH public key to extract RSA parameters.

        Args:
            key_data: The SSH key data

        Returns:
            Dictionary of RSA parameters
        """
        # Check if it's an SSH public key format
        if key_data.startswith('ssh-rsa'):
            parts = key_data.split()
            if len(parts) >= 2:
                try:
                    key_bytes = base64.b64decode(parts[1])

                    # Parse the SSH key format
                    i = 0

                    # Skip the algorithm identifier
                    alg_len = int.from_bytes(key_bytes[i:i + 4], byteorder='big')
                    i += 4 + alg_len

                    # Extract e
                    e_len = int.from_bytes(key_bytes[i:i + 4], byteorder='big')
                    i += 4
                    e = int.from_bytes(key_bytes[i:i + e_len], byteorder='big')
                    i += e_len

                    # Extract n
                    n_len = int.from_bytes(key_bytes[i:i + 4], byteorder='big')
                    i += 4
                    n = int.from_bytes(key_bytes[i:i + n_len], byteorder='big')

                    return {'n': n, 'e': e}
                except Exception as e:
                    self.log(f"Error parsing SSH key: {str(e)}", level="WARNING")

        raise ValueError("Failed to extract RSA parameters from SSH key")

    def detect_key_format(self, key_data: str) -> str:
        """
        Detect the format of a key file.

        Args:
            key_data: The key data

        Returns:
            Format string ('pem', 'certificate', 'ssh', 'der', 'unknown')
        """
        key_data = key_data.strip()

        # Check for PEM format
        if '-----BEGIN ' in key_data and '-----END ' in key_data:
            if 'CERTIFICATE' in key_data:
                return 'certificate'
            return 'pem'

        # Check for SSH public key
        if key_data.startswith('ssh-rsa '):
            return 'ssh'

        # Check for numeric modulus/exponent format
        if key_data.lower().startswith('n =') or key_data.lower().startswith('modulus ='):
            return 'numeric'

        # Might be DER format (binary)
        if not all(c.isascii() and c.isprintable() for c in key_data):
            return 'der'

        return 'unknown'

    def parse_key_file(self, file_path: str) -> Dict[str, int]:
        """
        Parse an RSA key file in various formats.

        Args:
            file_path: Path to the key file

        Returns:
            Dictionary of RSA parameters
        """
        try:
            with open(file_path, 'r') as f:
                data = f.read()

            format_type = self.detect_key_format(data)

            if format_type == 'pem':
                return self.parse_pem_key(data)
            elif format_type == 'certificate':
                return self.parse_certificate(data)
            elif format_type == 'ssh':
                return self.parse_ssh_key(data)
            elif format_type == 'numeric':
                # Parse numeric format (e.g., n = ..., e = ...)
                params = {}
                lines = data.splitlines()

                for line in lines:
                    line = line.strip()
                    if line.lower().startswith('n =') or line.lower().startswith('modulus ='):
                        value = re.sub(r'^[^=]+=\s*', '', line).strip()
                        if value.startswith('0x'):
                            params['n'] = int(value, 16)
                        else:
                            params['n'] = int(value)
                    elif line.lower().startswith('e =') or line.lower().startswith('exponent ='):
                        value = re.sub(r'^[^=]+=\s*', '', line).strip()
                        if value.startswith('0x'):
                            params['e'] = int(value, 16)
                        else:
                            params['e'] = int(value)
                    elif line.lower().startswith('d ='):
                        value = re.sub(r'^[^=]+=\s*', '', line).strip()
                        if value.startswith('0x'):
                            params['d'] = int(value, 16)
                        else:
                            params['d'] = int(value)
                    elif line.lower().startswith('p ='):
                        value = re.sub(r'^[^=]+=\s*', '', line).strip()
                        if value.startswith('0x'):
                            params['p'] = int(value, 16)
                        else:
                            params['p'] = int(value)
                    elif line.lower().startswith('q ='):
                        value = re.sub(r'^[^=]+=\s*', '', line).strip()
                        if value.startswith('0x'):
                            params['q'] = int(value, 16)
                        else:
                            params['q'] = int(value)

                if 'n' in params and 'e' in params:
                    return params

            # Try binary DER format as last resort
            if format_type == 'der' or format_type == 'unknown':
                try:
                    # Re-open in binary mode
                    with open(file_path, 'rb') as f:
                        data = f.read()

                    # Try PyCryptodome
                    if self.optional_deps['pycryptodome']:
                        from Crypto.PublicKey import RSA
                        key = RSA.import_key(data)

                        if key.has_private():
                            return {
                                'n': key.n,
                                'e': key.e,
                                'd': key.d,
                                'p': key.p,
                                'q': key.q
                            }
                        else:
                            return {
                                'n': key.n,
                                'e': key.e
                            }
                except Exception as e:
                    self.log(f"Error parsing binary key: {str(e)}", level="WARNING")

        except Exception as e:
            self.log(f"Error reading or parsing key file: {str(e)}", level="ERROR")

        raise ValueError(f"Failed to extract RSA parameters from {file_path}")

    # ===== Factorization Methods =====

    def trial_division(self, n: int, limit: int = 1_000_000) -> Optional[int]:
        """
        Find a small prime factor of n using trial division.

        Args:
            n: Number to factor
            limit: Maximum value to test for primality

        Returns:
            A small prime factor if found, None otherwise
        """
        self.log(f"Attempting trial division up to {limit}...")

        # Progress bar if tqdm is available
        if self.optional_deps['tqdm']:
            from tqdm import tqdm
            iterator = tqdm(range(2, min(limit, int(math.sqrt(n)) + 1)))
        else:
            iterator = range(2, min(limit, int(math.sqrt(n)) + 1))

        # Check if n is even
        if n % 2 == 0:
            return 2

        # Check odd numbers up to the limit
        for i in iterator:
            if n % i == 0:
                return i

        return None

    def pollard_rho(self, n: int, max_iterations: int = 100000) -> Optional[int]:
        """
        Try to find a factor of n using Pollard's rho algorithm.

        Args:
            n: Number to factor
            max_iterations: Maximum number of iterations

        Returns:
            A factor of n if found, None otherwise
        """
        import random

        self.log(f"Attempting Pollard's Rho algorithm...")

        if n % 2 == 0:
            return 2

        # Define the function f(x) = (x^2 + c) % n
        def f(x, c):
            return (x * x + c) % n

        # Progress updates for long-running iterations
        update_interval = max(1, max_iterations // 100)

        # Try different values of c if one fails
        for c in range(1, 4):
            x, y, d = 2, 2, 1

            # Main loop
            for i in range(max_iterations):
                if i % update_interval == 0 and self.verbose:
                    print(f"Pollard Rho: iteration {i}/{max_iterations}, c={c}", end='\r')

                x = f(x, c)  # One step
                y = f(f(y, c), c)  # Two steps
                d = math.gcd(abs(x - y), n)

                if 1 < d < n:
                    self.log(f"\nFound factor with Pollard's Rho: {d}", level="SUCCESS")
                    return d
                if d == n:
                    break  # Failed with this c, try another

            self.log(f"Pollard's Rho failed with c={c}")

        return None

    def pollard_p_minus_1(self, n: int, B1: int = 100000, B2: int = 1000000) -> Optional[int]:
        """
        Try to find a factor of n using Pollard's p-1 algorithm.

        Args:
            n: Number to factor
            B1: First bound
            B2: Second bound

        Returns:
            A factor of n if found, None otherwise
        """
        import random

        self.log(f"Attempting Pollard's p-1 algorithm with B1={B1}, B2={B2}...")

        # Try to use gmpy2 for better performance
        if self.optional_deps['gmpy2']:
            try:
                import gmpy2

                # Check if n is a perfect square
                root_n = gmpy2.isqrt(n)
                if gmpy2.is_square(n):
                    root = int(gmpy2.sqrt(n))
                    return (root, root)

                # Fermat's method
                a = root_n + 1
                b2 = gmpy2.square(a) - n

                for i in range(max_iterations):
                    if i % 1000 == 0 and self.verbose:
                        print(f"Fermat: iteration {i}/{max_iterations}", end='\r')

                    if gmpy2.is_square(b2):
                        b = gmpy2.sqrt(b2)
                        p = a + b
                        q = a - b
                        self.log(f"\nFound factorization with Fermat's method: {p}, {q}", level="SUCCESS")
                        return (int(p), int(q))
                    a += 1
                    b2 = gmpy2.square(a) - n

                return None
            except Exception as e:
                self.log(f"Error in gmpy2 implementation of Fermat factorization: {str(e)}", level="WARNING")

        # Fallback to pure Python implementation
        a = math.isqrt(n) + 1
        b2 = a * a - n

        for i in range(max_iterations):
            if i % 1000 == 0 and self.verbose:
                print(f"Fermat: iteration {i}/{max_iterations}", end='\r')

            b_root = math.isqrt(b2)
            if b_root * b_root == b2:
                p = a + b_root
                q = a - b_root
                self.log(f"\nFound factorization with Fermat's method: {p}, {q}", level="SUCCESS")
                return (p, q)
            a += 1
            b2 = a * a - n

        return None Stage 1
                a = 2
                for p in range(2, B1):
                    e = 1
                    while e <= B1 // p:
                        e *= p
                    a = gmpy2.powmod(a, e, n)

                g = gmpy2.gcd(a - 1, n)
                if 1 < g < n:
                    self.log(f"Found factor with Pollard's p-1 (stage 1): {g}", level="SUCCESS")
                    return int(g)

                # Stage 2 (simplified)
                if B2 > B1:
                    for p in range(B1, B2):
                        if gmpy2.is_prime(p):
                            a = gmpy2.powmod(a, p, n)
                            g = gmpy2.gcd(a - 1, n)
                            if 1 < g < n:
                                self.log(f"Found factor with Pollard's p-1 (stage 2): {g}", level="SUCCESS")
                                return int(g)

                return None
            except Exception as e:
                self.log(f"Error in gmpy2 implementation of Pollard's p-1: {str(e)}", level="WARNING")

        # Fallback to pure Python implementation
        a = 2

        # Stage 1
        for p in range(2, B1):
            # If using tqdm and verbose mode
            if p % 1000 == 0 and self.verbose:
                print(f"Pollard p-1: stage 1, testing prime {p}/{B1}", end='\r')

            if self.is_prime(p):
                e = 1
                while e <= B1 // p:
                    e *= p
                a = pow(a, e, n)

        g = math.gcd(a - 1, n)
        if 1 < g < n:
            self.log(f"\nFound factor with Pollard's p-1 (stage 1): {g}", level="SUCCESS")
            return g

        # Stage 2 (simplified)
        if B2 > B1:
            for p in range(B1, min(B2, B1 + 10000)):  # Limit to avoid excessive time
                if p % 100 == 0 and self.verbose:
                    print(f"Pollard p-1: stage 2, testing prime {p}/{min(B2, B1 + 10000)}", end='\r')

                if self.is_prime(p):
                    a = pow(a, p, n)
                    g = math.gcd(a - 1, n)
                    if 1 < g < n:
                        self.log(f"\nFound factor with Pollard's p-1 (stage 2): {g}", level="SUCCESS")
                        return g

        return None


def fermat_factorization(self, n: int, max_iterations: int = 10000) -> Optional[Tuple[int, int]]:
    """
    Try to factor n using Fermat's factorization method.

    Args:
        n: Number to factor
        max_iterations: Maximum number of iterations

    Returns:
        Tuple of (p, q) if successful, None otherwise
    """
    self.log(f"Attempting Fermat factorization...")

    # Check if n is even
    if n % 2 == 0:
        return (2, n // 2)

    # Try to use gmpy2 for better performance
    if self.optional_deps['gmpy2']:
        try:
            import gmpy2

            # Check if n is a perfect square
            root_n = gmpy2.isqrt(n)
            if gmpy2.is_square(n):
                root = int(gmpy2.sqrt(n))
                return (root, root)

            # Fermat's method
            a = root_n + 1
            b2 = gmpy2.square(a) - n

            for i in range(max_iterations):
                if i % 1000 == 0 and self.verbose:
                    print(f"Fermat: iteration {i}/{max_iterations}", end='\r')

                if gmpy2.is_square(b2):
                    b = gmpy2.sqrt(b2)
                    p = a + b
                    q = a - b
                    self.log(f"\nFound factorization with Fermat's method: {p}, {q}", level="SUCCESS")
                    return (int(p), int(q))
                a += 1
                b2 = gmpy2.square(a) - n

            return None
        except Exception as e:
            self.log(f"Error in gmpy2 implementation of Fermat factorization: {str(e)}", level="WARNING")

    # Fallback to pure Python implementation
    a = math.isqrt(n) + 1
    b2 = a * a - n

    for i in range(max_iterations):
        if i % 1000 == 0 and self.verbose:
            print(f"Fermat: iteration {i}/{max_iterations}", end='\r')

        b_root = math.isqrt(b2)
        if b_root * b_root == b2:
            p = a + b_root
            q = a - b_root
            self.log(f"\nFound factorization with Fermat's method: {p}, {q}", level="SUCCESS")
            return (p, q)
        a += 1
        b2 = a * a - n

    return None


def factorize_using_online_services(self, n: int) -> Optional[Tuple[int, int]]:
    """
    Try to factorize n using online factorization services.

    Args:
        n: Number to factorize

    Returns:
        Tuple of (p, q) if successful, None otherwise
    """
    if not self.online_lookup:
        self.log("Online factorization services disabled", level="INFO")
        return None

    self.log("Attempting to factorize using online services...", level="INFO")

    # Try FactorDB API if the library is available
    if self.optional_deps['factordb']:
        try:
            from factordb.factordb import FactorDB

            self.log("Using FactorDB API...", level="INFO")
            f = FactorDB(n)
            f.connect()
            factors = f.get_factor_list()

            if len(factors) == 2:
                p, q = factors
                self.log(f"Found factorization with FactorDB: {p}, {q}", level="SUCCESS")
                return (p, q)
            elif len(factors) > 2:
                # If there are more than 2 factors, find p and q such that p*q = n
                for i in range(len(factors)):
                    for j in range(i + 1, len(factors)):
                        if factors[i] * factors[j] == n:
                            self.log(f"Found factorization with FactorDB: {factors[i]}, {factors[j]}",
                                     level="SUCCESS")
                            return (factors[i], factors[j])

            self.log(f"FactorDB found {len(factors)} factors, but couldn't determine p and q", level="WARNING")
        except Exception as e:
            self.log(f"Error using FactorDB API: {str(e)}", level="WARNING")

    # Try direct HTTP request to factordb.com
    try:
        self.log("Trying direct HTTP request to factordb.com...", level="INFO")
        response = requests.get(f"http://factordb.com/index.php?query={n}")

        if response.status_code == 200:
            # Parse the response for factor information
            result_text = response.text
            # Look for factor links in the HTML
            factor_links = re.findall(r'index\.php\?id=([0-9]+)"', result_text)

            if factor_links:
                factors = []
                for fid in factor_links:
                    # Get factor value
                    factor_response = requests.get(f"http://factordb.com/index.php?id={fid}")
                    if factor_response.status_code == 200:
                        factor_match = re.search(r'value="([0-9]+)"', factor_response.text)
                        if factor_match:
                            factors.append(int(factor_match.group(1)))

                if len(factors) == 2:
                    p, q = factors
                    if p * q == n:
                        self.log(f"Found factorization with FactorDB website: {p}, {q}", level="SUCCESS")
                        return (p, q)
    except Exception as e:
        self.log(f"Error using FactorDB website: {str(e)}", level="WARNING")

    # Try other factorization services
    # (These would need to be integrated based on available APIs)

    return None


# ===== RSA Attack Methods =====

def attack_known_private_key(self, n: int, e: int, d: int, ciphertext: int) -> Dict[str, Any]:
    """
    Decrypt using a known private exponent.

    Args:
        n: Modulus
        e: Public exponent
        d: Private exponent
        ciphertext: The encrypted message

    Returns:
        Dictionary with attack results and decryption if successful
    """
    self.attempted_methods.add('known_private_key')
    self.log("Attempting decryption with known private key...", level="INFO")

    try:
        plaintext = pow(ciphertext, d, n)
        plaintext_str = self.int_to_string(plaintext)

        return {
            'success': True,
            'method': 'known_private_key',
            'plaintext_int': plaintext,
            'plaintext': plaintext_str
        }
    except Exception as e:
        self.log(f"Decryption with known private key failed: {str(e)}", level="WARNING")
        return {'success': False, 'method': 'known_private_key', 'error': str(e)}


def attack_known_prime_factors(self, n: int, e: int, p: int, q: int, ciphertext: int) -> Dict[str, Any]:
    """
    Decrypt using known prime factors.

    Args:
        n: Modulus
        e: Public exponent
        p: First prime factor
        q: Second prime factor
        ciphertext: The encrypted message

    Returns:
        Dictionary with decryption results
    """
    self.attempted_methods.add('known_prime_factors')
    self.log("Attempting decryption with known prime factors...", level="INFO")

    try:
        # Verify p*q = n
        if p * q != n:
            raise ValueError(f"Invalid prime factors: p*q ({p * q}) does not equal n ({n})")

        # Compute private key
        phi_n = (p - 1) * (q - 1)
        d = self.mod_inverse(e, phi_n)

        # Compute CRT parameters for faster decryption
        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = self.mod_inverse(q, p)

        # CRT decryption
        m1 = pow(ciphertext, dp, p)
        m2 = pow(ciphertext, dq, q)
        h = (qinv * ((m1 - m2) % p)) % p
        plaintext = m2 + h * q

        plaintext_str = self.int_to_string(plaintext)

        return {
            'success': True,
            'method': 'known_prime_factors',
            'plaintext_int': plaintext,
            'plaintext': plaintext_str,
            'd': d,
            'phi_n': phi_n,
            'dp': dp,
            'dq': dq,
            'qinv': qinv
        }
    except Exception as e:
        self.log(f"Decryption with known prime factors failed: {str(e)}", level="WARNING")
        return {'success': False, 'method': 'known_prime_factors', 'error': str(e)}


def attack_small_exponent(self, ciphertext: int, e: int, n: Optional[int] = None) -> Dict[str, Any]:
    """
    Attempt a small exponent attack (e.g., cube root when e = 3).

    Args:
        ciphertext: The encrypted message
        e: The public exponent
        n: The RSA modulus (optional, for validation)

    Returns:
        Dictionary with decryption results
    """
    self.attempted_methods.add('small_exponent')
    self.log(f"Attempting small exponent attack with e={e}...", level="INFO")

    if n is not None:
        # Check if the attack is likely to work
        if ciphertext.bit_length() > n.bit_length() // e:
            self.log("Warning: The ciphertext seems too large for a direct eth root attack.", level="WARNING")
            self.log(f"For this attack to work, ciphertext^(1/e) should be an integer and m^e < n.", level="INFO")

    try:
        # Try to find a perfect eth root
        root = self.perfect_eth_root(ciphertext, e)
        if root is not None:
            self.log(f"Found perfect {e}th root!", level="SUCCESS")
            plaintext_str = self.int_to_string(root)

            return {
                'success': True,
                'method': 'small_exponent_perfect_root',
                'plaintext_int': root,
                'plaintext': plaintext_str
            }

        # If e=3, use Newton's method as fallback
        if e == 3:
            self.log("Attempting cube root approximation...", level="INFO")
            root = self.newton_method_root(ciphertext, 3)

            # Verify the result
            if pow(root, e) == ciphertext:
                plaintext_str = self.int_to_string(root)
                return {
                    'success': True,
                    'method': 'small_exponent_newton',
                    'plaintext_int': root,
                    'plaintext': plaintext_str
                }

            # If verification fails, try a small adjustment
            for i in range(1, 1000):
                if pow(root + i, e) == ciphertext:
                    plaintext_str = self.int_to_string(root + i)
                    return {
                        'success': True,
                        'method': 'small_exponent_newton_adjusted',
                        'plaintext_int': root + i,
                        'plaintext': plaintext_str
                    }
                if pow(root - i, e) == ciphertext:
                    plaintext_str = self.int_to_string(root - i)
                    return {
                        'success': True,
                        'method': 'small_exponent_newton_adjusted',
                        'plaintext_int': root - i,
                        'plaintext': plaintext_str
                    }

        return {'success': False, 'method': 'small_exponent', 'error': 'No eth root found'}
    except Exception as e:
        self.log(f"Small exponent attack failed: {str(e)}", level="WARNING")
        return {'success': False, 'method': 'small_exponent', 'error': str(e)}


def attack_wiener(self, n: int, e: int, ciphertext: int) -> Dict[str, Any]:
    """
    Attempt Wiener's attack for small private exponents.

    Args:
        n: Modulus
        e: Public exponent
        ciphertext: The encrypted message

    Returns:
        Dictionary with decryption results
    """
    self.attempted_methods.add('wiener')
    self.log("Attempting Wiener's attack for small private exponent...", level="INFO")

    try:
        # Compute continued fraction convergents of e/n
        def continued_fraction_convergents(num, den):
            convergents = []

            # Get continued fraction coefficients
            coeffs = []
            while den:
                q, r = divmod(num, den)
                coeffs.append(q)
                num, den = den, r

            # Compute convergents
            n0, d0 = 1, 0
            n1, d1 = coeffs[0], 1
            convergents.append((n1, d1))

            for i in range(1, len(coeffs)):
                n2 = coeffs[i] * n1 + n0
                d2 = coeffs[i] * d1 + d0
                convergents.append((n2, d2))
                n0, d0 = n1, d1
                n1, d1 = n2, d2

            return convergents

        # Get convergents of e/n
        convergents = continued_fraction_convergents(e, n)

        # Check each convergent
        for k, d in convergents:
            if k == 0:  # Skip this iteration if k is zero (avoid division by zero)
                continue

            # Check if d is a potential private exponent
            phi_n = (e * d - 1) // k

            # Calculate potential values of p+q
            p_plus_q = n - phi_n + 1

            # Check if p+q is an integer
            if isinstance(p_plus_q, float) and not p_plus_q.is_integer():
                continue

            # Calculate potential values of (p-q)^2
            p_minus_q_squared = p_plus_q ** 2 - 4 * n

            # Check if (p-q)^2 is a perfect square
            p_minus_q = math.isqrt(p_minus_q_squared)
            if p_minus_q * p_minus_q != p_minus_q_squared:
                continue

            # Calculate p and q
            p = (p_plus_q + p_minus_q) // 2
            q = (p_plus_q - p_minus_q) // 2

            # Verify that p and q are indeed the factors of n
            if p * q == n:
                self.log(f"Found private exponent d = {d} with Wiener's attack!", level="SUCCESS")

                # Decrypt the ciphertext
                plaintext = pow(ciphertext, d, n)
                plaintext_str = self.int_to_string(plaintext)

                return {
                    'success': True,
                    'method': 'wiener',
                    'plaintext_int': plaintext,
                    'plaintext': plaintext_str,
                    'd': d,
                    'p': p,
                    'q': q,
                    'phi_n': phi_n
                }

        return {'success': False, 'method': 'wiener', 'error': 'No small private exponent found'}
    except Exception as e:
        self.log(f"Wiener's attack failed: {str(e)}", level="WARNING")
        return {'success': False, 'method': 'wiener', 'error': str(e)}


def attack_boneh_durfee(self, n: int, e: int, ciphertext: int) -> Dict[str, Any]:
    """
    Attempt Boneh-Durfee attack for small private exponents.
    This requires a symbolic math library like SageMath, which isn't standard.
    We'll provide an implementation hint here but it can't be fully executed.

    Args:
        n: Modulus
        e: Public exponent
        ciphertext: The encrypted message

    Returns:
        Dictionary with decryption results
    """
    self.attempted_methods.add('boneh_durfee')
    self.log("Attempting Boneh-Durfee attack for small private exponent...", level="INFO")
    self.log("Note: Full Boneh-Durfee implementation requires SageMath and may not be available.", level="WARNING")

    # Try to use sympy for a simplified implementation
    if self.optional_deps['sympy']:
        try:
            import sympy

            # This is a very simplified implementation and may not work for all cases
            self.log("Using sympy for a simplified Boneh-Durfee implementation...", level="INFO")

            # The full implementation would require lattice basis reduction
            # which is not directly supported in sympy

            # Instead, we'll just check some basic properties that might indicate
            # vulnerability to Boneh-Durfee

            # Boneh-Durfee works when d < N^0.292
            # Check if e is unusually large which might indicate small d
            if e > n:
                self.log("Public exponent e > n, which might indicate a small private exponent", level="INFO")

                # Try to compute d directly for small values
                for d_candidate in range(2, 1000000):
                    if (e * d_candidate) % n == 1:
                        self.log(f"Found potential private exponent d = {d_candidate}", level="SUCCESS")

                        # Try to decrypt
                        plaintext = pow(ciphertext, d_candidate, n)
                        try:
                            plaintext_str = self.int_to_string(plaintext)
                            return {
                                'success': True,
                                'method': 'boneh_durfee_simplified',
                                'plaintext_int': plaintext,
                                'plaintext': plaintext_str,
                                'd': d_candidate
                            }
                        except:
                            pass
        except Exception as e:
            self.log(f"Simplified Boneh-Durfee attack failed: {str(e)}", level="WARNING")

    self.log("Full Boneh-Durfee attack not available. Requires SageMath.", level="WARNING")
    return {'success': False, 'method': 'boneh_durfee', 'error': 'Not implemented or failed'}


def attack_hastad_broadcast(self, ciphertexts: List[int], moduli: List[int], e: int) -> Dict[str, Any]:
    """
    Attempt Hastad's broadcast attack when the same message is encrypted with
    the same small exponent to multiple recipients.

    Args:
        ciphertexts: List of encrypted messages
        moduli: List of moduli (n values)
        e: Public exponent (should be small)

    Returns:
        Dictionary with decryption results
    """
    self.attempted_methods.add('hastad_broadcast')
    self.log("Attempting Hastad's broadcast attack...", level="INFO")

    if len(ciphertexts) < e:
        self.log(f"Not enough ciphertexts for Hastad's attack. Need at least {e}, got {len(ciphertexts)}",
                 level="WARNING")
        return {'success': False, 'method': 'hastad_broadcast', 'error': 'Not enough ciphertexts'}

    try:
        # Use Chinese Remainder Theorem to combine the ciphertexts

        # First, compute the product of all moduli
        N = 1
        for n_i in moduli[:e]:
            N *= n_i

        # Then, compute the CRT coefficients
        result = 0
        for i in range(e):
            N_i = N // moduli[i]
            result += ciphertexts[i] * N_i * self.mod_inverse(N_i, moduli[i])

        result %= N

        # Take the eth root
        plaintext = self.perfect_eth_root(result, e)

        if plaintext is not None:
            plaintext_str = self.int_to_string(plaintext)
            return {
                'success': True,
                'method': 'hastad_broadcast',
                'plaintext_int': plaintext,
                'plaintext': plaintext_str
            }

        return {'success': False, 'method': 'hastad_broadcast', 'error': 'Could not find eth root'}
    except Exception as e:
        self.log(f"Hastad's broadcast attack failed: {str(e)}", level="WARNING")
        return {'success': False, 'method': 'hastad_broadcast', 'error': str(e)}


def attack_common_modulus(self, ciphertext1: int, e1: int, ciphertext2: int, e2: int, n: int) -> Dict[str, Any]:
    """
    Attempt common modulus attack when the same message is encrypted
    with different exponents but the same modulus.

    Args:
        ciphertext1: First encrypted message
        e1: First public exponent
        ciphertext2: Second encrypted message
        e2: Second public exponent
        n: Common modulus

    Returns:
        Dictionary with decryption results
    """
    self.attempted_methods.add('common_modulus')
    self.log("Attempting common modulus attack...", level="INFO")

    try:
        # Check if e1 and e2 are coprime
        gcd, s, t = self.extended_gcd(e1, e2)

        if gcd != 1:
            self.log(f"Public exponents are not coprime. GCD={gcd}", level="WARNING")
            return {'success': False, 'method': 'common_modulus', 'error': 'Exponents not coprime'}

        # If s < 0, we need to find the modular inverse of ciphertext1
        if s < 0:
            c1_inv = self.mod_inverse(ciphertext1, n)
            plaintext = (pow(c1_inv, -s, n) * pow(ciphertext2, t, n)) % n
        else:
            plaintext = (pow(ciphertext1, s, n) * pow(ciphertext2, t, n)) % n

        plaintext_str = self.int_to_string(plaintext)

        return {
            'success': True,
            'method': 'common_modulus',
            'plaintext_int': plaintext,
            'plaintext': plaintext_str
        }
    except Exception as e:
        self.log(f"Common modulus attack failed: {str(e)}", level="WARNING")
        return {'success': False, 'method': 'common_modulus', 'error': str(e)}


def attack_franklin_reiter(self, n: int, e: int, c1: int, c2: int, a: int, b: int, c: int) -> Dict[str, Any]:
    """
    Attempt Franklin-Reiter related message attack when two messages are related by a linear function.

    Args:
        n: Modulus
        e: Public exponent
        c1: First ciphertext
        c2: Second ciphertext
        a, b, c: Parameters such that m2 = (a * m1 + b) % n and m1 = c

    Returns:
        Dictionary with decryption results
    """
    self.attempted_methods.add('franklin_reiter')
    self.log("Attempting Franklin-Reiter related message attack...", level="INFO")

    # This attack requires a polynomial GCD computation which is best done with a computer algebra system
    self.log("Franklin-Reiter attack requires a polynomial GCD implementation.", level="WARNING")
    self.log("Consider using SageMath for this attack.", level="INFO")

    if self.optional_deps['sympy']:
        try:
            import sympy
            from sympy.polys.galoistools import gf_gcdex

            self.log("Using sympy for Franklin-Reiter attack...", level="INFO")

            # This is a simplified implementation and may not work for all cases
            # The full implementation would define polynomials in a finite field

            # Just check if the provided message is actually valid
            m1 = c
            m2 = (a * m1 + b) % n

            if pow(m1, e, n) == c1 and pow(m2, e, n) == c2:
                plaintext_str1 = self.int_to_string(m1)
                plaintext_str2 = self.int_to_string(m2)

                return {
                    'success': True,
                    'method': 'franklin_reiter_direct',
                    'plaintext1_int': m1,
                    'plaintext1': plaintext_str1,
                    'plaintext2_int': m2,
                    'plaintext2': plaintext_str2
                }
        except Exception as e:
            self.log(f"Simplified Franklin-Reiter attack failed: {str(e)}", level="WARNING")

    return {'success': False, 'method': 'franklin_reiter', 'error': 'Not implemented or failed'}


def attack_bleichenbacher_pkcs1(self, n: int, e: int, ciphertext: int) -> Dict[str, Any]:
    """
    Attempt Bleichenbacher's PKCS#1 v1.5 padding oracle attack.
    This is an implementation sketch as the attack requires an oracle.

    Args:
        n: Modulus
        e: Public exponent
        ciphertext: The encrypted message

    Returns:
        Dictionary with attack results
    """
    self.attempted_methods.add('bleichenbacher')
    self.log("Bleichenbacher's PKCS#1 v1.5 padding oracle attack requires an oracle.", level="WARNING")
    self.log("This attack cannot be performed without an oracle that checks padding.", level="INFO")

    return {'success': False, 'method': 'bleichenbacher', 'error': 'Requires padding oracle'}


# ===== Factorization Attack Orchestration =====

def factorize_modulus(self, n: int) -> Optional[Tuple[int, int]]:
    """
    Attempt to factorize the modulus using various methods.

    Args:
        n: The RSA modulus

    Returns:
        Tuple of (p, q) if successful, None otherwise
    """
    self.log(f"Attempting to factorize n = {n} ({n.bit_length()} bits)...", level="INFO")

    # Check for perfect square
    root_n = math.isqrt(n)
    if root_n * root_n == n:
        self.log(f"Modulus is a perfect square: {n} = {root_n}^2", level="SUCCESS")
        return (root_n, root_n)

    # Method 1: Try trial division for small primes
    result = self.trial_division(n, limit=1000000)
    if result:
        q = n // result
        self.log(f"Found factors via trial division: p={result}, q={q}", level="SUCCESS")
        return (result, q)

    # Method 2: Try online factorization services
    if self.online_lookup:
        result = self.factorize_using_online_services(n)
        if result:
            self.log(f"Found factors via online services: p={result[0]}, q={result[1]}", level="SUCCESS")
            return result

    # Method 3: Try Pollard's rho algorithm
    result = self.pollard_rho(n)
    if result:
        q = n // result
        self.log(f"Found factors via Pollard's rho: p={result}, q={q}", level="SUCCESS")
        return (result, q)

    # Method 4: Try Fermat factorization (works well when p and q are close)
    result = self.fermat_factorization(n)
    if result:
        self.log(f"Found factors via Fermat factorization: p={result[0]}, q={result[1]}", level="SUCCESS")
        return result

    # Method 5: Try Pollard's p-1 algorithm (if deep scan is enabled)
    if self.deep_scan:
        result = self.pollard_p_minus_1(n)
        if result:
            q = n // result
            self.log(f"Found factors via Pollard's p-1: p={result}, q={q}", level="SUCCESS")
            return (result, q)

    self.log("Failed to factorize the modulus with available methods.", level="WARNING")
    return None


# ===== Main Attack Orchestration =====

def crack_rsa(self, **kwargs) -> Dict[str, Any]:
    """
    Attempt to break RSA encryption using various attack methods.

    Args:
        **kwargs: Parameters that may include:
            - ciphertext: The encrypted message (required)
            - n, e: RSA public key parameters
            - d, p, q: RSA private key parameters (if known)
            - key_file: Path to a key file (alternative to providing n, e directly)
            - multiple_ciphertexts: List of ciphertexts for broadcast attacks
            - multiple_moduli: List of moduli for broadcast attacks

    Returns:
        Dictionary with attack results and decryption if successful
    """
    results = {
        'success': False,
        'attacks_attempted': [],
        'attack_results': {}
    }

    # Extract parameters
    ciphertext = kwargs.get('ciphertext')
    n = kwargs.get('n')
    e = kwargs.get('e')
    d = kwargs.get('d')
    p = kwargs.get('p')
    q = kwargs.get('q')
    key_file = kwargs.get('key_file')

    # Parse key file if provided
    if key_file and (n is None or e is None):
        try:
            key_params = self.parse_key_file(key_file)
            n = key_params.get('n')
            e = key_params.get('e')
            d = key_params.get('d')
            p = key_params.get('p')
            q = key_params.get('q')
        except Exception as e:
            self.log(f"Failed to parse key file: {str(e)}", level="ERROR")
            results['error'] = f"Failed to parse key file: {str(e)}"
            return results

    # Validate required parameters
    if ciphertext is None:
        self.log("No ciphertext provided", level="ERROR")
        results['error'] = "No ciphertext provided"
        return results

    if n is None or e is None:
        self.log("RSA public key (n, e) required but not provided", level="ERROR")
        results['error'] = "RSA public key (n, e) required but not provided"
        return results

    # Store key information in results
    results['key_info'] = {
        'n': n,
        'e': e,
        'n_bit_length': n.bit_length(),
        'ciphertext': ciphertext
    }

    # Check if all private key parameters are already known
    if d is not None:
        # Method 1: Decrypt with known private key
        attack_result = self.attack_known_private_key(n, e, d, ciphertext)
        results['attacks_attempted'].append('known_private_key')
        results['attack_results']['known_private_key'] = attack_result

        if attack_result['success']:
            results['success'] = True
            results['plaintext'] = attack_result['plaintext']
            results['plaintext_int'] = attack_result['plaintext_int']
            results['method'] = 'known_private_key'
            return results

    if p is not None and q is not None:
        # Method 2: Decrypt with known prime factors
        attack_result = self.attack_known_prime_factors(n, e, p, q, ciphertext)
        results['attacks_attempted'].append('known_prime_factors')
        results['attack_results']['known_prime_factors'] = attack_result

        if attack_result['success']:
            results['success'] = True
            results['plaintext'] = attack_result['plaintext']
            results['plaintext_int'] = attack_result['plaintext_int']
            results['method'] = 'known_prime_factors'
            return results

    # Method 3: Try small exponent attack if e is small
    if e <= 5:
        attack_result = self.attack_small_exponent(ciphertext, e, n)
        results['attacks_attempted'].append('small_exponent')
        results['attack_results']['small_exponent'] = attack_result

        if attack_result['success']:
            results['success'] = True
            results['plaintext'] = attack_result['plaintext']
            results['plaintext_int'] = attack_result['plaintext_int']
            results['method'] = attack_result['method']
            return results

    # Method 4: Try Wiener's attack for small private exponents
    attack_result = self.attack_wiener(n, e, ciphertext)
    results['attacks_attempted'].append('wiener')
    results['attack_results']['wiener'] = attack_result

    if attack_result['success']:
        results['success'] = True
        results['plaintext'] = attack_result['plaintext']
        results['plaintext_int'] = attack_result['plaintext_int']
        results['method'] = 'wiener'
        return results

    # Method 5: Try to factorize the modulus
    factors = self.factorize_modulus(n)
    if factors:
        p, q = factors
        attack_result = self.attack_known_prime_factors(n, e, p, q, ciphertext)
        results['attacks_attempted'].append('factorization')
        results['attack_results']['factorization'] = attack_result

        if attack_result['success']:
            results['success'] = True
            results['plaintext'] = attack_result['plaintext']
            results['plaintext_int'] = attack_result['plaintext_int']
            results['method'] = 'factorization'
            results['factors'] = {'p': p, 'q': q}
            return results

    # Method 6: Try Boneh-Durfee attack (if deep scan is enabled)
    if self.deep_scan:
        attack_result = self.attack_boneh_durfee(n, e, ciphertext)
        results['attacks_attempted'].append('boneh_durfee')
        results['attack_results']['boneh_durfee'] = attack_result

        if attack_result['success']:
            results['success'] = True
            results['plaintext'] = attack_result['plaintext']
            results['plaintext_int'] = attack_result['plaintext_int']
            results['method'] = 'boneh_durfee'
            return results

    # Method 7: Check for Hastad's broadcast attack if multiple ciphertexts are provided
    if 'multiple_ciphertexts' in kwargs and 'multiple_moduli' in kwargs:
        multiple_ciphertexts = kwargs['multiple_ciphertexts']
        multiple_moduli = kwargs['multiple_moduli']

        if len(multiple_ciphertexts) >= e and len(multiple_moduli) >= e:
            attack_result = self.attack_hastad_broadcast(multiple_ciphertexts, multiple_moduli, e)
            results['attacks_attempted'].append('hastad_broadcast')
            results['attack_results']['hastad_broadcast'] = attack_result

            if attack_result['success']:
                results['success'] = True
                results['plaintext'] = attack_result['plaintext']
                results['plaintext_int'] = attack_result['plaintext_int']
                results['method'] = 'hastad_broadcast'
                return results

    # Method 8: Check for common modulus attack if multiple ciphertexts are provided
    if 'second_ciphertext' in kwargs and 'second_exponent' in kwargs:
        second_ciphertext = kwargs['second_ciphertext']
        second_exponent = kwargs['second_exponent']

        attack_result = self.attack_common_modulus(ciphertext, e, second_ciphertext, second_exponent, n)
        results['attacks_attempted'].append('common_modulus')
        results['attack_results']['common_modulus'] = attack_result

        if attack_result['success']:
            results['success'] = True
            results['plaintext'] = attack_result['plaintext']
            results['plaintext_int'] = attack_result['plaintext_int']
            results['method'] = 'common_modulus'
            return results

    # All attack methods failed
    self.log("All attack methods failed", level="WARNING")
    return results


def main():
    """Main function for the RSA cracking tool."""
    parser = argparse.ArgumentParser(
        description="Enhanced RSA Cracking Tool - Break RSA encryption using various attack methods"
    )

    # Input options
    parser.add_argument('--ciphertext', type=str, help='Ciphertext to decrypt (as a decimal integer)')
    parser.add_argument('--n', type=str, help='RSA modulus')
    parser.add_argument('--e', type=str, help='Public exponent')
    parser.add_argument('--d', type=str, help='Private exponent (if known)')
    parser.add_argument('--p', type=str, help='First prime factor (if known)')
    parser.add_argument('--q', type=str, help='Second prime factor (if known)')
    parser.add_argument('--key-file', type=str, help='Path to key file (PEM, certificate, etc.)')
    parser.add_argument('--input-file', type=str, help='JSON file with input parameters')

    # Multiple ciphertexts for broadcast attacks
    parser.add_argument('--multiple-ciphertexts', type=str, nargs='+',
                        help='Multiple ciphertexts for broadcast attacks')
    parser.add_argument('--multiple-moduli', type=str, nargs='+',
                        help='Multiple moduli for broadcast attacks')

    # Common modulus attack
    parser.add_argument('--second-ciphertext', type=str,
                        help='Second ciphertext for common modulus attack')
    parser.add_argument('--second-exponent', type=str,
                        help='Second exponent for common modulus attack')

    # Configuration options
    parser.add_argument('--no-online-lookup', action='store_true',
                        help='Disable online factorization services')
    parser.add_argument('--deep-scan', action='store_true',
                        help='Enable deeper scans with more time-consuming attacks')
    parser.add_argument('--timeout', type=int, default=300,
                        help='Maximum time in seconds for each attack method')
    parser.add_argument('--max-workers', type=int, default=4,
                        help='Maximum number of parallel workers')

    # Output options
    parser.add_argument('--output-file', type=str, help='Output file for results')
    parser.add_argument('--output-format', choices=['json', 'text'], default='json',
                        help='Output format')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')

    # One-click mode - just provide a ciphertext and let the tool do everything
    parser.add_argument('--auto', action='store_true',
                        help='Auto mode - attempt all possible attacks with minimal input')

    args = parser.parse_args()

    # Initialize the cracking tool
    cracker = RSACrackingTool(
        verbose=args.verbose,
        online_lookup=not args.no_online_lookup,
        max_workers=args.max_workers,
        deep_scan=args.deep_scan,
        timeout=args.timeout
    )

    # Check for optional dependencies
    if args.verbose:
        print("Optional dependencies:")
        for dep, available in cracker.optional_deps.items():
            status = "Available" if available else "Not available"
            print(f"  - {dep}: {status}")

    # Load parameters from input file if provided
    params = {}
    if args.input_file:
        try:
            with open(args.input_file, 'r') as f:
                file_params = json.load(f)
                for key, value in file_params.items():
                    params[key] = value
        except Exception as e:
            print(f"Error loading input file: {str(e)}")
            return 1

    # Override with command line parameters
    if args.ciphertext:
        params['ciphertext'] = int(args.ciphertext)
    if args.n:
        params['n'] = int(args.n)
    if args.e:
        params['e'] = int(args.e)
    if args.d:
        params['d'] = int(args.d)
    if args.p:
        params['p'] = int(args.p)
    if args.q:
        params['q'] = int(args.q)
    if args.key_file:
        params['key_file'] = args.key_file

    # Multiple ciphertexts for broadcast attacks
    if args.multiple_ciphertexts and args.multiple_moduli:
        params['multiple_ciphertexts'] = [int(c) for c in args.multiple_ciphertexts]
        params['multiple_moduli'] = [int(n) for n in args.multiple_moduli]

    # Common modulus attack
    if args.second_ciphertext and args.second_exponent:
        params['second_ciphertext'] = int(args.second_ciphertext)
        params['second_exponent'] = int(args.second_exponent)

    # Auto mode - try to automatically detect or prompt for parameters
    if args.auto:
        if 'ciphertext' not in params:
            ciphertext_input = input("Enter ciphertext (as a decimal integer): ")
            params['ciphertext'] = int(ciphertext_input)

        if 'n' not in params and 'key_file' not in params:
            n_input = input("Enter modulus n (optional, press Enter to skip): ")
            if n_input.strip():
                params['n'] = int(n_input)
            else:
                print("No modulus provided. Will try to extract from key file or guess.")
                key_file = input("Enter path to key file (optional, press Enter to skip): ")
                if key_file.strip():
                    params['key_file'] = key_file

        if 'e' not in params and 'key_file' not in params:
            e_input = input("Enter public exponent e (optional, default is 65537): ")
            if e_input.strip():
                params['e'] = int(e_input)
            else:
                params['e'] = 65537
                print("Using default public exponent e = 65537")

    # Validate minimal required parameters
    if 'ciphertext' not in params:
        print("Error: No ciphertext provided")
        return 1

    if 'n' not in params and 'key_file' not in params:
        print("Error: Either modulus (n) or key file must be provided")
        return 1

    if 'e' not in params and 'key_file' not in params:
        print("Using default public exponent e = 65537")
        params['e'] = 65537

    # Run the cracking tool
    print(f"\nStarting RSA cracking with {'deep scan' if args.deep_scan else 'normal scan'}...")
    start_time = time.time()

    results = cracker.crack_rsa(**params)

    elapsed = time.time() - start_time
    print(f"\nRSA cracking completed in {elapsed:.2f} seconds")

    # Display results
    if results['success']:
        print("\n🎉 SUCCESS! RSA encryption broken!")
        print(f"Attack method: {results['method']}")
        print(f"Plaintext: {results['plaintext']}")

        # Generate flag format if it looks like a flag
        if any(x in results['plaintext'] for x in ['flag', 'CTF', 'key', 'password']):
            print(f"Flag format: ZD{{{results['plaintext']}}}")
    else:
        print("\n❌ Failed to break RSA encryption with available methods")
        print("Attacks attempted:")
        for method in results['attacks_attempted']:
            print(f"  - {method}")

        # Offer suggestions
        print("\nSuggestions:")
        if 'error' in results:
            print(f"  - Address error: {results['error']}")
        if 'key_info' in results and results['key_info'].get('n_bit_length', 0) > 1024:
            print("  - The modulus is large. For keys > 1024 bits, factorization is extremely difficult.")
            print("  - Try to find alternative attack vectors or side-channel information.")
        if 'factorization' not in results['attacks_attempted'] or args.no_online_lookup:
            print("  - Enable online factorization services with --auto")
        if not args.deep_scan:
            print("  - Try deep scan mode with --deep-scan")

    # Save results if requested
    if args.output_file:
        try:
            # Add timestamp and context to results
            results['timestamp'] = time.time()
            results['elapsed_time'] = elapsed
            results['scan_type'] = 'deep_scan' if args.deep_scan else 'normal_scan'

            with open(args.output_file, 'w') as f:
                if args.output_format == 'json':
                    json.dump(results, f, indent=2, default=str)
                else:
                    # Text format
                    f.write(f"RSA Cracking Results\n")
                    f.write(f"====================\n\n")
                    f.write(f"Success: {results['success']}\n")
                    if results['success']:
                        f.write(f"Method: {results['method']}\n")
                        f.write(f"Plaintext: {results['plaintext']}\n")
                    f.write(f"\nAttacks attempted: {', '.join(results['attacks_attempted'])}\n")
                    f.write(f"Elapsed time: {elapsed:.2f} seconds\n")

            print(f"\nResults saved to {args.output_file}")
        except Exception as e:
            print(f"Error saving results: {str(e)}")

    return 0 if results['success'] else 1


if __name__ == "__main__":
    exit(main())