# Custom Wordlists Cheatsheet

Custom wordlists allow for a much more targeted and efficient brute-force attack by leveraging information specific to the target (user/company/environment) rather than relying only on large, generic lists like rockyou.txt.

## Why Custom Wordlists?

- Large premade lists (rockyou, SecLists) are slow, generic, may miss custom usernames/passwords.
- Custom lists use data from OSINT: social media, company websites, breached data, news, public records.

---

## Username Generation: Username Anarchy

- Usernames depend on company conventions, personal variations, leetspeak, hobbies.
- **Username Anarchy** tool creates comprehensive username permutations (initials, first/last, leet, nick, etc.):
  - Install ruby: `sudo apt install ruby -y`
  - Clone tool: `git clone https://github.com/urbanadventurer/username-anarchy.git`
  - Usage: `./username-anarchy FirstName LastName > usernames.txt`
  - Output: janesmith, jane.smith, j.smith, js, smithjane, j4n3, etc.

---

## Password Wordlists: CUPP (Common User Passwords Profiler)

- Gathers intelligence (name, nickname, DOB, partner, pet, employer, interests, keywords) to create personal wordlists.
- Installation: `sudo apt install cupp -y`
- Run interactive: `cupp -i`
- Enter as much info as possible (from OSINT: Facebook, LinkedIn, etc.)
- Generates wordlist: `victim.txt` (combines names, dates, reversals, leet, concatenations, numbers, special chars)
- Can generate tens of thousands of relevant entries.

---

## Filtering the Password List (for Policy Compliance)

If company policy requires:
- **Min 6 chars:** `grep -E '^.{6,}$'`
- **At least 1 uppercase:** `grep -E '[A-Z]'`
- **At least 1 lowercase:** `grep -E '[a-z]'`
- **At least 1 number:** `grep -E '[0-9]'`
- **At least 2 special (!@#$%^&\*):** `grep -E '([!@#$%^&*].*){2,}'`

Combine in series (example):