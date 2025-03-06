# hibp

A command-line tool to check if email addresses have been compromised using the Have I Been Pwned API.

## Features

- Check individual email addresses
- Check passwords securely (using k-anonymity)
- Process multiple email addresses from a file
- Apply rate limiting to stay within API constraints
- Detailed breach reporting

## Installation

1. Clone this repository
2. Install requirements: `pip install requests rich`
3. Get your API key from [haveibeenpwned.com](https://haveibeenpwned.com/API/Key)

## Usage

Check a single email:
```bash
python3 hibp.py --key YOUR_API_KEY email user@example.com
```
Check emails from a file:
```bash
python3 hibp.py --key YOUR_API_KEY file emails.txt --output results.txt
```
