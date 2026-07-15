#!/usr/bin/env python3
import csv
import random
import argparse
import io
import os
# Example
# python3 dlpGen.py -m pci -s 18 -o max_email_payload.csv
# --- EXPANDED INPUT LISTS ---

FIRST_NAMES = [
    # Millennial Female Names
    "Jessica", "Ashley", "Sarah", "Amanda", "Jennifer", "Emily", "Samantha", 
    "Melissa", "Stephanie", "Nicole", "Heather", "Elizabeth", "Megan", "Amber", 
    "Rachel", "Michelle", "Danielle", "Tiffany", "Chelsea", "Erin", "Kayla", 
    "Brittany", "Courtney", "Rebecca", "Christina", "Amy", "Laura", "Kimberly",
    # Millennial Male Names
    "Michael", "Christopher", "Matthew", "Joshua", "Andrew", "Daniel", "David", 
    "Tyler", "James", "John", "Joseph", "Ryan", "Nicholas", "Brandon", "William", 
    "Justin", "Benjamin", "Cody", "Robert", "Austin", "Thomas", "Kyle", "Samuel", 
    "Kevin", "Zachary", "Eric", "Brian", "Jaden", "Aiden", "Bradley"
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", 
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", 
    "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", 
    "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", 
    "Lewis", "Robinson", "Walker", "Young", "Allen", "King", "Wright", 
    "Scott", "Torres", "Nguyen", "Hill", "Flores", "Green", "Adams", 
    "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell", "Carter", 
    "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker", 
    "Cruz", "Edwards", "Collins", "Reyes", "Stewart", "Morris", "Morales", 
    "Murphy", "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper", 
    "Peterson", "Bailey", "Reed", "Kelly", "Howard", "Ramos", "Kim", 
    "Cox", "Ward", "Richardson", "Watson", "Brooks", "Chavez", "Wood", 
    "James", "Bennett", "Gray", "Mendoza", "Ruiz", "Hughes", "Price", 
    "Alvarez", "Castillo", "Sanders", "Patel", "Myers", "Long", "Ross", 
    "Foster", "Jimenez"
]

# STREAMING_CHUNK:Defining Luhn algorithm validation...
def generate_luhn_number(prefix: str, length: int) -> str:
    """
    Generates a structurally valid card number using the Luhn algorithm.
    """
    digits = [int(x) for x in prefix]
    while len(digits) < (length - 1):
        digits.append(random.randint(0, 9))
    
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 0:
            doubled = digit * 2
            checksum += doubled if doubled < 10 else doubled - 9
        else:
            checksum += digit
            
    check_digit = (10 - (checksum % 10)) % 10
    digits.append(check_digit)
    return "".join(map(str, digits))

# STREAMING_CHUNK:Defining random value generators...
def generate_credit_card() -> str:
    """
    Returns a structurally valid PAN using real BIN patterns.
    """
    brands = [
        ("4", 16),    # Visa
        ("51", 16),   # Mastercard
        ("37", 15),   # Amex
        ("6011", 16)  # Discover
    ]
    prefix, length = random.choice(brands)
    return generate_luhn_number(prefix, length)

def generate_ssn() -> str:
    """
    Generates a realistic SSN in the unassigned 900-series range 
    to avoid accidental real-world matches while passing string validations.
    """
    area = random.randint(900, 999)
    group = random.randint(1, 99)
    serial = random.randint(1, 9999)
    return f"{area:03d}-{group:02d}-{serial:04d}"

def generate_cvv() -> str:
    """Generates a standard 3-digit Card Verification Value."""
    return f"{random.randint(100, 999)}"

def generate_exp() -> str:
    """Generates a card expiration date formatted as MM/YY."""
    month = random.randint(1, 12)
    year = random.randint(26, 32)  # Generates futures up to 2032
    return f"{month:02d}/{year:02d}"

# STREAMING_CHUNK:Setting up size calculation utilities...
def get_csv_row_bytes(row: list, encoding: str = "utf-8") -> int:
    """
    Calculates exact byte length on disk for any given list row.
    """
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(row)
    return len(output.getvalue().encode(encoding))

# STREAMING_CHUNK:Defining dataset generator logic...
def generate_dataset(output_file="dlp_millennial_test_records.csv", num_records=None, max_size_mb=None, mode="pii"):
    """
    Generates optimized PII or PCI records with hard size ceilings.
    """
    bytes_limit = int(max_size_mb * 1024 * 1024) if max_size_mb is not None else None
    bytes_written = 0
    records_count = 0

    # Determine schema based on the selected mode
    if mode == "pii":
        # The absolute leanest combination to trigger a 50-state statutory PII breach
        header = ["First Name", "Last Name", "SSN"]
    else:
        # The absolute leanest combination to trigger a 50-state statutory credit card breach
        header = ["First Name", "Last Name", "Card Number", "CVV", "Exp"]

    header_bytes = get_csv_row_bytes(header)

    if bytes_limit is not None and header_bytes > bytes_limit:
        print(f"[-] Error: Target size of {max_size_mb} MB is too small even for the CSV header ({header_bytes} bytes).")
        return

    print(f"[*] Starting dataset generation (Mode: {mode.upper()}) for '{output_file}'...")
    if bytes_limit:
        print(f"[*] Target cap: {max_size_mb} MB ({bytes_limit:,} bytes)")
    if num_records:
        print(f"[*] Target record count: {num_records:,}")

    # STREAMING_CHUNK:Assembling rows based on mode...
    with open(output_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, lineterminator="\r\n")
        
        writer.writerow(header)
        bytes_written += header_bytes

        while True:
            if num_records is not None and records_count >= num_records:
                print(f"[+] Reached requested record limit of {num_records:,} rows.")
                break

            # Populate only the bare essential fields per mode
            first = random.choice(FIRST_NAMES)
            last = random.choice(LAST_NAMES)

            if mode == "pii":
                row = [first, last, generate_ssn()]
            else:
                row = [first, last, generate_credit_card(), generate_cvv(), generate_exp()]
            
            row_bytes = get_csv_row_bytes(row)

            if bytes_limit is not None and (bytes_written + row_bytes) > bytes_limit:
                print(f"[+] Reached file size threshold. Next record would exceed {max_size_mb} MB limit.")
                break

            writer.writerow(row)
            bytes_written += row_bytes
            records_count += 1

            if records_count % 100000 == 0:
                mb_curr = bytes_written / (1024 * 1024)
                print(f"    -> Generated {records_count:,} records (~{mb_curr:.2f} MB written)")

    actual_file_size = os.path.getsize(output_file)
    print(f"[+] Successfully wrote {records_count:,} records to '{output_file}'")
    print(f"[+] Final output size: {actual_file_size / (1024 * 1024):.4f} MB ({actual_file_size:,} bytes)")

# STREAMING_CHUNK:Implementing command line interface...
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate highly optimized, structurally valid PII or PCI datasets constrained by size or count for DLP testing."
    )
    parser.add_argument(
        "-o", "--output", 
        default="dlp_millennial_test_records.csv", 
        help="Path where output CSV should be saved (default: dlp_millennial_test_records.csv)"
    )
    parser.add_argument(
        "-n", "--records", 
        type=int, 
        default=None, 
        help="Specific number of records to generate"
    )
    parser.add_argument(
        "-s", "--max-size", 
        type=float, 
        default=None, 
        dest="max_size",
        help="Maximum size constraint of the output file in MB (e.g. 18.7 for a raw email attachment limit)"
    )
    parser.add_argument(
        "-m", "--mode",
        choices=["pii", "pci"],
        default="pii",
        help="Generation mode: 'pii' (First, Last, SSN) or 'pci' (First, Last, Card Number, CVV, Exp). Default is 'pii'."
    )

    args = parser.parse_args()

    if args.records is None and args.max_size is None:
        args.records = 10000

    generate_dataset(
        output_file=args.output,
        num_records=args.records,
        max_size_mb=args.max_size,
        mode=args.mode
    )