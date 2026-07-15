#!/usr/bin/env python3
import csv
import random
import argparse
import io
import os
from datetime import datetime, timedelta

# Example
# python3 piiGen.py -s 18.7 -o max_email_payload.csv

# --- EXPANDED INPUT LISTS ---

# Top Millennial Names (from BabyCenter)
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

# Top 100 US Surnames (from ThoughtCo / US Census Data)
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

# Common US ZIP prefixes mapped to populated areas for convincing spatial data
ZIP_PREFIXES = ["232", "201", "220", "100", "902", "303", "606", "752", "941"]

# --- CONVINCING DATA GENERATION LOGIC ---

def generate_luhn_number(prefix: str, length: int) -> str:
    """
    Generates a structurally valid card number using the Luhn algorithm.
    """
    digits = [int(x) for x in prefix]
    while len(digits) < (length - 1):
        digits.append(random.randint(0, 9))
    
    # Calculate checksum digit (Luhn / Mod 10)
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

def generate_credit_card() -> tuple:
    """
    Returns a tuple of (Brand, Card Number) with correct BIN prefixes and Luhn check.
    """
    brands = [
        ("Visa", "4", 16),
        ("Mastercard", "51", 16),
        ("Mastercard", "55", 16),
        ("Amex", "34", 15),
        ("Amex", "37", 15),
        ("Discover", "6011", 16)
    ]
    brand_name, prefix, length = random.choice(brands)
    card_number = generate_luhn_number(prefix, length)
    return brand_name, card_number

def generate_dob(min_age=28, max_age=45) -> str:
    """
    Generates a valid Date of Birth preserving month-specific day counts and leap years.
    Targeted to birth years roughly matching the millennial range (1981 - 1998).
    """
    end_date = datetime.now() - timedelta(days=min_age * 365)
    start_date = datetime.now() - timedelta(days=max_age * 365)
    
    random_days = random.randint(0, (end_date - start_date).days)
    random_date = start_date + timedelta(days=random_days)
    return random_date.strftime("%Y-%m-%d")

def generate_zip() -> str:
    """Generates a realistic US ZIP code using common state prefixes."""
    prefix = random.choice(ZIP_PREFIXES)
    suffix = "".join(str(random.randint(0, 9)) for _ in range(5 - len(prefix)))
    return f"{prefix}{suffix}"

def get_csv_row_bytes(row: list, encoding: str = "utf-8") -> int:
    """
    Simulates writing a CSV row to memory to find its exact byte length on disk,
    including appropriate system line terminators.
    """
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(row)
    return len(output.getvalue().encode(encoding))

# --- MAIN ENGINE ---

def generate_dataset(output_file="dlp_millennial_test_records.csv", num_records=None, max_size_mb=None):
    """
    Generates realistic synthetic records with optional size or record constraints.
    Stops when the record count is met or when adding another record would exceed the max_size_mb.
    """
    # Calculate bytes limit if maximum size in MB is supplied
    bytes_limit = int(max_size_mb * 1024 * 1024) if max_size_mb is not None else None
    bytes_written = 0
    records_count = 0

    header = ["First Name", "Last Name", "Date of Birth", "ZIP Code", "Card Brand", "Card Number"]
    header_bytes = get_csv_row_bytes(header)

    # Pre-check size logic
    if bytes_limit is not None and header_bytes > bytes_limit:
        print(f"[-] Error: Target size of {max_size_mb} MB is too small even for the CSV header ({header_bytes} bytes).")
        return

    print(f"[*] Starting dataset generation for '{output_file}'...")
    if bytes_limit:
        print(f"[*] Target cap: {max_size_mb} MB ({bytes_limit:,} bytes)")
    if num_records:
        print(f"[*] Target record count: {num_records:,}")

    with open(output_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, lineterminator="\r\n")
        
        # Write header
        writer.writerow(header)
        bytes_written += header_bytes

        while True:
            # Check record limit constraint
            if num_records is not None and records_count >= num_records:
                print(f"[+] Reached requested record limit of {num_records:,} rows.")
                break

            # Generate dummy values
            first = random.choice(FIRST_NAMES)
            last = random.choice(LAST_NAMES)
            dob = generate_dob()
            zip_code = generate_zip()
            brand, cc_num = generate_credit_card()
            
            row = [first, last, dob, zip_code, brand, cc_num]
            row_bytes = get_csv_row_bytes(row)

            # Check size limit constraint
            if bytes_limit is not None and (bytes_written + row_bytes) > bytes_limit:
                print(f"[+] Reached file size threshold. Next record would exceed {max_size_mb} MB limit.")
                break

            # Write row to output
            writer.writerow(row)
            bytes_written += row_bytes
            records_count += 1

            # Provide UI feedback for large files
            if records_count % 50000 == 0:
                mb_curr = bytes_written / (1024 * 1024)
                print(f"    -> Generated {records_count:,} records (~{mb_curr:.2f} MB written)")

    actual_file_size = os.path.getsize(output_file)
    print(f"[+] Successfully wrote {records_count:,} records to '{output_file}'")
    print(f"[+] Final output size: {actual_file_size / (1024 * 1024):.4f} MB ({actual_file_size:,} bytes)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate robust structured synthetic datasets constrained by count or physical file size for DLP testing."
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
        help="Maximum size constraint of the output file in MB (e.g. 18.7 for a raw email attachment limit)"
    )

    args = parser.parse_args()

    # Default fallback behavior if no constraints are provided
    if args.records is None and args.max-size is None:
        args.records = 10000

    generate_dataset(
        output_file=args.output,
        num_records=args.records,
        max_size_mb=args.max_size
    )
