import csv
import json
import re
import sys

# Regex patterns for PII detection
PHONE_RE = re.compile(r'\b\d{10}\b')
AADHAR_RE = re.compile(r'\b\d{12}\b')
PASSPORT_RE = re.compile(r'\b[A-Z]\d{7}\b', re.I)
UPI_RE = re.compile(r'\b[a-zA-Z0-9_.]+@[a-zA-Z]{2,}\b')

def mask_phone(phone):
    return phone[:2] + 'XXXXXX' + phone[-2:]

def mask_aadhar(aadhar):
    return aadhar[:4] + 'XXXXXX' + aadhar[-2:]

def mask_passport(passport):
    return passport[0] + 'XXXXXX' + passport[-1]

def mask_email(email):
    name, domain = email.split('@')
    if len(name) <= 2:
        masked = name[0] + 'XXX'
    else:
        masked = name[:2] + 'XXX'
    return masked + '@' + domain

def mask_upi(upi):
    parts = upi.split('@')
    if len(parts[0]) > 2:
        masked = parts[0][:2] + 'XXX'
    else:
        masked = parts[0][0] + 'XXX'
    return masked + '@' + parts[1]

def mask_name(full_name):
    return ' '.join([p[0] + 'XXX' for p in full_name.split() if p])

def mask_address(address):
    # Mask entire address for security
    return '[REDACTED_PII]'

def mask_ip(ip):
    parts = ip.split('.')
    if len(parts) == 4:
        return parts[0] + '.XXX.XXX.' + parts[-1]
    return ip

STANDALONE_PII_KEYS = {'phone', 'aadhar', 'passport', 'upi_id'}
COMBINATORIAL_KEYS = {'name', 'email', 'address', 'device_id', 'ip_address'}

def is_valid_email(email):
    pattern = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
    return bool(pattern.match(email))

def redact_row(row):
    pii_detected = False
    redacted = {}

    # Redact standalone PII
    for key, value in row.items():
        if value is None:
            continue
        if key == 'phone' and PHONE_RE.fullmatch(str(value)):
            redacted[key] = mask_phone(value)
            pii_detected = True
        elif key == 'aadhar' and AADHAR_RE.fullmatch(str(value)):
            redacted[key] = mask_aadhar(value)
            pii_detected = True
        elif key == 'passport' and PASSPORT_RE.fullmatch(str(value)):
            redacted[key] = mask_passport(value)
            pii_detected = True
        elif key == 'upi_id' and UPI_RE.fullmatch(str(value)):
            redacted[key] = mask_upi(value)
            pii_detected = True
        else:
            redacted[key] = value

    # Detect and redact combinatorial PII
    comb_fields = {k: row[k] for k in COMBINATORIAL_KEYS if row.get(k)}
    full_name = 'name' in comb_fields and len(comb_fields['name'].split()) >= 2
    comb_count = len(comb_fields)

    if full_name and comb_count >= 2:
        pii_detected = True
        for k in comb_fields:
            if k == 'name':
                redacted[k] = mask_name(comb_fields[k])
            elif k == 'email' and is_valid_email(comb_fields[k]):
                redacted[k] = mask_email(comb_fields[k])
            elif k == 'address':
                redacted[k] = mask_address(comb_fields[k])
            elif k == 'device_id':
                redacted[k] = '[REDACTED_PII]'
            elif k == 'ip_address':
                redacted[k] = mask_ip(comb_fields[k])
    elif any(k in comb_fields for k in ['device_id', 'ip_address']) and any(k in comb_fields for k in ['name', 'email', 'address']):
        pii_detected = True
        for k in comb_fields:
            if k == 'email' and is_valid_email(comb_fields[k]):
                redacted[k] = mask_email(comb_fields[k])
            elif k == 'address':
                redacted[k] = mask_address(comb_fields[k])
            elif k == 'device_id':
                redacted[k] = '[REDACTED_PII]'
            elif k == 'ip_address':
                redacted[k] = mask_ip(comb_fields[k])

    return redacted, pii_detected

def main(input_csv):
    output_rows = []
    with open(input_csv, newline='', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        for rec in reader:
            rid = rec['record_id']
            raw_json = rec['data_json']
            try:
                row = json.loads(raw_json)
            except:
                continue
            redacted, is_pii = redact_row(row)
            output_rows.append({
                'record_id': rid,
                'redacted_data_json': json.dumps(redacted, ensure_ascii=False),
                'is_pii': str(is_pii)
            })

    with open('redacted_output_candidate_full_name.csv', 'w', newline='', encoding='utf-8') as outcsv:
        writer = csv.DictWriter(outcsv, fieldnames=['record_id', 'redacted_data_json', 'is_pii'])
        writer.writeheader()
        writer.writerows(output_rows)

if __name__ == '__main__':
    input_csv = sys.argv[1]
    main(input_csv)
