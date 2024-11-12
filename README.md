# xssgen

**xssgen** is an advanced tool designed to help penetration testers and security researchers generate sophisticated Cross-Site Scripting (XSS) payloads. With built-in bypass techniques, multi-stage payloads, and a variety of encoding options, **xssgen** assists in crafting payloads to test the security of web applications against various defenses such as Content Security Policies (CSP) and Web Application Firewalls (WAF).

## Features

- **Interactive Mode**: Guides users step-by-step in creating payloads.
- **Encoding Options**: Supports multiple encoding techniques, including HTML, URL, Unicode, Base64, and more.
- **Multi-Stage Payloads**: Creates payloads that execute over time to bypass security measures.
- **Bypass Techniques**: Generates payloads designed to evade CSP and WAF protections.
- **Save and Load**: Save generated payloads to a file and load existing payloads for reuse.
- **Flexible CLI**: User-friendly short flags for ease of use.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/S2K7x/xssgen.git
    cd xssgen
    ```

2. Install the required dependencies (Python 3.6+):

    ```bash
    pip install -r requirements.txt
    ```

3. Ensure your `config.json` file is in the same directory and properly configured.

## Usage

### Basic Usage

To generate a payload:

```bash
python xssgen.py -c innerHTML -e url -v onmouseover
```

### Interactive Mode

Start the interactive mode to be guided step-by-step:

```bash
python xssgen.py -i
```

### Advanced Options

- **Generate a multi-stage payload**:

    ```bash
    python xssgen.py -c innerHTML -v onclick -m
    ```

- **Apply multiple encodings**:

    ```bash
    python xssgen.py -c src -e base64,url
    ```

- **Save a payload to a file**:

    ```bash
    python xssgen.py -c href -e hex -s payloads.txt
    ```

### Loading Payloads

Load and display payloads from a file:

```bash
python xssgen.py -l payloads.txt
```

### Bypass CSP or WAF

Generate payloads with bypass techniques:
- **CSP Bypass**:

    ```bash
    python xssgen.py -p
    ```

- **WAF Bypass**:

    ```bash
    python xssgen.py -w
    ```

## Arguments Overview

| Short Flag | Long Flag          | Description                                        |
|------------|--------------------|----------------------------------------------------|
| -c         | --context          | Specify the HTML context or advanced payload.      |
| -e         | --encode           | Select encoding type for payload (e.g., html, url).|
| -v         | --event            | Specify an event handler for the payload.          |
| -w         | --waf              | Generate a WAF-bypassing payload.                  |
| -p         | --csp              | Generate a CSP-compliant payload.                  |
| -m         | --multistage       | Generate multi-stage payloads.                     |
| -s         | --save             | Save generated payloads to a file.                 |
| -l         | --load             | Load payloads from a file.                         |
| -i         | --interactive      | Run the tool in interactive mode.                  |

## Configuration File (`config.json`)

Ensure `config.json` includes definitions for:
- **contexts**: Various HTML/JavaScript contexts.
- **events**: Common event handlers.
- **bypass_techniques**: Techniques to bypass CSP/WAF.

### Example structure:

```json
{
    "contexts": {
        "innerHTML": "<div>{{event}}=alert(1)></div>",
        "src": "<img src='x' onerror='{{event}}'>"
    },
    "events": ["onload", "onmouseover", "onclick"],
    "bypass_techniques": {
        "csp": "<script nonce='{{nonce}}'>alert(1)</script>",
        "waf": "<svg/onload=alert(1)>"
    }
}
```

## Contributing

Contributions are welcome! Please create a new issue or submit a pull request.

## License

This project is licensed under the MIT License.

## Disclaimer

**xssgen** is for educational and testing purposes only. Use it responsibly and with proper authorization.

## Contact

For questions, issues, or contributions, reach out at [your email] or submit an issue on GitHub.


This markdown format is ready to be used in documentation repositories, GitHub pages, or as part of a security testing toolkit.
