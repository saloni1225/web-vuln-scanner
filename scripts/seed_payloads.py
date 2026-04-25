from backend.payloads.payload_generator import PayloadGenerator


if __name__ == "__main__":
    generator = PayloadGenerator()
    print(f"Loaded {len(generator.sqli_payloads())} SQLi payloads.")
    print(f"Loaded {len(generator.xss_payloads())} XSS payloads.")

