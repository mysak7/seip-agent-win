"""Download, verify (RSA-4096 PKCS#1v15 SHA-256), and write Lua filter bundle.

Exit codes:
  0  - filters written successfully
  2  - already up-to-date (state file timestamp matches bundle)
  1  - any error (network, signature failure, missing args, etc.)
"""
import sys, json, base64, argparse, urllib.request

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle-url",   required=True)
    ap.add_argument("--pub-key-b64",  required=True)
    ap.add_argument("--noise-path",   required=True)
    ap.add_argument("--user-path",    required=True)
    ap.add_argument("--static-path",  required=True)
    ap.add_argument("--state-file",   default=None,
                    help="Path to timestamp state file; skip write if already current.")
    args = ap.parse_args()

    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        print("ERROR: 'cryptography' package missing. Run: pip install cryptography", file=sys.stderr)
        sys.exit(1)

    # Download bundle
    try:
        with urllib.request.urlopen(args.bundle_url, timeout=15) as r:
            bundle = json.loads(r.read().decode("utf-8"))
    except Exception as e:
        print(f"ERROR: Failed to download bundle: {e}", file=sys.stderr)
        sys.exit(1)

    for field in ("generated_at", "noise_filter", "user_filter", "static_filter", "signature"):
        if not bundle.get(field):
            print(f"ERROR: Bundle missing or empty field: {field}", file=sys.stderr)
            sys.exit(1)

    # Check state file — skip if already up-to-date
    if args.state_file:
        try:
            with open(args.state_file, "r") as f:
                if f.read().strip() == bundle["generated_at"]:
                    print(f"UP-TO-DATE: ts={bundle['generated_at']}")
                    sys.exit(2)
        except FileNotFoundError:
            pass

    # Build canonical payload exactly as the Python signer does
    payload = json.dumps(
        {"generated_at":  bundle["generated_at"],
         "noise_filter":  bundle["noise_filter"],
         "user_filter":   bundle["user_filter"],
         "static_filter": bundle["static_filter"]},
        separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")

    # Verify RSA-4096 PKCS#1v15 SHA-256 signature
    try:
        pub_der    = base64.b64decode(args.pub_key_b64.strip())
        public_key = serialization.load_der_public_key(pub_der)
        sig        = base64.b64decode(bundle["signature"])
        public_key.verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())
    except Exception as e:
        print(f"ERROR: Signature verification failed: {e}", file=sys.stderr)
        sys.exit(1)

    # Write files
    with open(args.noise_path,   "w", encoding="utf-8") as f:
        f.write(bundle["noise_filter"])
    with open(args.user_path,    "w", encoding="utf-8") as f:
        f.write(bundle["user_filter"])
    with open(args.static_path,  "w", encoding="utf-8") as f:
        f.write(bundle["static_filter"])

    # Update state file
    if args.state_file:
        with open(args.state_file, "w") as f:
            f.write(bundle["generated_at"])

    print(f"OK: Lua filters written (ts={bundle['generated_at']}, key_id={bundle.get('key_id','')})")
    sys.exit(0)

if __name__ == "__main__":
    main()
