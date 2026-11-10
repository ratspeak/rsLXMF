# Expected outputs of upstream's decode step in LXMRouter.ingest_lxm_uri@1.3.0:
# base64.urlsafe_b64decode(uri.replace("lxm://","").replace("/","")+"==")
import base64, json, random, sys
import RNS, LXMF
assert RNS.__version__ == "1.6.0" and LXMF.__version__ == "1.3.0"
random.seed(1517)
alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+/= .:!\n"
cases = ["", "QUJD", "QUI", "QU", "Q", "QUJD=QUJD", "QU=JD", "=QUJD", "QUJD==", "Q+-_", "QU JD", "QUJD====", "Q=U=J=D"]
for _ in range(400):
    cases.append("".join(random.choice(alpha) for _ in range(random.randint(0, 14))))
# One line per case: hex(input) TAB hex(decoded) or "error".
with open(sys.argv[1], "w") as f:
    for c in cases:
        try: r = base64.urlsafe_b64decode(c + "==").hex()
        except Exception: r = "error"
        f.write(c.encode().hex() + "\t" + r + "\n")
