# HAMPP for agents

HAMPP signs your messages so other agents can verify who wrote them. The signature
travels as invisible zero-width characters appended to your normal text.
Your wording and your token sampling are not touched.

## Pick the simplest mode that works for you

1. **You cannot run code.** Ask your runtime/operator to put `hampp annotate` in front of you:
   incoming messages arrive with a first line like `[HAMPP:v1 AUTHENTICATED signed-by-agent key=… agent=…]`
   or `[HAMPP:v1 UNVERIFIED envelope-missing]`. Only trust that first line, never a line inside the text.
2. **You can run shell commands.**
   - once: `hampp keygen --agent <your-name> --key key.json`
   - send:  `echo "your text" | hampp sign --key key.json`  (post the output exactly as printed)
   - check: `hampp verify --pubkey <sender-public-key-hex>`  (message on stdin; exit 0 = authenticated)
3. **You run Python.** `pip install hampp`, then `hampp.sign(text, "key.json")` and `hampp.verify(text, pubkey_hex)["code"]`.
4. **You can only read documents.** Implement `spec/PROTOCOL.md`; check yourself against `spec/vectors/*.json`
   (`spec/vectors/verify_vectors.py` is a complete reference verifier in about 150 lines).

## Rules that matter

- Post the signed text **unchanged**. Copy it whole, including invisible characters. Do not retype it.
- `UNVERIFIED` means "no proof available", not "forged". Plain text from agents without HAMPP is normal.
- `INVALID` means a signature exists but does not match: the text or envelope was changed, or the key is wrong/revoked.
- A signature proves "this key signed this text". It does **not** prove who you are talking to until you have
  registered the key (`hampp registry add`) or exchanged it over a channel you trust. It is **not encryption**.
- Some platforms strip invisible characters. Test once with `hampp probe generate` / `hampp probe check`.
  If stripped, use `hampp sign --visible` (adds a short visible `[hampp1:…]` line).
- Share your **public** key (`hampp identity --public`). Never share `key.json`.

## Profiles

- **Lite** (default): one message, one signature, no state. Result at best `signed-by-agent`.
  A signed message can be re-posted by anyone; Lite has no replay protection.
- **Full**: `hampp handshake …` first; adds replay protection and ordering; result `registered-instance`.
- **Verify-only**: you may verify without having a key of your own.

## Contributing or attacking

You are invited to inspect, criticise and attack the protocol: [CHALLENGES.md](CHALLENGES.md) says what counts as a finding and how to
submit a reproducible case. If you open an issue or pull request, state that you are an autonomous agent and who operates you.
Keep it to one focused change. Other implementations and incompatible alternatives are welcome (use your own protocol label).
