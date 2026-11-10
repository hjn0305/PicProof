from pathlib import Path

p = Path("examples/picproof_authenticated_registry.rs")
lines = p.read_text(encoding="utf-8").splitlines()
new_lines = []
for line in lines:
    if line.startswith("//!"):
        line = "//" + line[3:]
    new_lines.append(line)
p.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
print("FIXED_DOC_COMMENTS=PASS")
