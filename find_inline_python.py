from pathlib import Path
content = Path(".github/workflows/sentinel-blogger.yml").read_text(encoding="utf-8")
lines = content.splitlines()
# Find all python3 -c occurrences that have multiline issues
for i, line in enumerate(lines, 1):
    if 'python3 -c "' in line or "python3 -c '" in line:
        print(f"Line {i}: {line.rstrip()}")
        # Show context: next 3 lines
        for j in range(i, min(i+4, len(lines))):
            print(f"  +{j-i+1}: {lines[j].rstrip() if j < len(lines) else '(EOF)'}")
        print()
print("Search complete.")
