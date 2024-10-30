# ervis - Evidence Record Visualization

A Python/Lua library for creating, managing and visualizing Evidence Records based on [RFC 4998](https://datatracker.ietf.org/doc/html/rfc4998) (Evidence Record Syntax). This implementation serves as an educational example to understand the concepts of Evidence Records and their visualization.

## Overview

The ervis project consists of three main components, each for your preferred interpreter (Python or Lua):

For Python 3.12.+:

1. **evidence_record.py**: Core library for Evidence Record operations
2. **evidence_record_print.py**: Visualization utilities for Evidence Records
3. **ervis.py**: Example implementation demonstrating the library's usage

For Lua 5.4:
1. **evidence_record.lua**: Core library for Evidence Record operations
2. **evidence_record_print.lua**: Visualization utilities for Evidence Records
3. **ervis.lua**: Example implementation demonstrating the library's usage

## Features

- Creation, renewal and verification of Evidence Records
- Hash tree (Merkle tree) construction and reduction
- Timestamp sequence management
- Hash algorithm renewal support
- ASCII visualization of hash trees and Evidence Records

## Core library

### Evidence Record creation (evidence_record.py)

The main library providing all Evidence Record related functionality:

```python
from evidence_record import EvidenceRecord

# Create an Evidence Record instance
er = EvidenceRecord()

# Create a hash tree from multiple hash values
tree = er.create_hashtree(["h1", "h2", "h3"])

# Reduce tree for a specific hash
reduced_tree = EvidenceRecord().reduce_tree(tree, hash_value)

# Create an Evidence Record with the reduced tree for a specific hash
record = er.create_evidence_record(tree, reduced_tree, "SHA256")

# Verify an Evidence Record
result, message = er.verify_evidence_record(record, [(hash_value, "SHA256")])
print("\n")
print(text, result)
```

### Evidence Record hash algorithm renewal

The library supports Evidence Record hash algorithm renewal:

```python
# Simulate to update existing Evidence Records with new hashes with a new algorithm
records_and_hashes = [
    (records1, "H1"),
    (records2, "H2"),
    (records3, "H3")
]

# Renew hash algorithms
new_records, new_tree = er.renew_hashtree(records_and_hashes, "SHA512")
```

## Evidence Record visualization utilities

### Evidence Record visualization (evidence_record_print.py)

Visualization utilities (ASCII-based) for Evidence Records and hash trees:

```python
from evidence_record_print import PrintEr

# Visualize a hash tree
tree_visualization = PrintEr().visualize_tree(tree['root'])
for line in tree_visualization:
    print(line)
```

```python
from evidence_record_print import PrintEr

# Display a complete Evidence Record
PrintEr().display_evidence_record(record)
```

### Hash Tree Visualization Example

The library can create ASCII visualizations of hash trees like this:

```
        +-------+
        | h1+h2 |
        +-------+
           /\
          /  \
    +----+    +----+
    | h1 |    | h2 |
    +----+    +----+
```

## Evidence Record Structure

For details please refer to [RFC4998](https://datatracker.ietf.org/doc/html/rfc4998)

## Installation

Clone the repository:
```bash
git clone https://github.com/yourusername/ervis.git

cd ervis

python ervis.py
```

or

```bash
git clone https://github.com/yourusername/ervis.git

cd ervis

lua ervis.lua
```

No additional dependencies required - the library uses only Python/Lua standard library components.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Florian Fischer (c) 2024

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Note

This is an educational implementation to demonstrate Evidence Record concepts. For production use, please implement proper cryptographic functions and timestamp authorities.