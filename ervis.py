"""
MIT License

Copyright (c) 2024 Florian Fischer

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from evidence_record import EvidenceRecord
from evidence_record_print import PrintEr

print(EvidenceRecord().version())

# Create initial hash values
initial_hashes = ["h1", "h2", "h3"]

# Create initial hash tree
tree = EvidenceRecord().create_hashtree(initial_hashes)

# Visualize the full and reduced trees
print("\n============================================")
print("\nFull hash tree:")
full_tree_vis = PrintEr().visualize_tree(tree['root'])
for line in full_tree_vis:
    print(line)

# Create Evidence Records for each hash
records = []
for hash_value in initial_hashes:
    reduced_tree = EvidenceRecord().reduce_tree(tree, hash_value)

    record = EvidenceRecord().create_evidence_record(tree, reduced_tree, "SHA256")

    PrintEr().display_evidence_record(record)

    result, text = EvidenceRecord().verify_evidence_record(record, [hash_value, "SHA256"])
    print("\n")
    print(text, result)

    records.append(record)

# Simulate new hashes with a new algorithm
records_and_hashes = [
    (records[0], "H1"),
    (records[1], "H2"),
    (records[2], "H3")
]

# Perform renewal
renewed_records, new_tree = EvidenceRecord().renew_hashtree(records_and_hashes, "SHA512")

# Visualize the full and reduced trees
print("\n============================================")
print("\nFull hash tree:")
full_tree_vis = PrintEr().visualize_tree(new_tree['root'])
for line in full_tree_vis:
    print(line)

for i, record in enumerate(renewed_records):
    PrintEr().display_evidence_record(record)

    result, text = EvidenceRecord().verify_evidence_record(record, [
        (initial_hashes[i], "SHA256"),
        (records_and_hashes[i][1], "SHA512"),
    ])
    print(text, result)

