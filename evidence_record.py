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

import os
import time
from typing import List, Tuple

__NAME__ = "Evidence Record Library"
__version__ = "1.0.0"  # Following semantic versioning: MAJOR.MINOR.PATCH
__author__ = "Florian Fischer"

class EvidenceRecord:
    def __init__(self):
        self.with_bracket = True

    @staticmethod
    def version():
        """Return the current version of ervis"""
        return __NAME__ + " " + __version__ + " (c)'2024, " + __author__

    def hash_pair(self, left, right=None, write_brackets=False):
        """Helper function to hash two values"""
        left_hash = left
        right_hash = right

        # In a real implementation, this would use a cryptographic hash
        # For this example, we simply concatenate the values
        if right_hash and write_brackets and self.with_bracket:
            return f"({left_hash}) + ({right_hash})"
        elif right_hash:
            return f"{left_hash}+{right_hash}"
        else:
            return left_hash

    def create_hashtree(self, hash_values: List[str]):
        """Creates a Merkle hash tree from a list of hash values"""
        tree = {
            'nodes': [],
            'levels': [],
            'root': None
        }

        # First level with the input hash values
        tree['levels'].append([{'hash': h, 'left': None, 'right': None, 'parent': None, 'level': 1, 'is_leaf': True, 'leaf_position': 'left' if i % 2 == 0 else 'right'} for i, h in enumerate(hash_values)])
        tree['nodes'].extend(tree['levels'][0])

        # Build the tree
        current_level = 0
        while len(tree['levels'][current_level]) > 1:
            next_level = current_level + 1
            tree['levels'].append([])

            for i in range(0, len(tree['levels'][current_level]), 2):
                left = tree['levels'][current_level][i]
                right = tree['levels'][current_level][i + 1] if i + 1 < len(tree['levels'][current_level]) else None

                parent_hash = self.hash_pair(left['hash'], right['hash'] if right else None)
                parent = {'hash': parent_hash, 'left': left, 'right': right, 'parent': None, 'level': next_level, 'is_leaf': False}

                left['parent'] = parent
                if right:
                    right['parent'] = parent

                tree['nodes'].append(parent)
                tree['levels'][next_level].append(parent)

            current_level = next_level

        tree['root'] = tree['levels'][-1][0]
        return tree

    @staticmethod
    def create_timestamp(hash_value: str, timestamp_hash_algorithm: str):
        """Creates an abstract timestamp for a hash value"""
        return {'hash': hash_value, 'time': time.time(), 'algorithm': timestamp_hash_algorithm}

    def reduce_tree(self, tree, target_hash):
        """Reduces a hash tree to an Archival Data Object (ADO)"""
        path = []
        current = None

        # Find the node with the target hash
        for node in tree['nodes']:
            if node['hash'] == target_hash:
                current = node
                break

        if not current:
            return None

        # Reduced tree as a new structure
        reduced_tree = {'hash': current['hash'], 'left': None, 'right': None, 'is_leaf': current['is_leaf'], 'leaf_position': current['leaf_position']}
        current_reduced = reduced_tree
        current = current['parent']

        # Build the path to the root
        while current:
            new_node = {'hash': current['hash'], 'left': None, 'right': None, 'is_leaf': False}
            if current['left'] and current['left']['hash'] == current_reduced['hash']:
                new_node['left'] = current_reduced
                if current['right']:
                    new_node['right'] = {'hash': current['right']['hash'], 'is_leaf': current['right']['is_leaf'], 'leaf_position': current['right']}
            else:
                new_node['right'] = current_reduced
                new_node['left'] = {'hash': current['left']['hash'], 'is_leaf': current['left']['is_leaf'], 'leaf_position': current['left']}

            current_reduced = new_node
            current = current['parent']

        return current_reduced

    def create_evidence_record(self, tree, reduced_tree, hash_algorithm):
        """Creates an Evidence Record for a specific hash"""
        timestamp = self.create_timestamp(tree['root']['hash'], hash_algorithm)

        return {
            'version': 1,
            'digestAlgorithm': hash_algorithm,
            'cryptoInfos': [],
            'encryptionInfo': None,
            'archiveTimeStampSequence': [
                {
                    'reduced': reduced_tree,
                    'timestamp': timestamp
                }
            ]
        }

    def encode_atsc(self, sequence):
        """Helper function to convert an ArchiveTimeStampSequence to a string"""
        # In a real implementation, this would use DER encoding
        # For this example, we simply concatenate the hashes
        encoded = ''
        for ats in sequence:
            # last current ats-hash is taken
            encoded = ats['timestamp']['hash']
        return encoded

    def renew_hashtree(self, records_and_hashes, new_hash_algorithm):
        """Renews the hash tree for a list of Evidence Records with new hash values"""
        new_hashes = []

        # Step 3 & 4: For each Evidence Record
        for record, new_document_hash in records_and_hashes:
            # Encode the existing ArchiveTimeStampSequence
            atsc = self.encode_atsc(record['archiveTimeStampSequence'])
            atsc_hash = self.hash_pair(atsc)  # Step 3: ha(i) = H(atsc(i))

            # Step 4: Combine Document Hash with ATSC Hash
            if isinstance(new_document_hash, list):
                for hash_value in new_document_hash:
                    # Step 4: Combine Document Hash with ATSC Hash
                    combined_hash = self.hash_pair(hash_value, atsc_hash, True)
                    new_hashes.append(combined_hash)
            else:
                # Step 4: Combine Document Hash with ATSC Hash
                combined_hash = self.hash_pair(new_document_hash, atsc_hash, True)
                new_hashes.append(combined_hash)

        # Step 5: Create a new hash tree with the combined hashes
        new_tree = self.create_hashtree(new_hashes)

        # Create reduced trees for each Evidence Record
        results = []
        for record, new_document_hash in records_and_hashes:
            combined_hash = new_hashes[records_and_hashes.index((record, new_document_hash))]

            # Reduce the tree for the specific hash
            reduced_tree = self.reduce_tree(new_tree, combined_hash)

            # Step 6: Create new ArchiveTimeStampChain
            new_timestamp = self.create_timestamp(new_tree['root']['hash'], new_hash_algorithm)
            new_chain = {
                'reduced': reduced_tree,
                'timestamp': new_timestamp
            }

            # Add the new chain to the sequence
            record['archiveTimeStampSequence'].append(new_chain)

            # Update the used hash algorithm
            record['digestAlgorithm'] = new_hash_algorithm

            results.append(record)

        return results, new_tree
