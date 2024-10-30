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

from datetime import datetime
import time

class PrintEr:
    def spaces(self, n):
        """Helper function to generate spaces"""
        return " " * n

    def visualize_node(self, hash_value):
        """Visualizes a single node"""
        width = len(hash_value)
        top = f"+{'-' * (width + 2)}+"
        middle = f"| {hash_value} |"
        return [top, middle, top]

    def connect_nodes(self, left_lines, right_lines, center_spacing):
        """Helper function to connect lines"""
        result = []
        # First line: Connection lines
        first_line = ""
        left_width = len(left_lines[0]) if left_lines else 0
        right_width = len(right_lines[0]) if right_lines else 0

        if left_lines and right_lines:
            first_line = f"{self.spaces(left_width // 2)}/{self.spaces(center_spacing - 2)}\\{self.spaces(right_width // 2)}"
        elif left_lines:
            first_line = f"{self.spaces(left_width // 2)}|"
        elif right_lines:
            first_line = f"{self.spaces(center_spacing)}{self.spaces(right_width // 2)}|"

        result.append(first_line)
        return result

    def visualize_tree(self, node, prefix=""):
        """Visualizes a hash tree"""
        if not node:
            return []

        lines = []
        node_lines = self.visualize_node(node['hash'])

        # Recursively visualize child nodes
        left_lines = self.visualize_tree(node.get('left'), prefix + "  ")
        right_lines = self.visualize_tree(node.get('right'), prefix + "  ")

        # Calculate widths
        left_width = len(left_lines[0]) if left_lines else 0
        right_width = len(right_lines[0]) if right_lines else 0
        node_width = len(node_lines[0])
        spacing = 4

        # Center the node
        node_padding = max(0, (left_width + right_width + spacing - node_width) // 2)
        for line in node_lines:
            lines.append(self.spaces(node_padding) + line)

        # Add connection lines
        if node.get('left') or node.get('right'):
            connections = self.connect_nodes(
                left_lines[0] if left_lines else None,
                right_lines[0] if right_lines else None,
                spacing
            )
            lines.extend(connections)

        # Add child nodes
        max_child_lines = max(len(left_lines), len(right_lines))
        for i in range(max_child_lines):
            left_line = left_lines[i] if left_lines and i < len(left_lines) else self.spaces(left_width)
            right_line = right_lines[i] if right_lines and i < len(right_lines) else self.spaces(right_width)
            lines.append(left_line + self.spaces(spacing) + right_line)

        return lines

    def create_header_box(self, text, width):
        """Helper function to create a header box"""
        line = "-" * (width - 2)
        return [
            f"+{line}+",
            f"| {text}{self.spaces(width - 4 - len(text))} |",
            f"+{line}+"
        ]

    def merge_lines_horizontally(self, left, right, spacing=4):
        """Helper function to merge lines side by side"""
        result = []
        max_lines = max(len(left), len(right))
        left_width = len(left[0]) if left else 0
        
        for i in range(max_lines):
            left_line = left[i] if i < len(left) else self.spaces(left_width)
            right_line = right[i] if i < len(right) else self.spaces(len(right[0]) if right else 0)
            result.append(left_line + self.spaces(spacing) + right_line)
            
        return result

    def print_evidence_record(self, evidence_record):
        """Print an Evidence Record structure"""
        if not evidence_record:
            return ["No evidence record provided"]
        
        lines = []
        
        # Print header information
        header_info = self.create_header_box(
            f"Evidence Record v{evidence_record.get('version')} - {evidence_record.get('digestAlgorithm', 'Unknown Algorithm')}",
            60
        )
        
        lines.extend(header_info)
        lines.append("")
        
        # Print Archive Time Stamp Sequence
        ats_sequence = evidence_record.get('archiveTimeStampSequence', [])
        if ats_sequence:
            lines.append("Archive Time Stamp Sequence:")
            lines.append("-" * 30)
            
            for i, ats in enumerate(ats_sequence, 1):
                # Create chain header
                lines.append(f"Chain {i}:")
                lines.append("")
                
                # Print timestamp information
                if timestamp := ats.get('timestamp'):
                    timestamp_str = datetime.fromtimestamp(timestamp.get('time')).strftime("%Y-%m-%d %H:%M:%S")
                    timestamp_box = self.create_header_box(
                        f"Timestamp: {timestamp_str} [{timestamp.get('algorithm', 'Unknown')}]",
                        50
                    )
                    
                    for line in timestamp_box:
                        lines.append("  " + line)  # indent timestamp
                
                # Visualize reduced tree if present
                if reduced := ats.get('reduced'):
                    tree_lines = self.visualize_tree(reduced)
                    for line in tree_lines:
                        lines.append("  " + line)  # indent tree
                
                lines.append("")
                if i < len(ats_sequence):
                    lines.append("-" * 30)
        
        return lines

    def display_evidence_record(self, evidence_record):
        """Helper function to print the lines to console"""
        for line in self.print_evidence_record(evidence_record):
            print(line)
