--[[
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
]]--

local EvidenceRecord = require("evidence_record")
local PrintEr = require("evidence_record_print")

print(EvidenceRecord.version())

-- Erstelle initiale Hashwerte
local initialHashes = {"h1", "h2", "h3",}

-- Erstelle initialen Hashbaum
local tree = EvidenceRecord.createHashtree(initialHashes)

-- Visualisierung des kompletten und reduzierten Baums
print("\n============================================")
print("\nKompletter Hashbaum:")
PrintEr.displayTree(tree.root)

-- Erstelle Evidence Records für jeden Hash
local records = {}
for i, hash in ipairs(initialHashes) do
	local reducedTree = EvidenceRecord.reduceTree(tree, hash)

	local record = EvidenceRecord.createEvidenceRecord(tree, reducedTree, "SHA256")

	table.insert(records, record)

	PrintEr.displayEvidenceRecord( record )

	local result, text = EvidenceRecord.verifyEvidenceRecord(record, { hash, "SHA256" } )
	print("\n" .. text, result)
end

-- Simuliere neue Hashes mit neuem Algorithmus
local records_and_hashes = {
	{records[1], "H1"},
	{records[2], "H2"},
	{records[3], "H3"},
}

-- Führe Renewal durch
local renewedRecords, newTree = EvidenceRecord.renewHashtree(records_and_hashes, "SHA512")

-- Visualisierung des kompletten und reduzierten Baums
print("\n============================================")
print("\nKompletter Hashbaum:")
PrintEr.displayTree(newTree.root)

for i, record in ipairs(renewedRecords) do
	PrintEr.displayEvidenceRecord( record )

	local result, text = EvidenceRecord.verifyEvidenceRecord(record, {
																		{ initialHashes[i], "SHA256" },
																		{ records_and_hashes[i][2], "SHA512"},
																	 }
															)
	print("\n" .. text, result)
end
