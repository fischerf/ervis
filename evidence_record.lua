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

-- Evidence Record Implementation nach RFC4998
local EvidenceRecord = {
	_NAME = "Evidence Record Library",
    _VERSION = "1.0.0",  -- Following semantic versioning: MAJOR.MINOR.PATCH
    _AUTHOR = "Florian Fischer"
}

-- Return version string
function EvidenceRecord.version()
    return EvidenceRecord._NAME .. " " .. EvidenceRecord._VERSION .. " (c)'2024, " .. EvidenceRecord._AUTHOR
end

local withBracket = true

-- Hilfsfunktion zum Hashen von zwei Werten
local function hashPair(left, right, writeBrackets)
    -- Make sure we're working with the hash values, not node objects
    local leftHash = type(left) == "table" and left.hash or left
    local rightHash = type(right) == "table" and right.hash or right
    
    -- In einer echten Implementierung würde hier ein kryptographischer Hash verwendet
    -- Für dieses Beispiel konkatenieren wir einfach die Werte
    if rightHash and writeBrackets and withBracket then
        return "(" .. leftHash .. ") + (" .. rightHash .. ")"
	elseif rightHash then
        return leftHash .. "+" .. rightHash
    else
        return leftHash
    end
end

-- Erstellt einen Merkle-Hashbaum aus einer Liste von Hashwerten
function EvidenceRecord.createHashtree(hashValues)
    local tree = {
        nodes = {},
        levels = {},
        root = nil
    }
    
    -- Erste Ebene mit den Eingabe-Hashwerten
    tree.levels[1] = {}
    for i, hash in ipairs(hashValues) do
        local node = {
            hash = hash,
            left = nil,
            right = nil,
            parent = nil,
            level = 1,
            isLeaf = true,
            leafPosition = i % 2 == 1 and "left" or "right"
        }
        table.insert(tree.nodes, node)
        table.insert(tree.levels[1], node)
    end
    
    -- Baum aufbauen
    local currentLevel = 1
    while #tree.levels[currentLevel] > 1 do
        local nextLevel = currentLevel + 1
        tree.levels[nextLevel] = {}
        
        for i = 1, #tree.levels[currentLevel], 2 do
            local left = tree.levels[currentLevel][i]
            local right = tree.levels[currentLevel][i + 1]
            
            local parentHash
            if right then
                parentHash = hashPair(left.hash, right.hash)
            else
                parentHash = left.hash -- Einzelner Knoten wird nach oben durchgereicht
            end
            
            local parent = {
                hash = parentHash,
                left = left,
                right = right,
                parent = nil,
                level = nextLevel,
                isLeaf = false
            }
            
            left.parent = parent
            if right then
                right.parent = parent
            end
            
            table.insert(tree.nodes, parent)
            table.insert(tree.levels[nextLevel], parent)
        end
        
        currentLevel = nextLevel
    end
    
    tree.root = tree.levels[#tree.levels][1]
    return tree
end

-- Erstellt einen abstrakten Zeitstempel für einen Hashwert
function EvidenceRecord.createTimestamp(hash, timeStampHashAlgorithm)
    return {
        hash = hash,
        time = os.time(),
        algorithm = timeStampHashAlgorithm, -- "SHA256" - Beispiel-Algorithmus
    }
end

-- Reduziert einen Hashbaum zu einem Archival Data Object (ADO)
function EvidenceRecord.reduceTree(tree, targetHash)
    local path = {}
    local current = nil
    
    -- Finde den Knoten mit dem Zielhash
    for _, node in ipairs(tree.nodes) do
        if node.hash == targetHash then
            current = node
            break
        end
    end
    
    if not current then
        return nil
    end
    
    -- Reduzierter Baum als neue Struktur
    local reducedTree = {
        hash = current.hash,
        left = nil,
        right = nil,
        isLeaf = current.isLeaf,
        leafPosition = current.leafPosition
    }
    
    local currentReduced = reducedTree
    current = current.parent
    
    -- Pfad zur Wurzel aufbauen
    while current do
        local newNode = {
            hash = current.hash,
            left = nil,
            right = nil,
            isLeaf = false
        }
        
        if current.left and current.left.hash == currentReduced.hash then
            newNode.left = currentReduced
            if current.right then
                newNode.right = {
                    hash = current.right.hash,
                    isLeaf = current.right.isLeaf,
                    leafPosition = current.right.leafPosition
                }
            end
        else
            newNode.right = currentReduced
            newNode.left = {
                hash = current.left.hash,
                isLeaf = current.left.isLeaf,
                leafPosition = current.left.leafPosition
            }
        end
        
        currentReduced = newNode
        current = current.parent
    end
    
    return currentReduced
end

-- Erstellt einen Evidence Record für einen bestimmten Hash
function EvidenceRecord.createEvidenceRecord(tree, reducedTree, hashAlgorithm)
    local timestamp = EvidenceRecord.createTimestamp(tree.root.hash, hashAlgorithm)

    return {
        version = 1,
        digestAlgorithm = hashAlgorithm, -- "SHA256" - Beispiel-Algorithmus
        cryptoInfos = {},
        encryptionInfo = nil,
        archiveTimeStampSequence = {
            {
                reduced = reducedTree,
                timestamp = timestamp
            }
        }
    }
end

-- Hilfsfunktion zum Konvertieren einer ArchiveTimeStampSequence in einen String
local function encodeATSC(sequence)
    -- In einer echten Implementierung würde hier DER-Encoding stattfinden
    -- Für dieses Beispiel konkatenieren wir einfach die Hashes
    local encoded = ""
    for _, ats in ipairs(sequence) do
        -- letzter aktueller ats-hash wird genommen
        encoded = ats.timestamp.hash
    end
    return encoded
end

-- Erneuert den Hashbaum für eine Liste von Evidence Records mit neuen Hashwerten
function EvidenceRecord.renewHashtree(records_and_hashes, newHashAlgorithm)
    -- records_and_hashes ist eine Liste von Tupeln {record, newHash}
    local newHashes = {}
    
    -- Schritt 3 & 4: Für jeden Evidence Record
    for _, tuple in ipairs(records_and_hashes) do
        local record = tuple[1]
--        local newDocumentHash = tuple[2]
        
        -- Encode die bestehende ArchiveTimeStampSequence
        local atsc = encodeATSC(record.archiveTimeStampSequence)
        local atscHash = hashPair(atsc) -- Schritt 3: ha(i) = H(atsc(i))
        
        local newDocumentHash = tuple[2]
		
		if type(newDocumentHash) == "table" then
			for _, hash in ipairs(newDocumentHash) do
				-- Schritt 4: Kombiniere Document Hash mit ATSC Hash
				local combinedHash = hashPair(hash, atscHash, true)
				table.insert(newHashes, combinedHash)
			end
		else
			-- Schritt 4: Kombiniere Document Hash mit ATSC Hash
			local combinedHash = hashPair(newDocumentHash, atscHash, true)
			table.insert(newHashes, combinedHash)
		end
    end
    
    -- Schritt 5: Erstelle einen neuen Hashbaum mit den kombinierten Hashes
    local newTree = EvidenceRecord.createHashtree(newHashes)
    
    -- Erstelle reduzierte Bäume für jeden Evidence Record
    local results = {}
    for i, tuple in ipairs(records_and_hashes) do
        local record = tuple[1]
        local combinedHash = newHashes[i]
        
        -- Reduziere den Baum für den spezifischen Hash
        local reducedTree = EvidenceRecord.reduceTree(newTree, combinedHash)

        -- Schritt 6: Erstelle neue ArchiveTimeStampChain
        local newTimestamp = EvidenceRecord.createTimestamp(newTree.root.hash, newHashAlgorithm)
        local newChain = {
            reduced = reducedTree,
            timestamp = newTimestamp
        }
        
        -- Füge die neue Chain zur Sequence hinzu
        table.insert(record.archiveTimeStampSequence, newChain)
        
        -- Aktualisiere den verwendeten Hash-Algorithmus
        record.digestAlgorithm = newHashAlgorithm

        table.insert(results, record)
    end
    
    return results, newTree
end

--------------------------------------------------------------------
-- Verification is not complete!
--[[
-- Helper function to verify a single timestamp
local function verifyTimestamp(timestamp, referenceTime)
    -- In a real implementation, the cryptographic signature would be verified
    -- and validity would be checked at the reference time
    -- For this example, we just check if the timestamp is before the reference time
    return timestamp.time < referenceTime
end

-- Helper function to verify a reduced Merkle tree
local function verifyReducedTree(reducedTree, targetHash)
    if not reducedTree then
        return false
    end
    
    -- First, find the target hash in the leaf nodes
    local function findTargetInLeaves(node)
        if not node then
            return false
        end
        
        -- If we're at a leaf, check if it matches the target hash
        if node.isLeaf then
            return node.hash == targetHash
        end
        
        -- Recursively search left and right subtrees
        return findTargetInLeaves(node.left) or findTargetInLeaves(node.right)
    end
    
    -- Verify the hash calculations from bottom to top
    local function verifyNodeHash(node)
        if not node then
            return true
        end
        
        -- If it's a leaf node, no need to verify further down
        if node.isLeaf then
            return true
        end
        
        -- Verify left and right subtrees first
        if not verifyNodeHash(node.left) or not verifyNodeHash(node.right) then
            return false
        end
        
        -- Calculate expected hash based on children
        local calculatedHash
		--print('check hash', node.left and node.left.hash, node.right and node.right.hash)
        if node.left and node.right then
            calculatedHash = node.left.hash .. "+" .. node.right.hash
        elseif node.left or node.right then
            calculatedHash = node.left and node.left.hash or node.right.hash
        end
        
        -- Compare calculated hash with stored hash
        --print('compare', calculatedHash, node.hash, calculatedHash == node.hash)
        return calculatedHash == node.hash
    end
    
    -- First verify that the target hash exists in the leaves
    if not findTargetInLeaves(reducedTree) then
        return false
    end
    
    -- Then verify the hash chain from bottom to top
    return verifyNodeHash(reducedTree)
end

-- Main function to verify an Evidence Record
function EvidenceRecord.verifyEvidenceRecord(record, hashValueAlgorithmPairs)
    if not record or not record.archiveTimeStampSequence or #record.archiveTimeStampSequence == 0 then
        return false, "Invalid evidence record structure"
    end
    
    local currentTime = os.time() + 1
    
    -- Step 1: Verify the initial Archive Timestamp
    local initialChain = record.archiveTimeStampSequence[1]
    local initialHash = hashValueAlgorithmPairs[1][1]
    local initialAlgorithm = hashValueAlgorithmPairs[1][2]
    --print('initialChain.reduced, initialHash', initialChain.reduced, initialHash)
    if not verifyReducedTree(initialChain.reduced, initialHash) then
        return false, "Initial hash verification failed"
    end
    
    -- Step 2: Verify each ArchiveTimestampChain
    local previousTimestamp = initialChain.timestamp
    local previousAlgorithm = initialAlgorithm
    
    for i = 1, #record.archiveTimeStampSequence do
        local currentChain = record.archiveTimeStampSequence[i]
        local currentHash = hashValueAlgorithmPairs[i][1]
        local currentAlgorithm = hashValueAlgorithmPairs[i][2]
        
        -- Check if hash algorithm in chain is consistent
        if currentAlgorithm == previousAlgorithm then
            return false, string.format(
                "Inconsistent hash algorithm in chain %d: expected different than %s, got %s",
                i, previousAlgorithm, currentAlgorithm
            )
        end
        
        -- Verify timestamp
        if not verifyTimestamp(previousTimestamp, currentChain.timestamp.time + 1) then
            return false, string.format(
                "Invalid timestamp sequence in chain %d",
                i
            )
        end
        
        -- Step 3: Verify the chaining of ArchiveTimeStampChains
        local rightLeaf = previousTimestamp.hash -- Encode the previous timestamp
        local concatenatedHash = currentHash .. "+" .. rightLeaf
        if not verifyReducedTree(currentChain.reduced, concatenatedHash) then
            return false, string.format(
                "Chain linkage verification failed at chain %d",
                i
            )
        end
        
        previousTimestamp = currentChain.timestamp
        previousAlgorithm = currentAlgorithm
    end
    
    -- Check validity of last timestamp
    if not verifyTimestamp(previousTimestamp, currentTime) then
        return false, "Last timestamp is not valid at current time"
    end
    
    return true, "Evidence record verification successful"
end

-- Test function to validate the implementation
local function testVerifyReducedTree()
    local testReducedTree = {
						hash = "h1+h2+h3",
						isLeaf = false,
						left = {
						  hash = "h1+h2",
						  isLeaf = false
						},
						right = {
						  hash = "h3",
						  isLeaf = false,
						  left = {
							hash = "h3",
							isLeaf = true,
							leafPosition = "left"
						  }
						}
					  }
    
    -- Test cases
    print("Testing h1:", verifyReducedTree(testReducedTree, "h1"))  -- Should be false
    print("Testing h2:", verifyReducedTree(testReducedTree, "h2"))  -- Should be false
    print("Testing h3:", verifyReducedTree(testReducedTree, "h3"))  -- Should be true
    print("Testing invalid hash:", verifyReducedTree(testReducedTree, "h4"))  -- Should be false
end

testVerifyReducedTree()

local function testVerifyEvidenceRecord()
    local testEvidenceRecord = {
					  archiveTimeStampSequence = { {
						  reduced = {
							hash = "h1+h2+h3",
							isLeaf = false,
							left = {
							  hash = "h1+h2",
							  isLeaf = false
							},
							right = {
							  hash = "h3",
							  isLeaf = false,
							  left = {
								hash = "h3",
								isLeaf = true,
								leafPosition = "left"
							  }
							}
						  },
						  timestamp = {
							algorithm = "SHA256",
							hash = "h1+h2+h3",
							time = 1730736754
						  }
						}, {
						  reduced = {
							hash = "H1+h1+h2+h3+H2+h1+h2+h3+H3+h1+h2+h3",
							isLeaf = false,
							left = {
							  hash = "H1+h1+h2+h3+H2+h1+h2+h3",
							  isLeaf = false
							},
							right = {
							  hash = "H3+h1+h2+h3",
							  isLeaf = false,
							  left = {
								hash = "H3+h1+h2+h3",
								isLeaf = true,
								leafPosition = "left"
							  }
							}
						  },
						  timestamp = {
							algorithm = "SHA512",
							hash = "H1+h1+h2+h3+H2+h1+h2+h3+H3+h1+h2+h3",
							time = 1730736754
						  }
						} },
					  cryptoInfos = {},
					  digestAlgorithm = "SHA512",
					  version = 1
					}
    -- Test case: A sequence with two chains, where one document is covered. In the first chain the document hash is h3 made with SHA256 HashAlgorithm and the second hash of the document is H3 made with SHA512 HashAlgorithm.
	local result, text = EvidenceRecord.verifyEvidenceRecord(testEvidenceRecord, {
																		{ "h3", "SHA256" },
																		{ "H3", "SHA512"},
																	 }
															)
	print("Testing ER:", text, result)	-- result should be true
end

testVerifyEvidenceRecord()
]]--

return EvidenceRecord
