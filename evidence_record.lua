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

local withBracket = false

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
        encoded = encoded .. ats.timestamp.hash
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
        local newDocumentHash = tuple[2]
        
        -- Encode die bestehende ArchiveTimeStampSequence
        local atsc = encodeATSC(record.archiveTimeStampSequence)
        local atscHash = hashPair(atsc) -- Schritt 3: ha(i) = H(atsc(i))
        
        -- Schritt 4: Kombiniere Document Hash mit ATSC Hash
        local combinedHash = hashPair(newDocumentHash, atscHash, true)
        table.insert(newHashes, combinedHash)
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

-- Hilfsfunktion zum Verifizieren eines einzelnen Zeitstempels
local function verifyTimestamp(timestamp, referenceTime)
    -- In einer echten Implementierung würde hier die kryptographische Signatur geprüft
    -- und die Gültigkeit zum Referenzzeitpunkt verifiziert
    -- Für dieses Beispiel prüfen wir nur, ob der Timestamp vor der Referenzzeit liegt
    return timestamp.time < referenceTime
end

-- Hilfsfunktion zum Verifizieren eines reduzierten Merkle-Baums
local function verifyReducedTree(reducedTree, targetHash)
    if not reducedTree then
        return false
    end
    
    -- Wenn wir ein Blatt erreicht haben, vergleiche den Hash
    if reducedTree.isLeaf then
        return reducedTree.hash == targetHash
    end
    
    -- Berechne den Hash des aktuellen Knotens basierend auf seinen Kindern
    local calculatedHash
    if reducedTree.left and reducedTree.right then
        calculatedHash = hashPair(reducedTree.left.hash, reducedTree.right.hash)
    else
        calculatedHash = reducedTree.left and reducedTree.left.hash or reducedTree.right.hash
    end
    
    return calculatedHash == reducedTree.hash
end

-- Hauptfunktion zur Verifikation eines Evidence Records
function EvidenceRecord.verifyEvidenceRecord(record, hashValueAlgorithmPairs)
    if not record or not record.archiveTimeStampSequence or #record.archiveTimeStampSequence == 0 then
        return false, "Invalid evidence record structure"
    end
    
    local currentTime = os.time()+1
    
    -- Schritt 1: Verifiziere den initialen Archive Timestamp
    local initialChain = record.archiveTimeStampSequence[1]
    local initialHash = hashValueAlgorithmPairs[1][1]
    local initialAlgorithm = hashValueAlgorithmPairs[1][2]
    
    if not verifyReducedTree(initialChain.reduced, initialHash) then
        return false, "Initial hash verification failed"
    end
    
    -- Schritt 2: Verifiziere jede ArchiveTimestampChain
    local previousTimestamp = initialChain.timestamp
    local previousAlgorithm = initialAlgorithm
    
    for i = 2, #record.archiveTimeStampSequence do
        local currentChain = record.archiveTimeStampSequence[i]
        local currentHash = hashValueAlgorithmPairs[i][1]
        local currentAlgorithm = hashValueAlgorithmPairs[i][2]
        
        -- Prüfe, ob der Hash-Algorithmus in der Kette konsistent ist
        if currentAlgorithm == previousAlgorithm then
            return false, string.format(
                "Inconsistent hash algorithm in chain %d: expected %s, got %s",
                i, previousAlgorithm, currentAlgorithm
            )
        end
        
        -- Verifiziere den Zeitstempel
        if not verifyTimestamp(previousTimestamp, currentChain.timestamp.time+1) then
            return false, string.format(
                "Invalid timestamp sequence in chain %d",
                i
            )
        end
        
        -- Schritt 3: Verifiziere die Verkettung der ArchiveTimeStampChains
		local rightLeaf = encodeATSC({ timestamp = { previousTimestamp} })
        local concatenatedHash = hashPair(currentHash, rightLeaf)
        if not verifyReducedTree(currentChain.reduced, concatenatedHash) then
            return false, string.format(
                "Chain linkage verification failed at chain %d",
                i
            )
        end
        
        previousTimestamp = currentChain.timestamp
        previousAlgorithm = currentAlgorithm
    end
    
    -- Prüfe die Gültigkeit des letzten Zeitstempels
    if not verifyTimestamp(previousTimestamp, currentTime) then
        return false, "Last timestamp is not valid at current time"
    end
    
    return true, "Evidence record verification successful"
end

return EvidenceRecord
