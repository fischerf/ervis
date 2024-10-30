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

-- Visualisieren der Hashbäume nach Evidence Record Implementation nach RFC4998
local PrintEr = {}

-- Hilfsfunktion zum Erzeugen von Leerzeichen
local function spaces(n)
    return string.rep(" ", n)
end

-- Visualisiert einen einzelnen Knoten
local function visualizeNode(hash)
    local width = #hash
    local top = "+" .. string.rep("-", width + 2) .. "+"
    local middle = "| " .. hash .. " |"
    return {top, middle, top}
end

-- Hilfsfunktion zum Verbinden von Linien
local function connectNodes(leftLines, rightLines, centerSpacing)
    local result = {}
    -- Erste Zeile: Verbindungslinien
    local firstLine = ""
    local leftWidth = #(leftLines and leftLines[1] or "")
    local rightWidth = #(rightLines and rightLines[1] or "")
    
    if leftLines and rightLines then
        firstLine = spaces(leftWidth/2) .. "/" .. spaces(centerSpacing-2) .. "\\" .. spaces(rightWidth/2)
    elseif leftLines then
        firstLine = spaces(leftWidth/2) .. "|"
    elseif rightLines then
        firstLine = spaces(centerSpacing) .. spaces(rightWidth/2) .. "|"
    end
    
    table.insert(result, firstLine)
    return result
end

-- Visualisiert einen Hashbaum
function PrintEr.visualizeTree(node, prefix)
    if not node then return {} end
    prefix = prefix or ""
    
    local lines = {}
    local nodeLines = visualizeNode(node.hash)
    
    -- Rekursiv die Kindknoten visualisieren
    local leftLines = PrintEr.visualizeTree(node.left, prefix .. "  ")
    local rightLines = PrintEr.visualizeTree(node.right, prefix .. "  ")
    
    -- Breiten berechnen
    local leftWidth = leftLines[1] and #leftLines[1] or 0
    local rightWidth = rightLines[1] and #rightLines[1] or 0
    local nodeWidth = #nodeLines[1]
    local spacing = 4
    
    -- Knoten zentrieren
    local nodePadding = math.max(0, (leftWidth + rightWidth + spacing - nodeWidth) / 2)
    for _, line in ipairs(nodeLines) do
        table.insert(lines, spaces(math.floor(nodePadding)) .. line)
    end
    
    -- Verbindungslinien hinzufügen
    if node.left or node.right then
        local connections = connectNodes(leftLines[1], rightLines[1], spacing)
        for _, line in ipairs(connections) do
            table.insert(lines, line)
        end
    end
    
    -- Kindknoten hinzufügen
    local maxChildLines = math.max(#leftLines, #rightLines)
    for i = 1, maxChildLines do
        local leftLine = leftLines[i] or spaces(leftWidth)
        local rightLine = rightLines[i] or spaces(rightWidth)
        table.insert(lines, leftLine .. spaces(spacing) .. rightLine)
    end
    
    return lines
end

-- Helper function to print the lines to console
function PrintEr.displayTree(tree)
	local lines = PrintEr.visualizeTree(tree)
	for _, line in ipairs(lines) do
		print(line)
	end
end

-- Helper function to create a header box
local function createHeaderBox(text, width)
    local line = string.rep("-", width-2)
    return {
        "+" .. line .. "+",
        "| " .. text .. string.rep(" ", width-4-#text) .. " |",
        "+" .. line .. "+"
    }
end

-- Helper function to merge lines side by side
local function mergeLinesHorizontally(left, right, spacing)
    spacing = spacing or 4
    local result = {}
    local maxLines = math.max(#left, #right)
    
    for i = 1, maxLines do
        local leftLine = left[i] or string.rep(" ", #(left[1] or ""))
        local rightLine = right[i] or string.rep(" ", #(right[1] or ""))
        table.insert(result, leftLine .. string.rep(" ", spacing) .. rightLine)
    end
    
    return result
end

-- Print an Evidence Record structure
function PrintEr.printEvidenceRecord(evidenceRecord)
    if not evidenceRecord then
        return {"No evidence record provided"}
    end
    
    local lines = {}
    
    -- Print header information
    local headerInfo = createHeaderBox(string.format(
        "Evidence Record v%d - %s", 
        evidenceRecord.version,
        evidenceRecord.digestAlgorithm or "Unknown Algorithm"
    ), 60)
    
    for _, line in ipairs(headerInfo) do
        table.insert(lines, line)
    end
    table.insert(lines, "")
    
    -- Print Archive Time Stamp Sequence
    if evidenceRecord.archiveTimeStampSequence then
        table.insert(lines, "Archive Time Stamp Sequence:")
        table.insert(lines, string.rep("-", 30))
        
        for i, ats in ipairs(evidenceRecord.archiveTimeStampSequence) do
            -- Create chain header
            table.insert(lines, string.format("Chain %d:", i))
            table.insert(lines, "")
            
            -- Print timestamp information
            if ats.timestamp then
                local timestampBox = createHeaderBox(string.format(
                    "Timestamp: %s [%s]",
                    os.date("%Y-%m-%d %H:%M:%S", ats.timestamp.time),
                    ats.timestamp.algorithm or "Unknown"
                ), 50)
                
                for _, line in ipairs(timestampBox) do
                    table.insert(lines, "  " .. line)  -- indent timestamp
                end
            end

            -- Visualize reduced tree if present
            if ats.reduced then
                local treeLines = PrintEr.visualizeTree(ats.reduced)
                for _, line in ipairs(treeLines) do
                    table.insert(lines, "  " .. line)  -- indent tree
                end
            end
            
            table.insert(lines, "")
            if i < #evidenceRecord.archiveTimeStampSequence then
                table.insert(lines, string.rep("-", 30))
            end
        end
    end
    
    -- Return all lines joined by newlines
    return lines
end

-- Helper function to print the lines to console
function PrintEr.displayEvidenceRecord(evidenceRecord)
    local lines = PrintEr.printEvidenceRecord(evidenceRecord)
    for _, line in ipairs(lines) do
        print(line)
    end
end

return PrintEr
