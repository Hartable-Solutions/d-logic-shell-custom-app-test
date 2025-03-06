/**
 * Mifare Card Operations - D-Logic uFR ZERO Implementation
 * 
 * This file implements Mifare Classic card operations for D-Logic uFR ZERO reader
 * using direct communication with the card reader through WebUSB API.
 */

// Global constants for key types
const DEFAULT_KEY = "FFFFFFFFFFFF";  // Type A key (FF FF FF FF FF FF)
const KEY_A = 0x60;
const KEY_B = 0x61;

// D-Logic uFR ZERO specific constants
const VENDOR_ID = 0x1427;  // D-Logic Vendor ID for uFR ZERO
const PRODUCT_ID = 0x0001; // Product ID may need adjustment depending on specific model
const DL_OK = 0x0000;      // Success status code

// Reader state
let reader = null;
let isConnected = false;
let cardPresent = false;

/**
 * Initialize the card reader
 * @returns {Promise<boolean>} - Resolves to true when reader is initialized successfully
 */
async function initializeReader() {
    try {
        if (navigator.usb) {
            // Using Web USB API to connect to the reader
            const devices = await navigator.usb.getDevices();
            if (devices.length > 0) {
                // Try to find a D-Logic device among connected devices
                const dlogicDevice = devices.find(d => d.vendorId === VENDOR_ID);
                if (dlogicDevice) {
                    reader = dlogicDevice;
                } else {
                    reader = devices[0]; // Fallback to first device if no D-Logic device found
                }
                
                await reader.open();
                await reader.selectConfiguration(1);
                await reader.claimInterface(0);
                isConnected = true;
                console.log("Reader connected successfully");
                
                // Check if card is present
                cardPresent = await checkCardPresence();
                
                return true;
            } else {
                // Try to request a D-Logic device if none are already paired
                try {
                    const filters = [
                        { vendorId: VENDOR_ID }  // D-Logic vendor ID
                    ];
                    reader = await navigator.usb.requestDevice({ filters });
                    await reader.open();
                    await reader.selectConfiguration(1);
                    await reader.claimInterface(0);
                    isConnected = true;
                    console.log("Reader connected successfully");
                    
                    // Check if card is present
                    cardPresent = await checkCardPresence();
                    
                    return true;
                } catch (err) {
                    console.error("Failed to request device: ", err);
                    return false;
                }
            }
        } else {
            console.error("WebUSB not supported by this browser");
            return false;
        }
    } catch (error) {
        console.error("Error initializing reader:", error);
        return false;
    }
}

/**
 * Disconnect from the reader
 * @returns {Promise<boolean>} - Resolves to true when reader is disconnected
 */
async function disconnectReader() {
    if (reader && isConnected) {
        try {
            await reader.releaseInterface(0);
            await reader.close();
            isConnected = false;
            reader = null;
            console.log("Reader disconnected");
            return true;
        } catch (error) {
            console.error("Error disconnecting reader:", error);
            return false;
        }
    }
    return true; // Already disconnected
}

/**
 * Check if a card is present in the reader
 * @returns {Promise<boolean>} - Resolves to true if card is present
 */
async function checkCardPresence() {
    if (!isConnected) {
        return false;
    }
    
    try {
        // Command for checking card presence (GetCardIdEx for D-Logic)
        const command = [
            0xFF, // CLA
            0xCA, // INS: GET DATA
            0x00, // P1
            0x00, // P2
            0x00  // Le: Expected length of returned data
        ];
        
        const response = await sendCommand(command);
        cardPresent = (response.status === 0x9000 && response.data.length > 0);
        return cardPresent;
    } catch (error) {
        console.error("Error checking card presence:", error);
        cardPresent = false;
        return false;
    }
}

/**
 * Send a command to the reader and get the response
 * @param {Array} command - Command bytes to send
 * @returns {Promise<Object>} - Response with data and status
 */
async function sendCommand(command) {
    if (!isConnected) {
        throw new Error("Reader not connected");
    }
    
    try {
        // Send the command to the reader
        await reader.transferOut(1, new Uint8Array(command));
        
        // Get the response
        const response = await reader.transferIn(1, 64);
        const data = new Uint8Array(response.data.buffer);
        
        // Extract status (last 2 bytes) and data
        const status = (data[data.length - 2] << 8) | data[data.length - 1];
        const responseData = data.slice(0, data.length - 2);
        
        return {
            status,
            data: responseData
        };
    } catch (error) {
        console.error("Error sending command to reader:", error);
        throw error;
    }
}

/**
 * Get the UID (serial number) of the card
 * @returns {Promise<string>} - Card UID in hex format
 */
async function getCardUid() {
    try {
        if (!cardPresent && !(await checkCardPresence())) {
            throw new Error("No card present");
        }
        
        // ISO 14443 Type A Get UID command (GetCardIdEx for D-Logic)
        const command = [
            0xFF, // CLA
            0xCA, // INS: GET DATA
            0x00, // P1
            0x00, // P2
            0x00  // Le: Expected length of returned data
        ];
        
        const result = await sendCommand(command);
        if (result.status === 0x9000) {
            return Array.from(result.data).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        } else {
            throw new Error(`Failed to get card UID, status: ${result.status.toString(16)}`);
        }
    } catch (error) {
        console.error("Error getting card UID:", error);
        throw error;
    }
}

/**
 * Convert hex string to byte array
 * @param {string} hex - Hex string
 * @returns {Array} - Byte array
 */
function hexToBytes(hex) {
    if (!hex) {
        return [];
    }
    
    // Ensure even number of characters
    hex = hex.length % 2 ? '0' + hex : hex;
    
    // Convert hex pairs to bytes
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    
    return bytes;
}

/**
 * Convert byte array to hex string
 * @param {Array|Uint8Array} bytes - Byte array
 * @returns {string} - Hex string
 */
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Calculate absolute block address from sector and block
 * @param {number} sector - Sector number
 * @param {number} block - Block number within sector
 * @returns {number} - Absolute block address
 */
function calculateBlockAddress(sector, block) {
    // For Mifare Classic 1K:
    // Sectors 0-15, each with 4 blocks (0-3)
    // Sector 0, blocks 0-3 = absolute blocks 0-3
    // Sector 1, blocks 0-3 = absolute blocks 4-7
    // And so on...
    if (sector < 0 || sector > 15) {
        throw new Error("Invalid sector number (must be 0-15)");
    }
    
    if (block < 0 || block > 3) {
        throw new Error("Invalid block number (must be 0-3)");
    }
    
    return (sector * 4) + block;
}

/**
 * Authenticate to a specific sector
 * @param {number} sector - Sector number (0-15 for Mifare Classic 1K)
 * @param {string} key - Authentication key (in hex format)
 * @param {number} keyType - KEY_A (0x60) or KEY_B (0x61)
 * @returns {Promise<boolean>} - True if authentication successful
 */
async function authenticateSector(sector, key = DEFAULT_KEY, keyType = KEY_A) {
    try {
        if (!cardPresent && !(await checkCardPresence())) {
            throw new Error("No card present");
        }
        
        if (sector < 0 || sector > 15) {
            throw new Error("Invalid sector number (must be 0-15)");
        }
        
        if (!isValidHexString(key) || key.length !== 12) {
            throw new Error("Invalid key format (must be 12 hex characters)");
        }
        
        // Convert the key to bytes
        const keyBytes = hexToBytes(key);
        
        // For D-Logic uFR ZERO, we authenticate to the first block of the sector
        const blockAddress = calculateBlockAddress(sector, 0);
        
        // Authentication command - adapted for D-Logic uFR ZERO
        // Use General Authenticate command (ISO/IEC 7816-4)
        const command = [
            0xFF, // CLA
            0x86, // INS: GENERAL AUTHENTICATE
            0x00, // P1
            0x00, // P2
            0x05, // Lc: Length of data
            keyType, // Auth with KEY_A (0x60) or KEY_B (0x61)
            blockAddress, // Block address
            ...keyBytes // Key bytes
        ];
        
        const result = await sendCommand(command);
        return result.status === 0x9000;
    } catch (error) {
        console.error(`Authentication error for sector ${sector}:`, error);
        return false;
    }
}

/**
 * Read a block from a sector
 * @param {number} sector - Sector number (0-15 for Mifare Classic 1K)
 * @param {number} block - Block number within sector (0-3)
 * @param {string} key - Authentication key (in hex format)
 * @param {number} keyType - KEY_A (0x60) or KEY_B (0x61)
 * @returns {Promise<string>} - Block data in hex format
 */
async function readBlockInSector(sector, block, key = DEFAULT_KEY, keyType = KEY_A) {
    try {
        if (!cardPresent && !(await checkCardPresence())) {
            throw new Error("No card present");
        }
        
        // Authenticate to the sector first
        const authSuccess = await authenticateSector(sector, key, keyType);
        if (!authSuccess) {
            throw new Error(`Authentication failed for sector ${sector}`);
        }
        
        // Calculate absolute block address
        const blockAddress = calculateBlockAddress(sector, block);
        
        // Read command - adapted for D-Logic uFR ZERO
        // Use Read Binary command (ISO/IEC 7816-4)
        const command = [
            0xFF, // CLA
            0xB0, // INS: READ BINARY
            0x00, // P1
            blockAddress, // P2: Block address
            0x10  // Le: Expected length (16 bytes for Mifare Classic)
        ];
        
        const result = await sendCommand(command);
        if (result.status === 0x9000) {
            return bytesToHex(result.data);
        } else {
            throw new Error(`Failed to read block, status: ${result.status.toString(16)}`);
        }
    } catch (error) {
        console.error(`Error reading block ${block} in sector ${sector}:`, error);
        throw error;
    }
}

/**
 * Write data to a block in a sector
 * @param {number} sector - Sector number (0-15 for Mifare Classic 1K)
 * @param {number} block - Block number within sector (0-3)
 * @param {string} data - Data to write (hex string, 32 characters)
 * @param {string} key - Authentication key (in hex format)
 * @param {number} keyType - KEY_A (0x60) or KEY_B (0x61)
 * @returns {Promise<boolean>} - True if write successful
 */
async function writeBlockInSector(sector, block, data, key = DEFAULT_KEY, keyType = KEY_A) {
    try {
        if (!cardPresent && !(await checkCardPresence())) {
            throw new Error("No card present");
        }
        
        if (!isValidHexString(data) || data.length !== 32) {
            throw new Error("Invalid data format (must be 32 hex characters)");
        }
        
        // Authenticate to the sector first
        const authSuccess = await authenticateSector(sector, key, keyType);
        if (!authSuccess) {
            throw new Error(`Authentication failed for sector ${sector}`);
        }
        
        // Calculate absolute block address
        const blockAddress = calculateBlockAddress(sector, block);
        
        // Prevent writing to sector trailer (block 3) without special handling
        if (block === 3) {
            console.warn("Warning: Writing to sector trailer (block 3) may lock the card if incorrect values are used");
        }
        
        // Convert data to bytes
        const dataBytes = hexToBytes(data);
        
        // Write command - adapted for D-Logic uFR ZERO
        // Use Update Binary command (ISO/IEC 7816-4)
        const command = [
            0xFF, // CLA
            0xD6, // INS: UPDATE BINARY
            0x00, // P1
            blockAddress, // P2: Block address
            0x10, // Lc: Length of data (16 bytes for Mifare Classic)
            ...dataBytes // Data bytes
        ];
        
        const result = await sendCommand(command);
        return result.status === 0x9000;
    } catch (error) {
        console.error(`Error writing to block ${block} in sector ${sector}:`, error);
        return false;
    }
}

/**
 * Read a value block (special format block for Mifare Value operations)
 * @param {number} sector - Sector number (0-15 for Mifare Classic 1K)
 * @param {number} block - Block number within sector (0-2, not block 3)
 * @param {string} key - Authentication key (in hex format)
 * @param {number} keyType - KEY_A (0x60) or KEY_B (0x61)
 * @returns {Promise<Object>} - Value and address from value block
 */
async function readValueBlock(sector, block, key = DEFAULT_KEY, keyType = KEY_A) {
    try {
        // Cannot use block 3 (sector trailer) as a value block
        if (block === 3) {
            throw new Error("Cannot use sector trailer (block 3) as a value block");
        }
        
        // Read the block as normal
        const blockData = await readBlockInSector(sector, block, key, keyType);
        
        // Value block format:
        // Bytes 0-3: Value (LSB first)
        // Bytes 4-7: Complement of value
        // Bytes 8-11: Value again
        // Bytes 12: Address byte
        // Bytes 13: Complement of address
        // Bytes 14: Address again
        // Bytes 15: Complement of address again
        const bytes = hexToBytes(blockData);
        
        // Extract value (bytes 0-3 in little endian format)
        const value = bytes[0] + (bytes[1] << 8) + (bytes[2] << 16) + (bytes[3] << 24);
        
        // Extract address (byte 12)
        const address = bytes[12];
        
        // Verify value block format
        const valueComplement = bytes[4] + (bytes[5] << 8) + (bytes[6] << 16) + (bytes[7] << 24);
        const valueAgain = bytes[8] + (bytes[9] << 8) + (bytes[10] << 16) + (bytes[11] << 24);
        
        if ((value !== valueAgain) || ((value ^ 0xFFFFFFFF) !== valueComplement)) {
            throw new Error("Invalid value block format");
        }
        
        return { value, address };
    } catch (error) {
        console.error(`Error reading value block in sector ${sector}, block ${block}:`, error);
        throw error;
    }
}

/**
 * Write value to a value block
 * @param {number} sector - Sector number (0-15 for Mifare Classic 1K)
 * @param {number} block - Block number within sector (0-2, not block 3)
 * @param {number} value - Value to write
 * @param {number} address - Address byte (0-255)
 * @param {string} key - Authentication key (in hex format)
 * @param {number} keyType - KEY_A (0x60) or KEY_B (0x61)
 * @returns {Promise<boolean>} - True if write successful
 */
async function writeValueBlock(sector, block, value, address = 0, key = DEFAULT_KEY, keyType = KEY_A) {
    try {
        // Cannot use block 3 (sector trailer) as a value block
        if (block === 3) {
            throw new Error("Cannot use sector trailer (block 3) as a value block");
        }
        
        // Value must be a 32-bit integer
        if (!Number.isInteger(value) || value < -2147483648 || value > 2147483647) {
            throw new Error("Value must be a 32-bit integer");
        }
        
        // Address must be a byte (0-255)
        if (!Number.isInteger(address) || address < 0 || address > 255) {
            throw new Error("Address must be a byte (0-255)");
        }
        
        // Prepare value block data
        const bytes = new Uint8Array(16);
        
        // Value (LSB first)
        bytes[0] = value & 0xFF;
        bytes[1] = (value >> 8) & 0xFF;
        bytes[2] = (value >> 16) & 0xFF;
        bytes[3] = (value >> 24) & 0xFF;
        
        // Complement of value
        const valueComplement = ~value;
        bytes[4] = valueComplement & 0xFF;
        bytes[5] = (valueComplement >> 8) & 0xFF;
        bytes[6] = (valueComplement >> 16) & 0xFF;
        bytes[7] = (valueComplement >> 24) & 0xFF;
        
        // Value again
        bytes[8] = value & 0xFF;
        bytes[9] = (value >> 8) & 0xFF;
        bytes[10] = (value >> 16) & 0xFF;
        bytes[11] = (value >> 24) & 0xFF;
        
        // Address byte and its complements
        bytes[12] = address;
        bytes[13] = ~address & 0xFF;
        bytes[14] = address;
        bytes[15] = ~address & 0xFF;
        
        // Convert to hex string for writeBlockInSector
        const hexData = bytesToHex(bytes);
        
        // Write to block
        return await writeBlockInSector(sector, block, hexData, key, keyType);
    } catch (error) {
        console.error(`Error writing value block in sector ${sector}, block ${block}:`, error);
        return false;
    }
}

/**
 * Increment a value block
 * @param {number} sector - Sector number (0-15 for Mifare Classic 1K)
 * @param {number} block - Block number within sector (0-2, not block 3)
 * @param {number} amount - Amount to increment
 * @param {string} key - Authentication key (in hex format)
 * @param {number} keyType - KEY_A (0x60) or KEY_B (0x61)
 * @returns {Promise<boolean>} - True if operation successful
 */
async function incrementValueBlock(sector, block, amount, key = DEFAULT_KEY, keyType = KEY_A) {
    try {
        // First, read the current value
        const { value, address } = await readValueBlock(sector, block, key, keyType);
        
        // Calculate the new value
        const newValue = value + amount;
        
        // Write the new value back to the value block
        return await writeValueBlock(sector, block, newValue, address, key, keyType);
    } catch (error) {
        console.error(`Error incrementing value block in sector ${sector}, block ${block}:`, error);
        return false;
    }
}

/**
 * Decrement a value block
 * @param {number} sector - Sector number (0-15 for Mifare Classic 1K)
 * @param {number} block - Block number within sector (0-2, not block 3)
 * @param {number} amount - Amount to decrement
 * @param {string} key - Authentication key (in hex format)
 * @param {number} keyType - KEY_A (0x60) or KEY_B (0x61)
 * @returns {Promise<boolean>} - True if operation successful
 */
async function decrementValueBlock(sector, block, amount, key = DEFAULT_KEY, keyType = KEY_A) {
    try {
        // First, read the current value
        const { value, address } = await readValueBlock(sector, block, key, keyType);
        
        // Calculate the new value
        const newValue = value - amount;
        
        // Write the new value back to the value block
        return await writeValueBlock(sector, block, newValue, address, key, keyType);
    } catch (error) {
        console.error(`Error decrementing value block in sector ${sector}, block ${block}:`, error);
        return false;
    }
}

/**
 * Format a Mifare Classic card (set all sectors to default keys)
 * @param {string} currentKey - Current key for all sectors
 * @param {string} newKeyA - New KEY A to set (default: FFFFFFFFFFFF)
 * @param {string} newKeyB - New KEY B to set (default: FFFFFFFFFFFF)
 * @param {number} keyType - Current key type (KEY_A or KEY_B)
 * @returns {Promise<boolean>} - True if format successful
 */
async function formatCard(currentKey = DEFAULT_KEY, newKeyA = DEFAULT_KEY, newKeyB = DEFAULT_KEY, keyType = KEY_A) {
    try {
        // Default access bits for all sectors
        // FF 07 80 - This grants all permissions with KEY A and none with KEY B
        const defaultAccessBits = "FF078069";
        
        let allSuccess = true;
        
        // Format each sector (0-15)
        for (let sector = 0; sector < 16; sector++) {
            try {
                // Skip sector 0, block 0 (contains the card UID and manufacturer data)
                if (sector === 0) {
                    // Just format the sector trailer (block 3)
                    const trailerData = newKeyA + defaultAccessBits + newKeyB;
                    const writeSuccess = await writeBlockInSector(sector, 3, trailerData, currentKey, keyType);
                    if (!writeSuccess) {
                        console.error(`Failed to format sector ${sector} trailer`);
                        allSuccess = false;
                    }
                } else {
                    // Format all blocks in the sector
                    const emptyBlock = "00000000000000000000000000000000"; // 16 bytes of zeros
                    
                    // Write empty data to blocks 0, 1, 2
                    for (let block = 0; block < 3; block++) {
                        const writeSuccess = await writeBlockInSector(sector, block, emptyBlock, currentKey, keyType);
                        if (!writeSuccess) {
                            console.error(`Failed to format sector ${sector}, block ${block}`);
                            allSuccess = false;
                        }
                    }
                    
                    // Write new keys and access bits to sector trailer (block 3)
                    const trailerData = newKeyA + defaultAccessBits + newKeyB;
                    const writeSuccess = await writeBlockInSector(sector, 3, trailerData, currentKey, keyType);
                    if (!writeSuccess) {
                        console.error(`Failed to format sector ${sector} trailer`);
                        allSuccess = false;
                    }
                }
            } catch (error) {
                console.error(`Error formatting sector ${sector}:`, error);
                allSuccess = false;
            }
        }
        
        return allSuccess;
    } catch (error) {
        console.error("Error formatting card:", error);
        return false;
    }
}

/**
 * Convert a string to hex
 * @param {string} str - Input string
 * @returns {string} - Hex representation of the string
 */
function stringToHex(str) {
    let hex = '';
    for (let i = 0; i < str.length; i++) {
        const charCode = str.charCodeAt(i);
        hex += charCode.toString(16).padStart(2, '0');
    }
    return hex;
}

/**
 * Convert hex to string
 * @param {string} hex - Hex string
 * @returns {string} - ASCII string
 */
function hexToString(hex) {
    if (!hex || hex.length % 2 !== 0) {
        return '';
    }
    
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
        const charCode = parseInt(hex.substr(i, 2), 16);
        // Only include printable ASCII characters
        if (charCode >= 32 && charCode <= 126) {
            str += String.fromCharCode(charCode);
        } else {
            str += '.'; // Replace non-printable chars with dot
        }
    }
    return str;
}

/**
 * Validate if a string is a valid hex string
 * @param {string} hex - Hex string to validate
 * @returns {boolean} - True if valid hex string
 */
function isValidHexString(hex) {
    if (!hex || typeof hex !== 'string') {
        return false;
    }
    return /^[0-9A-Fa-f]*$/.test(hex);
}

// Export functions to be available globally
window.initializeReader = initializeReader;
window.disconnectReader = disconnectReader;
window.checkCardPresence = checkCardPresence;
window.getCardUid = getCardUid;
window.authenticateSector = authenticateSector;
window.readBlockInSector = readBlockInSector;
window.writeBlockInSector = writeBlockInSector;
window.readValueBlock = readValueBlock;
window.writeValueBlock = writeValueBlock;
window.incrementValueBlock = incrementValueBlock;
window.decrementValueBlock = decrementValueBlock;
window.formatCard = formatCard;
window.stringToHex = stringToHex;
window.hexToString = hexToString;
window.isValidHexString = isValidHexString;

// Also export constants
window.DEFAULT_KEY = DEFAULT_KEY;
window.KEY_A = KEY_A;
window.KEY_B = KEY_B; 