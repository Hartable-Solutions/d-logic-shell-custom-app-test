/**
 * Mifare Card Operations
 * 
 * This file implements Mifare Classic card operations using the PK variant
 * for direct key authentication. All functions use promises for better 
 * integration with modern JavaScript applications.
 */

// Default keys for Mifare Classic cards
const DEFAULT_KEY = "FFFFFFFFFFFF";  // Type A key (FF FF FF FF FF FF)

// Authentication key types
const KEY_A = 0x60;
const KEY_B = 0x61;

// Status codes
const UFR_OK = 0x00;

/**
 * Authenticates to a card sector using direct key authentication (PK variant)
 * 
 * @param {number} sector - Sector number (0-15 for Mifare Classic 1K)
 * @param {string} key - Hex key (12 characters, no 0x prefix)
 * @param {number} keyType - Key type (KEY_A or KEY_B)
 * @returns {Promise} - Resolves with status on success, rejects on failure
 */
function authenticateSector(sector, key = DEFAULT_KEY, keyType = KEY_A) {
    return new Promise((resolve, reject) => {
        const authCommand = keyType === KEY_A ? 'LinearRead_PK' : 'LinearRead_PK_M';
        
        ufRequest(authCommand, {
            sector: sector,
            block: 0,      // Use block 0 for authentication
            count: 1,      // Only read 1 block to verify auth
            auth_mode: keyType,
            key: key
        }, (status, response) => {
            if (status === UFR_OK) {
                resolve({ status, message: `Successfully authenticated to sector ${sector}` });
            } else {
                reject({ status, message: `Authentication failed for sector ${sector}: ${status}` });
            }
        });
    });
}

/**
 * Reads a block in a sector using direct key authentication
 * 
 * @param {number} sector - Sector number (0-15 for Mifare Classic 1K)
 * @param {number} block - Block number within sector (0-3)
 * @param {string} key - Hex key (12 characters, no 0x prefix)
 * @param {number} keyType - Key type (KEY_A or KEY_B)
 * @returns {Promise} - Resolves with block data on success, rejects on failure
 */
function readBlockInSector(sector, block, key = DEFAULT_KEY, keyType = KEY_A) {
    return new Promise((resolve, reject) => {
        // For Mifare Classic 1K, each sector has 4 blocks (0-3)
        // Sector trailer is always the last block (3)
        
        ufRequest('BlockRead_PK', {
            block_address: sector * 4 + block,
            auth_mode: keyType,
            key: key
        }, (status, response) => {
            if (status === UFR_OK) {
                resolve({
                    status,
                    message: `Successfully read sector ${sector}, block ${block}`,
                    data: response.data
                });
            } else {
                reject({
                    status,
                    message: `Failed to read sector ${sector}, block ${block}: ${status}`
                });
            }
        });
    });
}

/**
 * Writes data to a block in a sector using direct key authentication
 * WARNING: Be careful when writing to sector trailers (block 3)!
 * 
 * @param {number} sector - Sector number (0-15 for Mifare Classic 1K)
 * @param {number} block - Block number within sector (0-3)
 * @param {string} data - Hex data to write (32 characters, no 0x prefix)
 * @param {string} key - Hex key (12 characters, no 0x prefix)
 * @param {number} keyType - Key type (KEY_A or KEY_B)
 * @returns {Promise} - Resolves with status on success, rejects on failure
 */
function writeBlockInSector(sector, block, data, key = DEFAULT_KEY, keyType = KEY_A) {
    // Warning for sector trailer writes
    if (block === 3) {
        console.warn("Writing to sector trailer! This can lock your card if not done correctly.");
    }
    
    return new Promise((resolve, reject) => {
        ufRequest('BlockWrite_PK', {
            block_address: sector * 4 + block,
            auth_mode: keyType,
            key: key,
            data: data
        }, (status, response) => {
            if (status === UFR_OK) {
                resolve({
                    status,
                    message: `Successfully wrote to sector ${sector}, block ${block}`
                });
            } else {
                reject({
                    status,
                    message: `Failed to write to sector ${sector}, block ${block}: ${status}`
                });
            }
        });
    });
}

/**
 * Reads a value block in a sector
 * 
 * @param {number} sector - Sector number (0-15 for Mifare Classic 1K)
 * @param {number} block - Block number within sector (0-2)
 * @param {string} key - Hex key (12 characters, no 0x prefix)
 * @param {number} keyType - Key type (KEY_A or KEY_B)
 * @returns {Promise} - Resolves with value and address on success, rejects on failure
 */
function readValueBlock(sector, block, key = DEFAULT_KEY, keyType = KEY_A) {
    // Value blocks cannot be in sector trailer (block 3)
    if (block === 3) {
        return Promise.reject({
            status: -1,
            message: "Block 3 is a sector trailer and cannot be a value block"
        });
    }
    
    return new Promise((resolve, reject) => {
        ufRequest('ValueBlockRead_PK', {
            block_address: sector * 4 + block,
            auth_mode: keyType,
            key: key
        }, (status, response) => {
            if (status === UFR_OK) {
                resolve({
                    status,
                    message: `Successfully read value from sector ${sector}, block ${block}`,
                    value: response.value,
                    address: response.address
                });
            } else {
                reject({
                    status,
                    message: `Failed to read value from sector ${sector}, block ${block}: ${status}`
                });
            }
        });
    });
}

/**
 * Writes a value block in a sector
 * 
 * @param {number} sector - Sector number (0-15 for Mifare Classic 1K)
 * @param {number} block - Block number within sector (0-2)
 * @param {number} value - Value to write (signed 32-bit integer)
 * @param {number} address - Address byte (0-255)
 * @param {string} key - Hex key (12 characters, no 0x prefix)
 * @param {number} keyType - Key type (KEY_A or KEY_B)
 * @returns {Promise} - Resolves with status on success, rejects on failure
 */
function writeValueBlock(sector, block, value, address = 0, key = DEFAULT_KEY, keyType = KEY_A) {
    // Value blocks cannot be in sector trailer (block 3)
    if (block === 3) {
        return Promise.reject({
            status: -1,
            message: "Block 3 is a sector trailer and cannot be a value block"
        });
    }
    
    return new Promise((resolve, reject) => {
        ufRequest('ValueBlockWrite_PK', {
            block_address: sector * 4 + block,
            auth_mode: keyType,
            key: key,
            value: value,
            address: address
        }, (status, response) => {
            if (status === UFR_OK) {
                resolve({
                    status,
                    message: `Successfully wrote value to sector ${sector}, block ${block}`
                });
            } else {
                reject({
                    status,
                    message: `Failed to write value to sector ${sector}, block ${block}: ${status}`
                });
            }
        });
    });
}

/**
 * Increments a value block by a specified amount
 * 
 * @param {number} sector - Sector number (0-15 for Mifare Classic 1K)
 * @param {number} block - Block number within sector (0-2)
 * @param {number} amount - Amount to increment
 * @param {string} key - Hex key (12 characters, no 0x prefix)
 * @param {number} keyType - Key type (KEY_A or KEY_B)
 * @returns {Promise} - Resolves with new value on success, rejects on failure
 */
function incrementValueBlock(sector, block, amount, key = DEFAULT_KEY, keyType = KEY_A) {
    // Value blocks cannot be in sector trailer (block 3)
    if (block === 3) {
        return Promise.reject({
            status: -1,
            message: "Block 3 is a sector trailer and cannot be a value block"
        });
    }
    
    return new Promise((resolve, reject) => {
        ufRequest('ValueBlockIncrement_PK', {
            block_address: sector * 4 + block,
            auth_mode: keyType,
            key: key,
            increment: amount
        }, (status, response) => {
            if (status === UFR_OK) {
                // Read the new value after increment
                readValueBlock(sector, block, key, keyType)
                    .then(result => resolve({
                        status,
                        message: `Successfully incremented value in sector ${sector}, block ${block}`,
                        newValue: result.value
                    }))
                    .catch(error => reject(error));
            } else {
                reject({
                    status,
                    message: `Failed to increment value in sector ${sector}, block ${block}: ${status}`
                });
            }
        });
    });
}

/**
 * Decrements a value block by a specified amount
 * 
 * @param {number} sector - Sector number (0-15 for Mifare Classic 1K)
 * @param {number} block - Block number within sector (0-2)
 * @param {number} amount - Amount to decrement
 * @param {string} key - Hex key (12 characters, no 0x prefix)
 * @param {number} keyType - Key type (KEY_A or KEY_B)
 * @returns {Promise} - Resolves with new value on success, rejects on failure
 */
function decrementValueBlock(sector, block, amount, key = DEFAULT_KEY, keyType = KEY_A) {
    // Value blocks cannot be in sector trailer (block 3)
    if (block === 3) {
        return Promise.reject({
            status: -1,
            message: "Block 3 is a sector trailer and cannot be a value block"
        });
    }
    
    return new Promise((resolve, reject) => {
        ufRequest('ValueBlockDecrement_PK', {
            block_address: sector * 4 + block,
            auth_mode: keyType,
            key: key,
            decrement: amount
        }, (status, response) => {
            if (status === UFR_OK) {
                // Read the new value after decrement
                readValueBlock(sector, block, key, keyType)
                    .then(result => resolve({
                        status,
                        message: `Successfully decremented value in sector ${sector}, block ${block}`,
                        newValue: result.value
                    }))
                    .catch(error => reject(error));
            } else {
                reject({
                    status,
                    message: `Failed to decrement value in sector ${sector}, block ${block}: ${status}`
                });
            }
        });
    });
}

/**
 * Formats a Mifare Classic card with new keys and default access bits
 * 
 * @param {string} currentKey - Current key to authenticate with (12 characters, no 0x prefix)
 * @param {string} newKeyA - New Key A to write (12 characters, no 0x prefix)
 * @param {string} newKeyB - New Key B to write (12 characters, no 0x prefix)
 * @param {number} keyType - Current key type (KEY_A or KEY_B)
 * @returns {Promise} - Resolves with status on success, rejects on failure
 */
function formatCard(currentKey = DEFAULT_KEY, newKeyA = DEFAULT_KEY, newKeyB = DEFAULT_KEY, keyType = KEY_A) {
    return new Promise((resolve, reject) => {
        ufRequest('LinearFormatCard_PK', {
            auth_mode: keyType,
            key: currentKey,
            new_key_A: newKeyA,
            new_key_B: newKeyB,
            new_access_bits: "FF078069", // Standard access bits
            sector_trailers_byte9: "69"   // Standard byte 9
        }, (status, response) => {
            if (status === UFR_OK) {
                resolve({
                    status,
                    message: "Card successfully formatted with new keys"
                });
            } else {
                reject({
                    status,
                    message: `Card formatting failed: ${status}`
                });
            }
        });
    });
}

/**
 * Utility function to convert a string to hex format
 * 
 * @param {string} str - String to convert
 * @returns {string} - Hex representation of the string
 */
function stringToHex(str) {
    let hex = '';
    for (let i = 0; i < str.length; i++) {
        const charCode = str.charCodeAt(i);
        hex += charCode.toString(16).padStart(2, '0');
    }
    return hex.toUpperCase();
}

/**
 * Utility function to convert hex to a readable string
 * 
 * @param {string} hex - Hex string to convert
 * @returns {string} - Decoded string
 */
function hexToString(hex) {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
        const charCode = parseInt(hex.substr(i, 2), 16);
        // Only include printable ASCII characters
        if (charCode >= 32 && charCode <= 126) {
            str += String.fromCharCode(charCode);
        } else {
            str += '.';
        }
    }
    return str;
}

/**
 * Validates if a hex string contains only valid hex characters
 * 
 * @param {string} hex - String to check
 * @returns {boolean} - True if valid hex, false otherwise
 */
function isValidHexString(hex) {
    return /^[0-9A-Fa-f]+$/.test(hex);
} 