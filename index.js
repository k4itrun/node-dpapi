const dpapi = require('bindings')('node-dpapi');

/**
 * Protects data using DPAPI.
 * @param {Uint8Array} userData - The data to be protected.
 * @param {Uint8Array | null} optionalEntropy - Optional entropy for additional protection.
 * @param {"CurrentUser" | "LocalMachine"} scope - The scope of protection.
 * @returns {Uint8Array} - The protected data.
 */
function protectData(userData, optionalEntropy, scope) {
    return dpapi.protectData(userData, optionalEntropy, scope);
}

/**
 * Unprotects data using DPAPI.
 * @param {Uint8Array} encryptedData - The data to be unprotected.
 * @param {Uint8Array | null} optionalEntropy - Optional entropy for additional protection.
 * @param {"CurrentUser" | "LocalMachine"} scope - The scope of protection.
 * @returns {Uint8Array} - The unprotected data.
 */
function unprotectData(encryptedData, optionalEntropy, scope) {
    return dpapi.unprotectData(encryptedData, optionalEntropy, scope);
}

module.exports = {
    protectData,
    unprotectData
};
