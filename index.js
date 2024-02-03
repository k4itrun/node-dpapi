const dpapi = require('bindings')('node-dpapi');

/**
 * Unprotects data using DPAPI.
 * @param {Uint8Array} encryptedData - The data to be unprotected.
 * @param {Uint8Array | null} optionalEntropy - Optional entropy for additional protection.
 * @param {"CurrentUser" | "LocalMachine"} scope - The scope of protection.
 * @returns {Uint8Array} - The unprotected data.
 */

module.exports.unprotectData = (encryptedData, optionalEntropy, scope) => {
    return dpapi.unprotectData(encryptedData, optionalEntropy, scope);
}