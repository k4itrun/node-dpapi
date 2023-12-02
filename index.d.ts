declare module "node-dpapi" {
    /**
     * Protects data using DPAPI.
     * @param userData - The data to be protected.
     * @param optionalEntropy - Optional entropy for additional protection.
     * @param scope - The scope of protection, either "CurrentUser" or "LocalMachine".
     * @returns The protected data.
     */
    function protectData(
        userData: Uint8Array,
        optionalEntropy: Uint8Array | null,
        scope: "CurrentUser" | "LocalMachine"
    ): Uint8Array;

    /**
     * Unprotects data using DPAPI.
     * @param encryptedData - The data to be unprotected.
     * @param optionalEntropy - Optional entropy for additional protection.
     * @param scope - The scope of protection, either "CurrentUser" or "LocalMachine".
     * @returns The unprotected data.
     */
    function unprotectData(
        encryptedData: Uint8Array,
        optionalEntropy: Uint8Array | null,
        scope: "CurrentUser" | "LocalMachine"
    ): Uint8Array;

    export { protectData, unprotectData };
}
