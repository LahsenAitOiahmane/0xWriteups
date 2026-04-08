const { exec} = require('child_process');
const { isValidIP, isValidMACAddress } = require('./utils');

/**
 * Retrieves the network neighbors for a specific network interface or all interfaces if none is specified.
 * This function returns a promise that resolves with the parsed JSON output of the command.
 * If there's an error in executing the command or parsing the output, the promise is rejected with an appropriate error message.
 * @param {string} [interfaceName] - Optional name of the network interface to retrieve neighbor information for.
 * @returns {Promise<Object[]>} A promise that resolves to an array of objects, each representing a neighbor entry with details like IP address, MAC address, and state.
 * @throws {Error} Throws an error if there's an issue executing the command or parsing its output.
 */
function show(interfaceName = '') {
    return new Promise((resolve, reject) => {
        const command = interfaceName ? `ip -j neigh show dev ${interfaceName.trim()}` : `ip -j neigh show`;
        exec(command, (error, stdout, stderr) => {
            if (stderr) {
                reject(new Error('Error retrieving network neighbors: ' + stderr));
                return;
            }
            try {
                const result = JSON.parse(stdout);
                resolve(result);
            } catch (parseError) {
                reject(new Error('Error parsing network neighbors: ' + parseError.message));
            }
        });
    });
}

/**
 * Adds a static neighbor entry.
 * This function returns a promise that resolves when the entry is successfully added.
 * @param {string} ipAddress - The IP address of the neighbor.
 * @param {string} macAddress - The MAC address of the neighbor.
 * @param {string} interfaceName - The name of the network interface.
 * @param {"permanent"|"noarp"|"reachable"|"stale"|"probe"|"delay"|"failed"} [type="permanent"] - The type of the neighbor entry.
 * @returns {Promise<void>} A promise that resolves when the neighbor is added.
 * @throws {Error} Throws an error if the command fails to execute, if parameters are missing, or if an invalid type is provided.
 */
function add(ipAddress, macAddress, interfaceName, type = "permanent") {
    const validTypes = ["permanent", "noarp", "reachable", "stale", "probe", "delay", "failed"];
    return new Promise((resolve, reject) => {
        if (!ipAddress || !macAddress || !interfaceName || !validTypes.includes(type)) {
            reject(new Error("Invalid parameters: Ensure all required parameters are provided and 'type' is one of the valid options."));
            return;
        }

        if(!isValidIP(ipAddress)) {
            reject(new Error('Invalid IP address: ' + ipAddress));
            return;
        }

        if(!isValidMACAddress(macAddress)) {
            reject(new Error('Invalid MAC address: ' + macAddress));
            return;
        }

        const command = `ip neigh add ${ipAddress} lladdr ${macAddress} dev ${interfaceName} nud ${type}`;
        exec(command, (error, stdout, stderr) => {
            if (error || stderr) {
                reject(new Error('Error adding network neighbor: ' + (stderr || error.message)));
                return;
            }
            resolve();
        });
    });
}

/**
 * Removes a static neighbor entry.
 * This function returns a promise that resolves when the entry is successfully removed.
 * @param {string} ipAddress - The IP address of the neighbor to be removed.
 * @param {string} interfaceName - The name of the network interface.
 * @returns {Promise<void>} A promise that resolves when the neighbor is removed.
 * @throws {Error} Throws an error if the command fails to execute, if parameters are missing, or if an invalid IP address is provided.
 */
function remove(ipAddress, interfaceName) {
    return new Promise((resolve, reject) => {
        if (!ipAddress || !interfaceName) {
            reject(new Error("Invalid parameters: IP address and interface name are required."));
            return;
        }

        if(!isValidIP(ipAddress)) {
            reject(new Error('Invalid IP address: ' + ipAddress));
            return;
        }

        const command = `ip neigh del ${ipAddress} dev ${interfaceName}`;
        exec(command, (error, stdout, stderr) => {
            if (error || stderr) {
                reject(new Error('Error removing network neighbor: ' + (stderr || error.message)));
                return;
            }
            resolve();
        });
    });
}

/**
 * Updates or replaces a neighbor entry.
 * If the entry does not exist, it will be created.
 * This function returns a promise that resolves when the entry is successfully updated or replaced.
 * @param {string} ipAddress - The IP address of the neighbor.
 * @param {string} macAddress - The MAC address of the neighbor.
 * @param {string} interfaceName - The name of the network interface.
 * @param {"permanent"|"noarp"|"reachable"|"stale"|"probe"|"delay"|"failed"} [type="permanent"] - The type of the neighbor entry.
 * @returns {Promise<void>} A promise that resolves when the neighbor is updated or replaced.
 * @throws {Error} Throws an error if the command fails to execute, if parameters are missing, or if an invalid type is provided.
 */
function update(ipAddress, macAddress, interfaceName, type = "permanent") {
    const validTypes = ["permanent", "noarp", "reachable", "stale", "probe", "delay", "failed"];
    return new Promise((resolve, reject) => {
        if (!ipAddress || !macAddress || !interfaceName || !validTypes.includes(type)) {
            reject(new Error("Invalid parameters: Ensure all required parameters are provided and 'type' is one of the valid options."));
            return;
        }

        if(!isValidIP(ipAddress)) {
            reject(new Error('Invalid IP address: ' + ipAddress));
            return;
        }

        if(!isValidMACAddress(macAddress)) {
            reject(new Error('Invalid MAC address: ' + macAddress));
            return;
        }

        const command = `ip neigh replace ${ipAddress} lladdr ${macAddress} dev ${interfaceName} nud ${type}`;
        exec(command, (error, stdout, stderr) => {
            if (error || stderr) {
                reject(new Error('Error updating network neighbor: ' + (stderr || error.message)));
                return;
            }
            resolve();
        });
    });
}

/**
 * Flushes neighbor entries from the neighbor table.
 * If an interface name is provided, it flushes entries for that specific interface.
 * If no interface is specified, it flushes all neighbor entries.
 * This function returns a promise that resolves when the entries are successfully flushed.
 * @param {string} [interfaceName] - Optional name of the network interface to flush neighbor entries for.
 * @returns {Promise<void>} A promise that resolves when the neighbor entries are flushed.
 * @throws {Error} Throws an error if the command fails to execute.
 */
function flush(interfaceName = '') {
    return new Promise((resolve, reject) => {
        const command = interfaceName ? `ip neigh flush dev ${interfaceName}` : `ip neigh flush all`;
        exec(command, (error, stdout, stderr) => {
            if (error || stderr) {
                reject(new Error('Error flushing network neighbors: ' + (stderr || error.message)));
                return;
            }
            resolve();
        });
    });
}

module.exports = {
    show,
    add,
    remove,
    update,
    flush
}