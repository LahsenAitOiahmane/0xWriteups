const { exec} = require('child_process');
const { isValidCIDR } = require('./utils');

/**
 * Retrieves the network interfaces and their IP addresses.
 * If an interface name is provided, it retrieves information for that specific interface.
 * If the interface does not exist, an error is thrown.
 * @param {string} [interfaceName] - Optional name of the interface to retrieve information for.
 * @returns {Promise<Object[]>} A promise that resolves to an array of objects representing network interfaces and their IP addresses.
 * @throws {Error} Throws an error for various failure scenarios, including non-existent interfaces.
 */
function show(interfaceName = '') {
    return new Promise((resolve, reject) => {
        const command = interfaceName ? `ip -j address show ${interfaceName.trim()}` : 'ip -j address';
        exec(command, (error, stdout, stderr) => {
            if (stderr) {
                if(stderr.includes('Cannot find device')) {
                    reject(new Error('Cannot find device ' + interfaceName));
                } else {
                    reject(new Error('Error retrieving network interfaces: ' + stderr));
                }
                return;
            }

            try {
                const result = JSON.parse(stdout);
                resolve(result);
            } catch (parseError) {
                reject(new Error('Error parsing network interfaces: ' + parseError.message));
            }
        });
    });
}

/**
 * Adds an IP address with CIDR notation to a specified network interface.
 *
 * @param {string} interfaceName - The name of the network interface to which the IP address will be added.
 * @param {string} ipCidr - The IP address in CIDR notation to add to the network interface.
 * @returns {Promise<void>} A promise that resolves if the IP address is successfully added, or rejects with an error.
 * @throws {Error} Throws an error if the IP CIDR is invalid, the interface cannot be found, or any other error occurs during the execution of the command.
 */
function add(interfaceName, ipCidr) {
    return new Promise((resolve, reject) => {
        if (!isValidCIDR(ipCidr)) {
            reject(new Error('Invalid IP CIDR: ' + ipCidr));
            return;
        }

        exec(`ip address add ${ipCidr} dev ${interfaceName}`, (error, stdout, stderr) => {
            if (stderr) {
                if(stderr.includes('Cannot find device')) {
                    reject(new Error('Cannot find device ' + interfaceName));
                } else if(stderr.includes('File exists')) {
                    reject(new Error('IP Address already exists on interface'));
                } else {
                    reject(new Error('Error adding IP address: ' + stderr));
                }
                return;
            }

            resolve();
        });
    });
}

/**
 * Removes an IP address with CIDR notation from a specified network interface.
 *
 * @param {string} interfaceName - The name of the network interface from which the IP address will be removed.
 * @param {string} ipCidr - The IP address in CIDR notation to remove from the network interface.
 * @returns {Promise<void>} A promise that resolves if the IP address is successfully removed, or rejects with an error.
 * @throws {Error} Throws an error if the IP CIDR is invalid, the interface cannot be found, or any other error occurs during the execution of the command.
 */
function remove(interfaceName, ipCidr) {
    return new Promise((resolve, reject) => {
        if (!isValidCIDR(ipCidr)) {
            reject(new Error('Invalid IP CIDR: ' + ipCidr));
            return;
        }

        exec(`ip address del ${ipCidr} dev ${interfaceName}`, (error, stdout, stderr) => {
            if (stderr) {
                if(stderr.includes('Cannot find device')) {
                    reject(new Error('Cannot find device ' + interfaceName));
                } else if(stderr.includes('Cannot assign requested address')) {
                    reject(new Error('IP Address does not exist on interface'));
                } else {
                    reject(new Error('Error removing IP address: ' + stderr));
                }
                return;
            }

            resolve();
        });
    });
}

/**
 * Removes all IP addresses from a specified network interface.
 *
 * @param {string} interfaceName - The name of the network interface from which all IP addresses will be removed.
 * @returns {Promise<void>} A promise that resolves if all IP addresses are successfully removed, or rejects with an error.
 * @throws {Error} Throws an error if the interface cannot be found, or any other error occurs during the execution of the command.
 */
function flush(interfaceName) {
    return new Promise((resolve, reject) => {
        exec(`ip address flush dev ${interfaceName}`, (error, stdout, stderr) => {
            if (stderr) {
                if(stderr.includes('Cannot find device')) {
                    reject(new Error('Cannot find device ' + interfaceName));
                } else {
                    reject(new Error('Error flushing IP addresses: ' + stderr));
                }
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
    flush
}