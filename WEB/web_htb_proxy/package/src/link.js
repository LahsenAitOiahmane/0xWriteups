const { exec} = require('child_process');
const { isValidMTU, isValidMACAddress } = require('./utils');

/**
 * Retrieves detailed information about all network interfaces (links).
 *
 * @returns {Promise<Object[]>} A promise that resolves to an array of objects representing each network interface and its details.
 * @throws {Error} Throws an error if there is a problem retrieving the network links or parsing the output.
 */
function show() {
    return new Promise((resolve, reject) => {
        exec(`ip -j link show`, (error, stdout, stderr) => {
            if (stderr) {
                reject(new Error('Error retrieving network links: ' + stderr));
                return;
            }
            try {
                const result = JSON.parse(stdout);
                resolve(result);
            } catch (parseError) {
                reject(new Error('Error parsing network links: ' + parseError.message));
            }
        });
    });
}

/**
 * Sets the state of a specified network interface.
 *
 * @param {string} interfaceName - The name of the network interface.
 * @param {("up"|"down")} state - The desired state, which can be 'up' or 'down'.
 * @returns {Promise<void>} A promise that resolves if the state is successfully set, or rejects with an error.
 * @throws {Error} Throws an error if the state is invalid, the interface cannot be found, or any other error occurs during the execution of the command.
 */
function setState(interfaceName, state) {
    return new Promise((resolve, reject) => {
        if(state !== 'up' && state !== 'down') {
            reject(new Error('Invalid state: ' + state));
            return;
        }

        exec(`ip link set ${interfaceName} ${state}`, (error, stdout, stderr) => {
            if (stderr) {
                if(stderr.includes('Cannot find device')) {
                    reject(new Error('Cannot find device ' + interfaceName));
                } else {
                    reject(new Error('Error setting link state: ' + stderr));
                }
            }

            resolve();
        });
    });
}

/**
 * Sets the Maximum Transmission Unit (MTU) for a specified network interface.
 *
 * @param {string} interfaceName - The name of the network interface.
 * @param {number} mtuValue - The desired MTU value in bytes.
 * @returns {Promise<void>} A promise that resolves if the MTU is successfully set, or rejects with an error.
 * @throws {Error} Throws an error if the MTU value is invalid, the interface cannot be found, or any other error occurs during the execution of the command.
 */
function setMTU(interfaceName, mtuValue) {
    return new Promise((resolve, reject) => {
        if (!isValidMTU(mtuValue)) {
            reject(new Error('Invalid MTU value: ' + mtuValue));
            return;
        }

        exec(`ip link set ${interfaceName} mtu ${mtuValue}`, (error, stdout, stderr) => {
            if (stderr) {
                if (stderr.includes('Cannot find device')) {
                    reject(new Error('Cannot find device ' + interfaceName));
                } else {
                    reject(new Error('Error setting MTU: ' + stderr));
                }
            }

            resolve();
        });
    });
}

/**
 * Renames a specified network interface.
 *
 * @param {string} oldInterfaceName - The current name of the network interface.
 * @param {string} newInterfaceName - The new name to assign to the network interface.
 * @returns {Promise<void>} A promise that resolves if the interface is successfully renamed, or rejects with an error.
 * @throws {Error} Throws an error if the interface names are invalid, or any other error occurs during the execution of the command.
 */
function rename(oldInterfaceName, newInterfaceName) {
    return new Promise((resolve, reject) => {
        exec(`ip link set dev ${oldInterfaceName} name ${newInterfaceName}`, (error, stdout, stderr) => {
            if (stderr) {
                if (stderr.includes('Cannot find device')) {
                    reject(new Error('Cannot find device ' + oldInterfaceName));
                } else {
                    reject(new Error('Error renaming interface: ' + stderr));
                }
            }

            resolve();
        });
    });
}

/**
 * Sets the MAC address for a specified network interface.
 *
 * @param {string} interfaceName - The name of the network interface.
 * @param {string} newMacAddress - The new MAC address to assign to the network interface.
 * @returns {Promise<void>} A promise that resolves if the MAC address is successfully set, or rejects with an error.
 * @throws {Error} Throws an error if the MAC address is invalid, the interface cannot be found, or any other error occurs during the execution of the command.
 */
function setMac(interfaceName, newMacAddress) {
    return new Promise((resolve, reject) => {
        if(!isValidMACAddress(newMacAddress)) {
            reject(new Error('Invalid Mac Address ' + newMacAddress))
        }


        exec(`ip link set dev ${interfaceName} address ${newMacAddress}`, (error, stdout, stderr) => {
            if (stderr) {
                if (stderr.includes('Cannot find device')) {
                    reject(new Error('Cannot find device ' + interfaceName));
                } else {
                    reject(new Error('Error setting MAC address: ' + stderr));
                }
            }

            resolve();
        });
    });
}

module.exports = {
    show,
    setState,
    setMTU,
    rename,
    setMac
}