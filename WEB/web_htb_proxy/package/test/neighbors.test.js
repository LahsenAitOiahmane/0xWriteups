const { show, add, remove, update, flush } = require('../src/neighbors');
const { exec } = require('child_process');
const { beforeAll, describe, expect, test, afterAll } = require("@jest/globals");

const dummyInterfaceName = 'eth_dummy_neigh';
const validIpAddress = '192.168.100.100';
const validMacAddress = '00:11:22:33:44:55';
const invalidIpAddress = '192.168.300.300';
const invalidMacAddress = '00:11:22:33:44:ZZ';

beforeAll(async () => {
    await execPromise(`ip link add ${dummyInterfaceName} type dummy`);
    await execPromise(`ip link set ${dummyInterfaceName} up`);
});

describe('Show', () => {
    test('Should return an Array', async () => {
        const result = await show();
        expect(result).toBeInstanceOf(Array);
    });

    test('Should return an Array for a specific interface', async () => {
        const result = await show(dummyInterfaceName);
        expect(result).toBeInstanceOf(Array);
    });

    test('Should reject with an error for a non-existent interface', async () => {
        const nonExistentInterface = 'nonexistent';
        await expect(show(nonExistentInterface)).rejects.toThrowError(/Error retrieving network neighbors/);
    });
});

describe('Add', () => {
    test('Should resolve if neighbor is successfully added', async () => {
        await expect(add(validIpAddress, validMacAddress, dummyInterfaceName)).resolves.toBeUndefined();
    });

    test('Should reject with an error for an invalid IP address', async () => {
        await expect(add(invalidIpAddress, validMacAddress, dummyInterfaceName)).rejects.toThrowError('Invalid IP address');
    });

    test('Should reject with an error for an invalid MAC address', async () => {
        await expect(add(validIpAddress, invalidMacAddress, dummyInterfaceName)).rejects.toThrowError('Invalid MAC address');
    });

    test('Should reject with an error for a non-existent interface', async () => {
        await expect(add(validIpAddress, validMacAddress, 'nonexistent')).rejects.toThrowError(/Error adding network neighbor/);
    });
});

describe('Remove', () => {
    test('Should resolve if neighbor is successfully removed', async () => {
        await expect(remove(validIpAddress, dummyInterfaceName)).resolves.toBeUndefined();
    });

    test('Should reject with an error for an invalid IP address', async () => {
        await expect(remove(invalidIpAddress, dummyInterfaceName)).rejects.toThrowError('Invalid IP address');
    });

    test('Should reject with an error for a non-existent interface', async () => {
        await expect(remove(validIpAddress, 'nonexistent')).rejects.toThrowError(/Error removing network neighbor/);
    });
});

describe('Update', () => {
    test('Should resolve if neighbor is successfully updated', async () => {
        await expect(update(validIpAddress, validMacAddress, dummyInterfaceName)).resolves.toBeUndefined();
    });

    test('Should reject with an error for an invalid IP address', async () => {
        await expect(update(invalidIpAddress, validMacAddress, dummyInterfaceName)).rejects.toThrowError('Invalid IP address');
    });

    test('Should reject with an error for an invalid MAC address', async () => {
        await expect(update(validIpAddress, invalidMacAddress, dummyInterfaceName)).rejects.toThrowError('Invalid MAC address');
    });

    test('Should reject with an error for a non-existent interface', async () => {
        await expect(update(validIpAddress, validMacAddress, 'nonexistent')).rejects.toThrowError(/Error updating network neighbor/);
    });
});

describe('Flush', () => {
    test('Should resolve if neighbors are successfully flushed', async () => {
        await expect(flush(dummyInterfaceName)).resolves.toBeUndefined();
    });

    test('Should reject with an error for a non-existent interface', async () => {
        await expect(flush('nonexistent')).rejects.toThrowError(/Error flushing network neighbors/);
    });
});

afterAll(async () => {
    // Cleanup the dummy interface
    await execPromise(`ip link del ${dummyInterfaceName}`);
});

// Helper function to promisify exec for use in beforeAll and afterAll
function execPromise(command) {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                reject(error);
            } else if (stderr) {
                reject(stderr);
            } else {
                resolve(stdout);
            }
        });
    });
}
