const { show, setState, setMTU, rename, setMac } = require('../src/link');
const { exec} = require("child_process");
const { beforeAll, describe, expect, test, afterAll } = require("@jest/globals");

const dummyInterfaceName = 'eth_dummy_link';
const dummyIpCidr = '172.16.16.0/24';

beforeAll(async () => {
    await exec(`ip link add ${dummyInterfaceName} type dummy`);
    await exec(`ip address add ${dummyIpCidr} dev eth_dummy_link`);
    await exec(`ip link set ${dummyInterfaceName} mtu 1500`);
    await exec(`ip link set ${dummyInterfaceName} up`);
});

describe('Show', () => {
    test('Should return an Array', async () => {
        const result = await show();
        expect(result).toBeInstanceOf(Array);
    });
});

describe('Set State', () => {
    test('Should set the state of a network interface to "up"', async () => {
        const interfaceName = 'eth_dummy_link';
        const state = 'up';
        await expect(setState(interfaceName, state)).resolves.toBeUndefined();
    });

    test('Should set the state of a network interface to "down"', async () => {
        const interfaceName = 'eth_dummy_link';
        const state = 'down';
        await expect(setState(interfaceName, state)).resolves.toBeUndefined();
    });

    test('Should reject with an error for an invalid state', async () => {
        const interfaceName = 'eth_dummy_link';
        const invalidState = 'invalid_state';
        await expect(setState(interfaceName, invalidState)).rejects.toThrowError(/Invalid state/);
    });

    test('Should reject with an error for a non-existent interface', async () => {
        const nonExistentInterface = 'nonexistent';
        const state = 'up';
        await expect(setState(nonExistentInterface, state)).rejects.toThrowError(/Cannot find device/);
    });
});

describe('setMTU', () => {
    test('Should set the MTU for a network interface', async () => {
        const interfaceName = 'eth_dummy_link';
        const mtuValue = 1500;
        await expect(setMTU(interfaceName, mtuValue)).resolves.toBeUndefined();
    });

    test('Should reject with an error for an invalid MTU value', async () => {
        const interfaceName = 'eth_dummy_link';
        const invalidMTU = 'invalid_mtu';
        await expect(setMTU(interfaceName, invalidMTU)).rejects.toThrowError(/Invalid MTU value/);
    });

    test('Should reject with an error for a non-existent interface', async () => {
        const nonExistentInterface = 'nonexistent';
        const mtuValue = 1500;
        await expect(setMTU(nonExistentInterface, mtuValue)).rejects.toThrowError(/Cannot find device/);
    });
});

describe('Rename', () => {
    test('should rename a network interface', async () => {
        const oldInterfaceName = 'eth_dummy_link';
        const newInterfaceName = 'eth_renamed';
        await expect(rename(oldInterfaceName, newInterfaceName)).resolves.toBeUndefined();
    });

    test('should reject with an error for invalid interface names', async () => {
        const invalidInterfaceName = 'eth_invalid!';
        const newInterfaceName = 'eth_renamed';
        await expect(rename(invalidInterfaceName, newInterfaceName)).rejects.toThrowError(/Cannot find device eth_invalid/);
    });

    test('should reject with an error for a non-existent interface', async () => {
        const nonExistentInterface = 'nonexistent';
        const newInterfaceName = 'eth_renamed';
        await expect(rename(nonExistentInterface, newInterfaceName)).rejects.toThrowError(/Cannot find device/);
    });

    afterAll(async () => {
        await rename('eth_renamed', 'eth_dummy_link');
    });
});

describe('Set Mac', () => {
    test('should set the MAC address for a network interface', async () => {
        const interfaceName = 'eth_dummy_link';
        const newMacAddress = '00:11:22:33:44:55';
        await expect(setMac(interfaceName, newMacAddress)).resolves.toBeUndefined();
    });

    test('should reject with an error for an invalid MAC address', async () => {
        const interfaceName = 'eth_dummy_link';
        const invalidMacAddress = 'invalid_mac';
        await expect(setMac(interfaceName, invalidMacAddress)).rejects.toThrowError(/Invalid Mac Address/);
    });

    test('should reject with an error for a non-existent interface', async () => {
        const nonExistentInterface = 'nonexistent';
        const newMacAddress = '00:11:22:33:44:55';
        await expect(setMac(nonExistentInterface, newMacAddress)).rejects.toThrowError(/Cannot find device nonexistent/);
    });
});

afterAll(async () => {
    await exec(`ip link del ${dummyInterfaceName}`);
});