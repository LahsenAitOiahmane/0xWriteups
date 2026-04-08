const { show, add, remove, flush } = require('../src/addresses');
const { exec } = require('child_process');
const { beforeAll, describe, expect, test, afterAll } = require("@jest/globals");

const dummyInterfaceName = 'eth_dummy_addr';
const dummyIpCidr = '172.16.16.0/24';

beforeAll(async () => {
    await exec(`ip link add ${dummyInterfaceName} type dummy`);
    await exec(`ip address add ${dummyIpCidr} dev eth_dummy`);
    await exec(`ip link set ${dummyInterfaceName} mtu 1500`);
    await exec(`ip link set ${dummyInterfaceName} up`);
});

describe('Show', () => {
    test('Should return an Array', async () => {
        const result = await show();
        expect(result).toBeInstanceOf(Array);
    });

    test('Should reject with an error for a non-existent interface', async () => {
        const nonExistentInterface = 'nonexistent';
        await expect(show(nonExistentInterface)).rejects.toThrowError(
            /Error retrieving network interfaces: Device "nonexistent" does not exist./
        );
    });
});

describe('Add', () => {
    test('Should resolve if IP address is successfully added', async () => {
        const interfaceName = 'eth_dummy_addr';
        const ipCidr = '172.16.17.1/32';
        await expect(add(interfaceName, ipCidr)).resolves.toBeUndefined();
    });

    test('Should reject with an error for an invalid IP CIDR', async () => {
        const interfaceName = 'eth_dummy_addr';
        const invalidIpCidr = 'invalid_ip';
        await expect(add(interfaceName, invalidIpCidr)).rejects.toThrowError(/Invalid IP CIDR/);
    });

    test('Should reject with an error for a non-existent interface', async () => {
        const nonExistentInterface = 'nonexistent';
        const ipCidr = '172.16.17.1/32';
        await expect(add(nonExistentInterface, ipCidr)).rejects.toThrowError(/Cannot find device/);
    });

    test('Should reject with an error if IP address already exists on interface', async () => {
        const interfaceName = 'eth_dummy_addr';
        const existingIpCidr = '172.16.17.1/32';
        await expect(add(interfaceName, existingIpCidr)).rejects.toThrowError(/IP Address already exists on interface/);
    });
});

describe('Remove', () => {
    test('Should resolve if IP address is successfully removed', async () => {
        const interfaceName = 'eth_dummy_addr';
        const ipCidrToRemove = '172.16.17.1/32';
        await expect(remove(interfaceName, ipCidrToRemove)).resolves.toBeUndefined();
    });

    test('Should reject with an error for an invalid IP CIDR', async () => {
        const interfaceName = 'eth_dummy_addr';
        const invalidIpCidr = 'invalid_ip';
        await expect(remove(interfaceName, invalidIpCidr)).rejects.toThrowError(/Invalid IP CIDR/);
    });

    test('Should reject with an error for a non-existent interface', async () => {
        const nonExistentInterface = 'nonexistent';
        const ipCidrToRemove = '172.16.17.1/32';
        await expect(remove(nonExistentInterface, ipCidrToRemove)).rejects.toThrowError(/Cannot find device/);
    });

    test('Should reject with an error if IP address does not exist on interface', async () => {
        const interfaceName = 'eth_dummy_addr';
        const nonExistingIpCidr = '172.16.17.2/32';
        await expect(remove(interfaceName, nonExistingIpCidr)).rejects.toThrowError(/IP Address does not exist on interface/);
    });
});

describe('Flush', () => {
    test('Should resolve if all IP addresses are successfully removed', async () => {
        const interfaceName = 'eth_dummy_addr';
        await expect(flush(interfaceName)).resolves.toBeUndefined();
    });

    test('Should reject with an error for a non-existent interface', async () => {
        const nonExistentInterface = 'nonexistent';
        await expect(flush(nonExistentInterface)).rejects.toThrowError(/Error flushing IP addresses: Device/);
    });
});

afterAll(async () => {
    await exec(`ip link del ${dummyInterfaceName}`);
});