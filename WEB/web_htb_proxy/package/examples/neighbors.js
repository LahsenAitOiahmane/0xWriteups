const ipWrapper = require('../src/index');

(async () => {
    try {
        const neighbors = await ipWrapper.neigh.show();
        await ipWrapper.neigh.add('192.168.1.100', 'aa:bb:cc:dd:ee:ff', 'enp6s0', 'permanent');
        await ipWrapper.neigh.update('192.168.1.100', 'aa:bb:cc:dd:ee:11', 'enp6s0', 'permanent');
        await ipWrapper.neigh.remove('192.168.1.100', 'enp6s0');
        await ipWrapper.neigh.flush();
    } catch (error) {
        console.error('An error occurred:', error.message);
    }
})();
