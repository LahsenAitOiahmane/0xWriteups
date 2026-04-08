const ipWrapper = require('../src/index');

(async () => {
    const links = await ipWrapper.link.show();

    await ipWrapper.link.setState('eth0', 'down');
    await ipWrapper.link.setState('eth0', 'up');
    await ipWrapper.link.setMTU('eth0', 1492);
    await ipWrapper.link.setState('eth0', 'down');
    await ipWrapper.link.rename('eth0', 'enp6s0');
    await ipWrapper.link.setState('enp6s0', 'up');
    await ipWrapper.link.setMac('enp6s0', '00:11:22:33:44:55');
})();