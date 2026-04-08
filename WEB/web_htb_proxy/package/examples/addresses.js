const ipWrapper = require('../src/index');

(async () => {
    const addresses = await ipWrapper.addr.show();
    await ipWrapper.addr.add('enp6s0', '6.6.6.6/32');
    await ipWrapper.addr.remove('enp6s0', '6.6.6.6/32');
    await ipWrapper.addr.flush('enp6s0');
})();