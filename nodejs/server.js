const net = require('net');
const server = net.createServer((client) => {
    // 'connection' listener
    console.log('client connected');

    client.on('data', (data) => {
        console.log("client data: " + data.toString('hex'));

        echoLogin(client);
    });

    client.on('end', () => {
        console.log('client disconnected');
    });


});
server.on('error', (err) => {

    Console.log(err.toString());
    throw err;
});
server.listen(8124, () => {
    console.log('server bound');
});

function echoLogin(client) {
    const response = Buffer.allocUnsafe(18);
    response.writeUInt32LE(0x01, 0);
    response.writeUInt32LE(0x01, 4);
    response.writeUInt32LE(0x00, 8); //返回状态码
    response.write("ok", 12); //登录响应内容
    response.writeUInt32LE(0x02, 14);
    client.write(response.toString());

    console.log(response.toString('hex') + "\n");

    client.pipe(client);
}