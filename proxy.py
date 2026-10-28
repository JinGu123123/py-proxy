import asyncio


async def pipe(reader,writer):
    """核心管道,从一端读取数据,写到另一端"""
    try:
        while True:
            #每次读 4096 字节
            data = await reader.read(4096)
            if not data:
                break
            #把读到的数据写给另一端
            writer.write(data)
            await writer.drain()        #刷新缓冲区，确保数据发出

    except Exception:
        pass
    finally:
        writer.close()


async def handle_client(client_reader,client_writer):
    """当有浏览器连上代理的 8080 端口时,函数被触发"""
    print("[+] 发现新的连接！")

    # 先读一行，浏览器的请求行
    request_line = await client_reader.readline()
    if not request_line:
        client_writer.close()
        return


    # 解码成字符串方便处理
    request_str = request_line.decode().strip()
    print(f"  收到的请求:{request_str}")

    # 针对 CONNECT 请求的处理
    if request_str.startswith("CONNECT"):
        # CONNECT 的格式是：CONNECT 域名:端口 HTTP/1.1
        parts = request_str.split()
        host_port = parts[1]
        host,port = host_port.split(":")
        port = int(port)
    else:
        # 普通的 HTTP GET 请求，格式是：GET http://域名/ HTTP/1.1
        parts = request_str.split()
        url = parts[1]
        # 简单提取域名和端口
        if url.startswith("http://"):
            host_port = url[7:].split("/")[0]
        else:
            host_port = url.split("/")[0]

        if ":" in host_port:
            host,port = host_port.split(":")
            port = int(port)
        else:
            host = host_port
            port = 80

    print(f"  正在连接目标服务器:{host}:{port}")

    try:
        remote_reader,remote_writer = await asyncio.open_connection(host,port)
    except Exception as e:
        print(f"[-] 连接目标失败:{e}")
        client_writer.close()
        return

    
    if request_str.startswith("CONNECT"):
        # CONNECT 请求，先告诉浏览器“隧道建好了”
        # 返回一个 200 状态码，告诉浏览器可以开始发加密数据了
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()

    else:
        # 普通的 HTTP 请求，原样转发第一行请求
        remote_writer.write(request_line)

    # 启动双向隧道（无论加密还是明文）
    await asyncio.gather(
        pipe(client_reader,remote_writer),  
        pipe(remote_reader,client_writer)
    )




async def main():
    """启动服务"""
    #监听本机的 8080 端口
    server = await asyncio.start_server(handle_client,'0.0.0.0',8080)
    print("[*] 代理服务器启动！监听 0.0.0.0:8080")

    #让服务器一直运行
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] 代理服务器已关闭")