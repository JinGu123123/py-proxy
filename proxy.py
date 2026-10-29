import asyncio
import ssl
import datetime
import logging
import gzip
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# 屏蔽所有无关紧要的底层日志
logging.getLogger('asyncio').setLevel(logging.CRITICAL)

with open("ca.key", "rb") as f:
    CA_KEY = serialization.load_pem_private_key(f.read(), password=None)
with open("ca.crt", "rb") as f:
    CA_CRT = x509.load_pem_x509_certificate(f.read())

def generate_cert(domain):
    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            CA_CRT.subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False,
        ).sign(CA_KEY, hashes.SHA256())
        
        with open("temp.key", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open("temp.crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return True
    except Exception as e:
        return False

async def pipe(reader, writer, is_decrypt=False):
    try:
        while True:
            data = await reader.read(8192)
            if not data:
                break
            if is_decrypt:
                try:
                    decompressed = gzip.decompress(data)
                except:
                    decompressed = data
                try:
                    text = decompressed.decode('utf-8', errors='ignore')
                    if "HTTP/1.1" in text or "GET " in text or "Host:" in text:
                        first_line = text.splitlines()[0]
                        print(f"\033[92m[明文截获] {first_line}\033[0m")
                except:
                    pass
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

async def handle_client(client_reader, client_writer):
    print("[+] 发现新连接！")
    try:
        request_line = await client_reader.readline()
        if not request_line:
            client_writer.close()
            return

        request_str = request_line.decode().strip()
        
        if request_str.startswith("CONNECT"):
            parts = request_str.split()
            host, port = parts[1].split(":")
            port = int(port)
            
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()

            if not generate_cert(host):
                client_writer.close()
                return
                
            dynamic_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            dynamic_ctx.load_cert_chain(certfile="temp.crt", keyfile="temp.key")
            dynamic_ctx.set_alpn_protocols(['http/1.1'])
            
            # 核心改变：直接包装底层的 Socket，而不是强拆 StreamWriter
            transport = client_writer.transport
            loop = asyncio.get_running_loop()
            
            new_transport = await loop.start_tls(
                transport, client_reader.protocol, dynamic_ctx, 
                server_side=True, server_hostname=host
            )
            # 替换底层 transport
            client_reader._transport = new_transport
            client_writer._transport = new_transport
            
            # 去连接真实服务器
            try:
                remote_reader, remote_writer = await asyncio.open_connection(host, port)
            except Exception as e:
                print(f"[-] 连接目标失败: {e}")
                client_writer.close()
                return
                
            print(f"[*] 正在解密 {host}:{port} 的流量...")
            await asyncio.gather(
                pipe(client_reader, remote_writer, is_decrypt=True),
                pipe(remote_reader, client_writer)
            )
        else:
            pass
    except Exception as e:
        print(f"[-] 处理异常: {e}")
        try:
            client_writer.close()
        except:
            pass

async def main():
    server = await asyncio.start_server(handle_client, '0.0.0.0', 8080)
    print("[*] 代理服务器启动！监听 0.0.0.0:8080 (支持 HTTPS 解密)")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] 代理服务已关闭")