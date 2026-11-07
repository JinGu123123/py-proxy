import os
import re
import ipaddress
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
import asyncio
import ssl
import datetime
import logging
import gzip
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlsplit

# 屏蔽所有无关紧要的底层日志
logging.getLogger('asyncio').setLevel(logging.CRITICAL)

with open("ca.key", "rb") as f:
    CA_KEY = serialization.load_pem_private_key(f.read(), password=None)
with open("ca.crt", "rb") as f:
    CA_CRT = x509.load_pem_x509_certificate(f.read())

CERT_DIR = "certs"
CERT_CACHE = {}  # domain -> (cert_path, key_path)


def _safe_name(domain):
    return re.sub(r"[^A-Za-z0-9._-]", "_", domain)


def generate_cert(domain):
    """为域名生成（或复用）一张由 CA 签发的证书，返回 (cert_path, key_path)。"""
    if domain in CERT_CACHE:
        return CERT_CACHE[domain]

    try:
        os.makedirs(CERT_DIR, exist_ok=True)
        base = os.path.join(CERT_DIR, _safe_name(domain))
        cert_path = base + ".crt"
        key_path = base + ".key"

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)

        # 域名用 DNSName，IP 用 IPAddress
        try:
            san = x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(domain))]
            )
        except ValueError:
            san = x509.SubjectAlternativeName([x509.DNSName(domain)])

        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
            )
            .issuer_name(CA_CRT.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(san, critical=False)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(CA_KEY, hashes.SHA256())
        )

        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        CERT_CACHE[domain] = (cert_path, key_path)
        return cert_path, key_path
    except Exception as e:
        print(f"[-] 生成证书失败 {domain}: {e}")
        return None, None

    
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




async def handle_http(client_reader, client_writer, request_str):
    try:
        method, url, version = request_str.split()
    except ValueError:
        client_writer.close()
        return

    if not url.startswith("http://"):
        client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await client_writer.drain()
        client_writer.close()
        return

    # 把剩下的请求头读完
    header_lines = []
    while True:
        line = await client_reader.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        header_lines.append(line)

    parts = urlsplit(url)
    host = parts.hostname
    port = parts.port or 80
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    try:
        remote_reader, remote_writer = await asyncio.open_connection(host, port)
    except Exception as e:
        print(f"[-] 连接目标失败: {e}")
        client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await client_writer.drain()
        client_writer.close()
        return

    # 代理形式 → 源服务器形式
    remote_writer.write(f"{method} {path} {version}\r\n".encode())
    for line in header_lines:
        low = line.lower()
        if low.startswith(b"proxy-connection:"):
            continue
        if low.startswith(b"connection:"):
            continue
        remote_writer.write(line)
    remote_writer.write(b"Connection: close\r\n\r\n")
    await remote_writer.drain()

    # 响应原样转发回客户端
    await pipe(remote_reader, client_writer)
    remote_writer.close()
    try:
        await remote_writer.wait_closed()
    except Exception:
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

            while True:
                line = await client_reader.readline()
                if line in (b"\r\n",b"\n",b""):
                    break
            
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()


            cert_path,key_path = generate_cert(host)
            if not cert_path:
                client_writer.close()
                return

            dynamic_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            dynamic_ctx.load_cert_chain(certfile=cert_path,keyfile=key_path)
            dynamic_ctx.set_alpn_protocols(['http/1.1'])
            
            # 核心改变：直接包装底层的 Socket，而不是强拆 StreamWriter
            transport = client_writer.transport
            loop = asyncio.get_running_loop()
            
            new_transport = await loop.start_tls(
                transport, client_writer._protocol, dynamic_ctx, 
                server_side=True
            )
            # 替换底层 transport
            client_reader._transport = new_transport
            client_writer._transport = new_transport
            
            # 去连接真实服务器
            try:
                remote_ctx = ssl.create_default_context()
                remote_reader, remote_writer = await asyncio.open_connection(
                    host, port,ssl=remote_ctx,server_hostname=host)
            except Exception as e:
                print(f"[-] 连接目标失败: {e}")
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                client_writer.close()
                return
                
            print(f"[*] 正在解密 {host}:{port} 的流量...")
            await asyncio.gather(
                pipe(client_reader, remote_writer, is_decrypt=True),
                pipe(remote_reader, client_writer)
            )

        else:
            await handle_http(client_reader,client_writer,request_str)

    except Exception as e:
        print(f"[-] 处理异常: {e}")
        try:
            client_writer.close()
        except Exception:
            pass

async def main():
    server = await asyncio.start_server(handle_client, '127.0.0.1', 8080)
    print("[*] 代理服务器启动！监听 127.0.0.1:8080 (支持 HTTPS 解密)")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] 代理服务已关闭")