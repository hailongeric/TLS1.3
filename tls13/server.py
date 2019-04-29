# -*- coding: UTF-8 -*-
import time
from .utilization import socket

from .protocol import TLSPlaintext, ContentType, Handshake, HandshakeType, \
    CipherSuite, ServerHello, KeyShareEntry, KeyShareServerHello, \
    Extension, ExtensionType, ProtocolVersion, SupportedVersions, \
    NamedGroup, SignatureScheme, \
    Certificate, CertificateEntry, CertificateVerify, Finished, Hash, \
    TLSCiphertext, Data, EncryptedExtensions, TLSRawtext

# Crypto
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, \
    X25519PublicKey
from .utilization.cryption_algorithm.ffdhe import FFDHE
from .utilization.cryption_algorithm import Cipher
from .utilization import cryptolib, hexdump, hexstr
from .utilization.type import Uint32


class TLSServer:
    def __init__(self, server_conn):
        self.server_conn = server_conn

        messages = bytearray(0)

        #    <<<   ClientHello   >>>
        data = server_conn.recv_msg()
        rcv_clienthello = TLSPlaintext.get_types_from_bytes(data)
        # TLSPlaintext.fragment 获取数据
        # len(ContentType + ProtocolVersion + length) == 5 取尾部数据
        messages += data[5:]
        print(rcv_clienthello)

        # >>> ServerHello >>>

        # select params

        client_session_id = rcv_clienthello.legacy_session_id
        client_cipher_suites = rcv_clienthello.cipher_suites
        client_key_share_groups = rcv_clienthello.get_extension(ExtensionType.key_share).get_groups()
        client_signature_scheme_list = rcv_clienthello.get_extension(ExtensionType.signature_algorithms).supported_signature_algorithms
        client_key_share = rcv_clienthello.get_extension(ExtensionType.key_share)

        # 确定参数并创建shared_key
        # 加密：从收到的ClientHello密码套件中进行选择
        if CipherSuite.TLS_CHACHA20_POLY1305_SHA256 in client_cipher_suites:
            cipher_suite = CipherSuite.TLS_CHACHA20_POLY1305_SHA256
        elif CipherSuite.TLS_AES_256_GCM_SHA384 in client_cipher_suites:
            cipher_suite = CipherSuite.TLS_AES_256_GCM_SHA384
        elif CipherSuite.TLS_AES_128_CCM_8_SHA256 in client_cipher_suites:
            cipher_suite = CipherSuite.TLS_AES_128_CCM_8_SHA256
        elif CipherSuite.TLS_AES_128_CCM_SHA256 in client_cipher_suites:
            cipher_suite = CipherSuite.TLS_AES_128_CCM_SHA256
        elif CipherSuite.TLS_AES_128_GCM_SHA256 in client_cipher_suites:
            cipher_suite = CipherSuite.TLS_AES_128_GCM_SHA256
        else:
            raise NotImplementedError()

        # 密钥共享：通过查看ClientHello的KeyShareEntry确定密钥共享方法后，
        # 决定参数（group，key_exchange）
        if NamedGroup.ffdhe2048 in client_key_share_groups:
            server_share_group = NamedGroup.ffdhe2048
            client_key_exchange = client_key_share.get_key_exchange(server_share_group)
            ffdhe2048 = FFDHE(server_share_group)
            server_key_share_key_exchange = ffdhe2048.gen_public_key()
            pre_master_shared_key = ffdhe2048.gen_shared_key(client_key_exchange)
        elif NamedGroup.x25519 in client_key_share_groups:
            server_share_group = NamedGroup.x25519
            client_key_exchange = client_key_share.get_key_exchange(server_share_group)
            x25519 = X25519PrivateKey.generate()
            server_key_share_key_exchange = x25519.public_key().public_bytes()
            pre_master_shared_key = x25519.exchange(X25519PublicKey.from_public_bytes(client_key_exchange))
        else:
            raise NotImplementedError()

        print("\n pre_master_shared_key: %s" % hexstr(pre_master_shared_key))
        print()
        selected_version = ProtocolVersion.TLS13

        serverhello = TLSPlaintext(
            type=ContentType.handshake,
            fragment=Handshake(
                msg_type=HandshakeType.server_hello,
                msg=ServerHello(
                    legacy_session_id_echo=client_session_id,
                    cipher_suite=cipher_suite,
                    extensions=[
                        # supported_versions
                        Extension(
                            extension_type=ExtensionType.supported_versions,
                            extension_data=SupportedVersions(
                                msg_type=HandshakeType.server_hello,
                                selected_version=selected_version )),

                        # key_share
                        Extension(
                            extension_type=ExtensionType.key_share,
                            extension_data=KeyShareServerHello(
                                server_share=KeyShareEntry(
                                    group=server_share_group,
                                    key_exchange=server_key_share_key_exchange ))),
                    ] )))

        # 包含ServerHello的TLSPlaintext
        print(serverhello)
        server_conn.send_msg(serverhello.to_bytes())
        messages += serverhello.fragment.to_bytes()

        # -- HKDF ---

        hash_algorithm = CipherSuite.get_hash_name(cipher_suite)
        secret_size = CipherSuite.get_hash_algo_size(cipher_suite)
        salt = bytearray(secret_size)
        IKM = bytearray(secret_size)

        print("\nmessages hash = " + cryptolib.hash_value(messages, 'sha256').hex())
        print()

        early_secret = cryptolib.hkdf_extract(salt, IKM, hash_algorithm)
        temp_secret = cryptolib.derive_secret(early_secret, b"derived", b"")
        handshake_secret = cryptolib.hkdf_extract(temp_secret, pre_master_shared_key, hash_algorithm)
        client_handshake_traffic_secret = cryptolib.derive_secret(handshake_secret, b"c hs traffic", messages)
        server_handshake_traffic_secret = cryptolib.derive_secret(handshake_secret, b"s hs traffic", messages)
        temp_secret = cryptolib.derive_secret(handshake_secret, b"derived", b"")
        master_secret = cryptolib.hkdf_extract(temp_secret, bytearray(secret_size), hash_algorithm)
        # print('master_secret =', master_secret.hex())
        client_application_traffic_secret_0 = cryptolib.derive_secret(master_secret, b"c ap traffic", messages)
        server_application_traffic_secret_0 = cryptolib.derive_secret(master_secret, b"s ap traffic", messages)
        # print('client_application_traffic_secret_0 =', client_application_traffic_secret_0.hex())
        # print('server_application_traffic_secret_0 =', server_application_traffic_secret_0.hex())
        exporter_master_secret = cryptolib.derive_secret(master_secret, b"exp master", messages)
        resumption_master_secret = cryptolib.derive_secret(master_secret, b"res master", messages)

        if cipher_suite == CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            cipher_class = Cipher.Chacha20Poly1305
            key_size = Cipher.Chacha20Poly1305.key_size
            nonce_size = Cipher.Chacha20Poly1305.nonce_size
        else:
            raise NotImplementedError()

        # recordlayer.seq_number

        server_write_key, server_write_iv = cryptolib.gen_key_and_iv(server_application_traffic_secret_0,
                                                                     key_size, nonce_size, hash_algorithm)
        server_traffic_crypto = cipher_class(key=server_write_key, nonce=server_write_iv)

        client_write_key, client_write_iv = cryptolib.gen_key_and_iv(client_application_traffic_secret_0,
                                                                     key_size, nonce_size, hash_algorithm)
        client_traffic_crypto = cipher_class(key=client_write_key, nonce=client_write_iv)

        # print('server_write_key =', server_write_key.hex())
        # print('server_write_iv =', server_write_iv.hex())
        # print('client_write_key =', client_write_key.hex())
        # print('client_write_iv =', client_write_iv.hex())

        # <<<    EncryptedExtensions    >>>

        encrypted_extensions = TLSPlaintext(
            type=ContentType.handshake,
            fragment=Handshake(
                msg_type=HandshakeType.encrypted_extensions,
                msg=EncryptedExtensions(extensions=[])))

        print(encrypted_extensions)
        encrypted_extensions_cipher = TLSCiphertext.create(encrypted_extensions, crypto=server_traffic_crypto)
        server_conn.send_msg(encrypted_extensions_cipher.to_bytes())
        messages += encrypted_extensions.fragment.to_bytes()

        # <<<   server Certificate   >>>

        with open('.ssh/server.crt', 'r') as f:
            import ssl
            bytes_DER_encoded = ssl.PEM_cert_to_DER_cert(f.read())
            cert_data = bytes_DER_encoded

        certificate = TLSPlaintext(
            type=ContentType.handshake,
            fragment=Handshake(
                msg_type=HandshakeType.certificate,
                msg=Certificate(
                    certificate_request_context=b'',
                    certificate_list=[
                        CertificateEntry(cert_data=cert_data)
                    ])))

        print("\n<<<   Certificate   >>>\n")
        # print(certificate)
        certificate_cipher = TLSCiphertext.create(certificate, crypto=server_traffic_crypto)
        # print("\n\n")
        # print(len(certificate_cipher))
        # # print(certificate_cipher.to_bytes())
        # # print("\n\n")
        time.sleep(1)
        server_conn.send_msg(certificate_cipher.to_bytes())
        messages += certificate.fragment.to_bytes()

        '''
        #  <<<  CertificateVerify   >>> 

        # 数字签名算法
        # 使用私钥.ssh/server.key进行签名
        
         The digital signature is then computed over the concatenation of:

   -  A string that consists of octet 32 (0x20) repeated 64 times

   -  The context string

   -  A single 0 byte which serves as the separator

   -  The content to be signed

   This structure is intended to prevent an attack on previous versions
   of TLS in which the ServerKeyExchange format meant that attackers
   could obtain a signature of a message with a chosen 32-byte prefix
   (ClientHello.random).  The initial 64-byte pad clears that prefix
   along with the server-controlled ServerHello.random.

   The context string for a server signature is
   "TLS 1.3, server CertificateVerify".  The context string for a
   client signature is "TLS 1.3, client CertificateVerify".  It is
   used to provide separation between signatures made in different
   contexts, helping against potential cross-protocol attacks.

   For example, if the transcript hash was 32 bytes of 01 (this length
   would make sense for SHA-256), the content covered by the digital
   signature for a server CertificateVerify would be:

      2020202020202020202020202020202020202020202020202020202020202020
      2020202020202020202020202020202020202020202020202020202020202020
      544c5320312e332c207365727665722043657274696669636174655665726966
      79
      00
      0101010101010101010101010101010101010101010101010101010101010101

        '''

        from Crypto.Hash import SHA256
        from Crypto.PublicKey import RSA
        key = RSA.importKey(open('.ssh/server.key').read())
        if SignatureScheme.rsa_pss_pss_sha256 in client_signature_scheme_list:
            server_signature_scheme = SignatureScheme.rsa_pss_pss_sha256
            from Crypto.Signature import PKCS1_PSS
            message = b'\x20' * 64 + b'TLS 1.3, server CertificateVerify' + b'\x00' + cryptolib.transcript_hash(messages, hash_algorithm)
            print("\nmessage:")
            print(hexdump(message))
            h = SHA256.new(message)
            certificate_signature = PKCS1_PSS.new(key).sign(h)
        else:
            raise NotImplementedError()

        cert_verify = TLSPlaintext(
            type=ContentType.handshake,
            fragment=Handshake(
                msg_type=HandshakeType.certificate_verify,
                msg=CertificateVerify(
                    algorithm=server_signature_scheme,
                    signature=certificate_signature )))

        print("\n <<<   CertificateVerify   >>> \n")
        print(cert_verify)
        # server_conn.send_msg(cert_verify.to_bytes())
        cert_verify_cipher = TLSCiphertext.create(cert_verify, crypto=server_traffic_crypto)
        time.sleep(1)
        server_conn.send_msg(cert_verify_cipher.to_bytes())
        # messages.append(cert_verify.fragment)
        messages += cert_verify.fragment.to_bytes()

        # <<<   Finished    >>>

        # 使用server_handshake_traffic_secret创建finished_key
        hash_algorithm = CipherSuite.get_hash_name(cipher_suite)
        hash_size = CipherSuite.get_hash_algo_size(cipher_suite)
        Hash.set_size(hash_size)
        finished_key = cryptolib.hkdf_expand_label(
            server_handshake_traffic_secret, b'finished', b'', hash_size, hash_algorithm)
        verify_data = cryptolib.hmac_value(
            finished_key, cryptolib.transcript_hash(messages, hash_algorithm), hash_algorithm)
        finished = TLSPlaintext(
            type=ContentType.handshake,
            fragment=Handshake(
                msg_type=HandshakeType.finished,
                msg=Finished(verify_data=verify_data) ))

        print("\n<<<   Finished   >>>\n")
        print(finished)
        # print(hexdump(finished.to_bytes()))
        finished_cipher = TLSCiphertext.create(finished, crypto=server_traffic_crypto)
        time.sleep(1)
        server_conn.send_msg(finished_cipher.to_bytes())
        messages += finished.fragment.to_bytes()

        # print(messages)

        client_master_key = cryptolib.derive_secret(master_secret, b"c ap traffic", messages)
        server_master_key = cryptolib.derive_secret(master_secret, b"s ap traffic", messages)

        server_app_write_key, server_app_write_iv = cryptolib.gen_key_and_iv(server_master_key, key_size, nonce_size, hash_algorithm)
        server_app_data_crypto = cipher_class(key=server_app_write_key, nonce=server_app_write_iv)
        client_app_write_key, client_app_write_iv = cryptolib.gen_key_and_iv(client_master_key, key_size, nonce_size, hash_algorithm)
        client_app_data_crypto = cipher_class(key=client_app_write_key, nonce=client_app_write_iv)
        client_write_key_1, client_write_iv_1 = cryptolib.gen_key_and_iv(master_secret, key_size, nonce_size, hash_algorithm)


        client_application_traffic_data_crypto = cipher_class(key=client_write_key_1, nonce=client_write_iv_1)

        self.server_app_data_crypto = server_app_data_crypto
        self.client_app_data_crypto = client_app_data_crypto
        self.client_application_traffic_data_crypto = client_application_traffic_data_crypto

        # print('client_master_key =', client_master_key.hex())
        # print('server_master_key =', server_master_key.hex())
        # print('server_app_write_key =', server_app_write_key.hex())
        # print('server_app_write_iv =', server_app_write_iv.hex())
        #
        # print('client_app_write_key =', client_app_write_key.hex())
        # print('client_app_write_iv =', client_app_write_iv.hex())


        # <<<   recv Finished   >>>
        print("<<<    recv Finished    >>>")
        hash_size = CipherSuite.get_hash_algo_size(cipher_suite)
        data = server_conn.recv_msg()
        print(hexdump(data))
        if len(data) == 7:  # 警报
            print(TLSPlaintext.get_types_from_bytes(data))
            raise RuntimeError("Alert!")
        #       需要同时进行处理
        # trimed_data = data[6:]  # change cipher spec (14 03 03 00 01 01) 的规范
        # print("remove: change cipher spec")
        # print(hexdump(trimed_data))

        # # recved_finished = TLSPlaintext.get_types_from_bytes(data)
        Cipher.Cipher.seq_number = 0
        recved_finished = TLSCiphertext.restore(data, crypto=client_traffic_crypto, mode=ContentType.handshake)
        # # messages.append(recved_finished.fragment)
        # messages += recved_finished.fragment.to_bytes()
        # print(recved_finished)
        # assert isinstance(recved_finished.fragment.msg, Finished)
        # recved_finished = TLSRawtext.get_types_from_bytes(trimed_data)
        print(recved_finished)

        from .protocol.ticket import NewSessionTicket
        # dummy
        new_session_ticket = TLSPlaintext(
            type=ContentType.handshake,
            fragment=Handshake(
                msg_type=HandshakeType.new_session_ticket,
                msg=NewSessionTicket(
                    ticket_lifetime=Uint32(0),
                    ticket_age_add=Uint32(0),
                    ticket_nonce=b'nonce',
                    ticket=b'foobar'
                    )))

        Cipher.Cipher.seq_number = 0

        print("\n\n<<<    NewSessionTicket    >>>\n\n")
        print(new_session_ticket)
        time.sleep(1)
        new_session_ticket_cipher = TLSCiphertext.create(
                new_session_ticket, crypto=server_app_data_crypto)
        server_conn.send_msg(new_session_ticket_cipher.to_bytes())
        messages += new_session_ticket.fragment.to_bytes()


    def recv(self):
        # while True:
        #     data = self.server_conn.recv_msg()
        #     if len(data) != 0:
        #         break
        #     time.sleep(0.5)
        data = self.server_conn.recv_msg()
        if len(data) != 0:
            recved_app_data = TLSCiphertext.restore(data,
                crypto=self.client_application_traffic_data_crypto,
                mode=ContentType.application_data)
            print("C:" + str(recved_app_data.raw))
            return recved_app_data.raw
        return None

    def send(self, send_bytes):
        tmp = send_bytes

        test_data = TLSPlaintext(
            type=ContentType.application_data,
            fragment=Data(tmp))
        test_data_cipher = TLSCiphertext.create(test_data,
            crypto=self.server_app_data_crypto)
        self.server_conn.send_msg(test_data_cipher.to_bytes())
        print("* [send]")
        print(hexdump(test_data_cipher.to_bytes()))

        return len(test_data_cipher)


def server_main():
    print("server is beginning ...")

    server_conn = socket.ServerConnection()
    server = TLSServer(server_conn)
    time.sleep(1)
    server.recv()

    while True:
        server.recv()
        my_message = input("C:")
        server.send(my_message.encode("utf-8"))

