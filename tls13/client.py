# -*- coding: UTF-8 -*-
from .utilization import socket
import time

from .protocol import TLSPlaintext, ContentType, Handshake, HandshakeType, \
    CipherSuite, ClientHello, Extension, ExtensionType, \
    KeyShareEntry, KeyShareClientHello, ProtocolVersion, SupportedVersions, \
    NamedGroup, NamedGroupList, SignatureScheme, SignatureSchemeList, \
    Finished, Hash, TLSCiphertext, Data

# Crypto
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, \
    X25519PublicKey
from .utilization.cryption_algorithm.ffdhe import FFDHE
from .utilization.cryption_algorithm import Cipher

from .utilization import cryptolib, hexstr


def client_main():
    print("client is beginning ...")
    messages = bytearray(0)

    # params

    ffdhe2048 = FFDHE(NamedGroup.ffdhe2048)
    ffdhe2048_key_exchange = ffdhe2048.gen_public_key()
    x25519 = X25519PrivateKey.generate()
    x25519_key_exchange = x25519.public_key().public_bytes()

    versions = [ProtocolVersion.TLS13, ProtocolVersion.TLS13unknow]
    named_group_list = [NamedGroup.x25519, NamedGroup.ffdhe2048]

    supported_signature_algorithms = [
        SignatureScheme.rsa_pss_pss_sha256,
        SignatureScheme.rsa_pss_pss_sha384,
        SignatureScheme.rsa_pss_pss_sha512,
        SignatureScheme.rsa_pss_rsae_sha256,
        SignatureScheme.rsa_pss_rsae_sha384,
        SignatureScheme.rsa_pss_rsae_sha512,
        SignatureScheme.ecdsa_secp256r1_sha256,
        SignatureScheme.ecdsa_secp384r1_sha384,
        SignatureScheme.ecdsa_secp512r1_sha512,
        SignatureScheme.ed25519,
        SignatureScheme.ed448,
    ]

    client_shares = [
        KeyShareEntry(
            group=NamedGroup.x25519,
            key_exchange=x25519_key_exchange),
        KeyShareEntry(
            group=NamedGroup.ffdhe2048,
            key_exchange=ffdhe2048_key_exchange),
    ]
    cipher_suites = [
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
    ]

    # <<<   ClientHello    >>>

    clienthello = TLSPlaintext(
        type=ContentType.handshake,
        fragment=Handshake(
            msg_type=HandshakeType.client_hello,
            msg=ClientHello(
                cipher_suites=cipher_suites,
                extensions=[
                    # supported_versions
                    Extension(
                        extension_type=ExtensionType.supported_versions,
                        extension_data=SupportedVersions(
                            msg_type=HandshakeType.client_hello,
                            versions=versions )),

                    # supported_groups
                    Extension(
                        extension_type=ExtensionType.supported_groups,
                        extension_data=NamedGroupList(
                            named_group_list=named_group_list )),

                    # signature_algorithms
                    Extension(
                        extension_type=ExtensionType.signature_algorithms,
                        extension_data=SignatureSchemeList(
                            supported_signature_algorithms=
                            supported_signature_algorithms)),

                    # key_share
                    Extension(
                        extension_type=ExtensionType.key_share,
                        extension_data=KeyShareClientHello(
                            client_shares=client_shares)),
                ])))

    # 将ClientHello字节字符串发送到Server
    print("\nConnecting to server...\n")
    client_conn = socket.ClientConnection()
    # 包含ClientHello的TLSPlaintext
    print(clienthello)
    client_conn.send_msg(clienthello.to_bytes())
    messages += clienthello.fragment.to_bytes()

    # <<<   ServerHello   >>>
    # 需要单独执行此操作并将其传递给TLSPlaintext.get_types_from_bytes
    data = client_conn.recv_msg()
    rcv_serverhello = TLSPlaintext.get_types_from_bytes(data)
    messages += data[5:len(rcv_serverhello)]
    print()
    print(rcv_serverhello)
    print()
    remain_data = data[len(rcv_serverhello):]

    tmp = remain_data[6:]
    remain_data = tmp

    # 确定参数
    server_cipher_suite = rcv_serverhello.cipher_suite
    server_selected_version = rcv_serverhello.get_extension(ExtensionType.supported_versions) \
        .selected_version
    server_key_share_group = rcv_serverhello.get_extension(ExtensionType.key_share).get_group()
    server_key_share_key_exchange = rcv_serverhello \
        .get_extension(ExtensionType.key_share).get_key_exchange()

    server_pub_key = server_key_share_key_exchange

    # pre_master_shared_key 的生成
    if server_key_share_group == NamedGroup.ffdhe2048:
        pre_master_shared_key = ffdhe2048.gen_shared_key(server_pub_key)
    elif server_key_share_group == NamedGroup.x25519:
        pre_master_shared_key = x25519.exchange(X25519PublicKey.from_public_bytes(server_pub_key))
    else:
        raise NotImplementedError()

    print("\npre_master_shared_key: %s" % hexstr(pre_master_shared_key))
    print()

    # -- HKDF ---

    # print("messages hash = " + cryptolib.hash_value(messages, 'sha256').hex())
    # print()

    last_use_cipher_suite = server_cipher_suite

    hash_algo = CipherSuite.get_hash_name(last_use_cipher_suite)
    secret_size = CipherSuite.get_hash_algo_size(last_use_cipher_suite)
    salt = bytearray(secret_size)
    IKM = bytearray(secret_size)

    early_secret = cryptolib.hkdf_extract(salt, IKM, hash_algo)
    # temp_secret是在计算过程中的一个中间密钥
    '''
     PSK ->  HKDF-Extract = Early Secret
             |
             +-----> Derive-Secret(., "ext binder" | "res binder", "")
             |                     = binder_key
             |
             +-----> Derive-Secret(., "c e traffic", ClientHello)
             |                     = client_early_traffic_secret
             |
             +-----> Derive-Secret(., "e exp master", ClientHello)
             |                     = early_exporter_master_secret
             v
       Derive-Secret(., "derived", "")
             |
             v
   (EC)DHE -> HKDF-Extract = Handshake Secret
             |
             +-----> Derive-Secret(., "c hs traffic",
             |                     ClientHello...ServerHello)
             |                     = client_handshake_traffic_secret
             |
             +-----> Derive-Secret(., "s hs traffic",
             |                     ClientHello...ServerHello)
             |                     = server_handshake_traffic_secret
             v
       Derive-Secret(., "derived", "")
             |
             v
   0 -> HKDF-Extract = Master Secret
             |
             +-----> Derive-Secret(., "c ap traffic",
             |                     ClientHello...server Finished)
             |                     = client_application_traffic_secret_0
             |
             +-----> Derive-Secret(., "s ap traffic",
             |                     ClientHello...server Finished)
             |                     = server_application_traffic_secret_0
             |
             +-----> Derive-Secret(., "exp master",
             |                     ClientHello...server Finished)
             |                     = exporter_master_secret
             |
             +-----> Derive-Secret(., "res master",
                                   ClientHello...client Finished)
                                   = resumption_master_secret
                                   '''
    temp_secret = cryptolib.derive_secret(early_secret, b"derived", b"")
    handshake_secret = cryptolib.hkdf_extract(temp_secret, pre_master_shared_key, hash_algo)
    client_handshake_traffic_secret = cryptolib.derive_secret(handshake_secret, b"c hs traffic", messages)
    server_handshake_traffic_secret = cryptolib.derive_secret(handshake_secret, b"s hs traffic", messages)
    # master secret
    temp_master_secret = cryptolib.derive_secret(handshake_secret, b"derived", b"")
    master_secret = cryptolib.hkdf_extract(temp_master_secret, bytearray(secret_size), hash_algo)
    client_application_traffic_secret_0 = cryptolib.derive_secret(master_secret, b"c ap traffic", messages)
    server_application_traffic_secret_0 = cryptolib.derive_secret(master_secret, b"s ap traffic", messages)
    exporter_master_secret = cryptolib.derive_secret(master_secret, b"exp master", messages)
    resumption_master_secret = cryptolib.derive_secret(master_secret, b"res master", messages)

    if last_use_cipher_suite == CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
        cipher_class = Cipher.Chacha20Poly1305
        key_size = Cipher.Chacha20Poly1305.key_size
        nonce_size = Cipher.Chacha20Poly1305.nonce_size
    else:
        raise NotImplementedError()

    server_write_key, server_write_iv = cryptolib.gen_key_and_iv(server_application_traffic_secret_0,
                                 key_size, nonce_size, hash_algo)
    server_traffic_crypto = cipher_class(key=server_write_key, nonce=server_write_iv)

    client_write_key_0, client_write_iv_0 = cryptolib.gen_key_and_iv(client_application_traffic_secret_0,
                                 key_size, nonce_size, hash_algo)
    client_traffic_crypto = cipher_class(key=client_write_key_0, nonce=client_write_iv_0)

    client_write_key_1, client_write_iv_1 = cryptolib.gen_key_and_iv(master_secret, key_size, nonce_size, hash_algo)

    # print('server_write_key =', server_write_key.hex())
    # print('server_write_iv =', server_write_iv.hex())
    # print('client_write_key_1 =', client_write_key_1.hex())
    # print('client_write_iv_1 =', client_write_iv_1.hex())

    app_data_crypto = cipher_class(key=client_write_key_1, nonce=client_write_iv_1)

    # <<< EncryptedExtensions <<<
    if len(remain_data) > 0:
        data = remain_data
    else:
        data = client_conn.recv_msg()
    recved_encrypted_extensions = TLSCiphertext.restore(data,
            crypto=server_traffic_crypto, mode=ContentType.handshake)
    messages += data[5:len(recved_encrypted_extensions)]
    print(recved_encrypted_extensions)
    remain_data = data[len(recved_encrypted_extensions):]

    # <<< server Certificate <<<
    data = client_conn.recv_msg()
    # print("\n\n")
    # print(data)
    # print("\n\n")

    recved_certificate = TLSCiphertext.restore(data,
            crypto=server_traffic_crypto, mode=ContentType.handshake)
    # TODO: data[5:len(recved_certificate)] and verfy it
    messages += data[5:]
    print(recved_certificate)

    # <<<    server CertificateVerify    >>>
    data = client_conn.recv_msg()
    recved_cert_verify = TLSCiphertext.restore(data,
            crypto=server_traffic_crypto, mode=ContentType.handshake)
    messages += data[5:]
    print(recved_cert_verify)

    # <<<   recv Finished    >>>
    hash_size = CipherSuite.get_hash_algo_size(last_use_cipher_suite)
    Hash.set_size(hash_size)
    data = client_conn.recv_msg()
    recved_finished = TLSCiphertext.restore(data,
            crypto=server_traffic_crypto, mode=ContentType.handshake)
    messages += data[5:]
    print(recved_finished)
    assert isinstance(recved_finished.fragment.msg, Finished)


    #  <<<     Finished     >>>
    # 使用client_handshake_traffic_secret创建finished_key
    hash_algo = CipherSuite.get_hash_name(last_use_cipher_suite)
    hash_size = CipherSuite.get_hash_algo_size(last_use_cipher_suite)
    finished_key = cryptolib.hkdf_expand_label(
        client_application_traffic_secret_0, b'finished', b'', hash_size, hash_algo)
    verify_data = cryptolib.hmac_value(
        finished_key, cryptolib.transcript_hash(messages, hash_algo), hash_algo)
    finished = TLSPlaintext(
        type=ContentType.handshake,
        fragment=Handshake(
            msg_type=HandshakeType.finished,
            msg=Finished(verify_data=verify_data) ))

    print(finished)
    # client_conn.send_msg(finished.to_bytes())
    finished_cipher = TLSCiphertext.create(finished, crypto=client_traffic_crypto)
    client_conn.send_msg(finished_cipher.to_bytes())
    # messages.append(finished.fragment)
    messages += finished.fragment.to_bytes()

    # data = client_conn.recv_msg()
    # new_session_ticket_ciphe = TLSCiphertext.restore(data, crypto=server_traffic_crypto, mode=ContentType.handshake)
    # print(new_session_ticket_ciphe)


    # <<<   Application Data    >>>

    print("\n\n<<<   Application Data   >>>\n\n")

    client_traffic_data = TLSPlaintext(
        type=ContentType.application_data,
        fragment=Data(b'my name is Eric, I will give your my secret about my lover!'))
    app_data_cipher = TLSCiphertext.create(client_traffic_data, crypto=app_data_crypto)
    print(app_data_cipher)
    time.sleep(3)
    client_conn.send_msg(app_data_cipher.to_bytes())
    print("\n\n <<<   welcome to secret shared   >>>\n\n")
    while True:
        my_message = input("C:")
        client_traffic_data = TLSPlaintext(
            type=ContentType.application_data, fragment=Data(my_message.encode('utf-8')))
        app_data_cipher = TLSCiphertext.create(client_traffic_data, crypto=app_data_crypto)
        # print(app_data_cipher)
        client_conn.send_msg(app_data_cipher.to_bytes())


        data = client_conn.recv_msg()
        print(len(data))
        if len(data) != 0:
            recved_server_data = TLSCiphertext.restore(data,
                    crypto=server_traffic_crypto, mode=ContentType.application_data)
            # print("* [recv] app_data")
            # print(recved_server_data)
            print("S:"+str(recved_server_data.raw))

