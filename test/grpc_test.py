#!/usr/bin/env python3

import grpc
import unittest
import os
from grpc_tools import protoc
import secrets
import binascii

class TestGRPC(unittest.TestCase):
    # Runs once before all tests
    @classmethod
    def setUpClass(cls):
        cur_path = os.path.dirname(os.path.abspath(__file__))
        proto_path = f'{cur_path}/../grpc/'
        proto_file = f'{proto_path}/psp_gateway.proto'
        grpc_out_path = f'{cur_path}/generated_code'

        # Workaround for https://github.com/grpc/grpc/issues/9575
        res = protoc.main([
            'grpc_tools.protoc',
            f'--proto_path={proto_path}',
            f'--python_out={cur_path}',
            f'--pyi_out={cur_path}',
            f'--grpc_python_out={cur_path}',
            proto_file
        ])
        print(f'gRPC code generation completed with exit code {res}.')

        cls.grpc_addr = '10.137.189.69'
        cls.grpc_port = 3000
        print(f"Using gRPC address: {cls.grpc_port}.")

    # Runs before each test
    def setUp(self):
        pass

    def _test_new_tunnel_request(self, request_id):
        # Note: We can't import this globally since it's generated during test setup
        from psp_gateway_pb2 import NewTunnelRequest, TunnelParameters
        from psp_gateway_pb2_grpc import PSP_GatewayStub

        # Create a gRPC channel and a stub
        channel = grpc.insecure_channel(f'{self.grpc_addr}:{self.grpc_port}')
        stub = PSP_GatewayStub(channel)

        tunnel_params = TunnelParameters()
        tunnel_params.mac_addr = "00:0a:95:9d:68:16"
        tunnel_params.ip_addr = "192.168.1.1"
        tunnel_params.psp_version = 1
        tunnel_params.spi = 1234
        tunnel_params.encryption_key = secrets.token_bytes(32)
        tunnel_params.virt_cookie = 5678

        new_tunnel_request = NewTunnelRequest()
        new_tunnel_request.request_id = request_id
        new_tunnel_request.psp_versions_accepted.append(1)
        new_tunnel_request.virt_src_ip = "192.168.1.2"
        new_tunnel_request.virt_dst_ip = "192.168.1.3"
        new_tunnel_request.reverse_params.CopyFrom(tunnel_params)

        # Send the NewTunnelRequest and get a NewTunnelResponse
        response = stub.RequestTunnelParams(new_tunnel_request)
        # print(f'Sent: {binascii.hexlify(tunnel_params.encryption_key).decode()} -> Received:{binascii.hexlify(response.params.encryption_key).decode()}')
        print(f'Received:{binascii.hexlify(response.params.encryption_key).decode()}')

        # Check the response (this depends on what your server sends back)
        # self.assertNotEqual(binascii.hexlify(response.params.encryption_key).decode(), '00' * 32)
        self.assertEqual(response.request_id, request_id)

    def _test_key_rotation_request(self, request_id, issue_new_keys):
    # Note: We can't import this globally since it's generated during test setup
        from psp_gateway_pb2 import KeyRotationRequest
        from psp_gateway_pb2_grpc import PSP_GatewayStub

        # Create a gRPC channel and a stub
        channel = grpc.insecure_channel(f'{self.grpc_addr}:{self.grpc_port}')
        stub = PSP_GatewayStub(channel)

        # Create a KeyRotationRequest
        key_rotation_request = KeyRotationRequest()
        key_rotation_request.request_id = request_id
        key_rotation_request.issue_new_keys = issue_new_keys

        # Send the KeyRotationRequest and get a response
        response = stub.RequestKeyRotation(key_rotation_request)

        # Print the response (this depends on what your server sends back)
        print(f'Received response: {response}')

        # Check the response (this depends on what your server sends back)
        self.assertEqual(response.request_id, request_id)

    # --- End of helpers ---

    def _test_new_tunnel_request_simple(self):
        self._test_new_tunnel_request(1)

    def test_key_rotation_request_simple(self):
        self._test_key_rotation_request(1, True)

if __name__ == '__main__':
    unittest.main()
