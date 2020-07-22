#!/usr/bin/env python3

from asyncio import run as asyncio_run
from argparse import Namespace as ArgparseNamespace
from typing import Union, Tuple
from ipaddress import IPv4Address, IPv6Address
from dataclasses import is_dataclass, asdict
from json import dumps as json_dumps

from smb.transport import TCPIPTransport
from smb.v2.connection import Connection as SMBv2Connection
from smb.contrib.argument_parsers import SmbSingleAuthenticationArgumentParser
from rpc.connection import Connection as RPCConnection
from rpc.structures.context_list import ContextList, ContextElement
from ms_srvs import MS_SRVS_ABSTRACT_SYNTAX, MS_SRVS_PIPE_NAME
from ms_srvs.operations.netr_share_enum import netr_share_enum, NetrShareEnumRequest
from ms_srvs.structures.share_info_container import ShareInfo1Container, ShareInfo1


def default_json_serializer(obj):
    if is_dataclass(obj):
        return asdict(obj)
    else:
        raise TypeError


async def enumerate_smb_shares(
    address: Union[str, IPv4Address, IPv6Address],
    username: str,
    authentication_secret: Union[str, bytes],
    port_number: int = 445
) -> Tuple[ShareInfo1, ...]:
    """
    Enumerate the SMB shares of an SMB server.

    :param address: An address of an SMB server whose shares to enumerate.
    :param username: A username to be used when authenticating with the SMB server.
    :param authentication_secret: An authentication secret to be used when authenticating with the SMB server. Either a
        password or NT hash.
    :param port_number: A port number that the SMB server listens on.
    :return: A collection of `ShareInfo1` structures, conveying SMB share information.
    """

    async with TCPIPTransport(address=address, port_number=port_number) as tcp_ip_transport:
        async with SMBv2Connection(tcp_ip_transport=tcp_ip_transport) as smb_connection:
            await smb_connection.negotiate()
            async with smb_connection.setup_session(username=username, authentication_secret=authentication_secret) as smb_session:
                async with smb_connection.make_smbv2_transport(session=smb_session, pipe=MS_SRVS_PIPE_NAME) as (r, w):
                    async with RPCConnection(reader=r, writer=w) as rpc_connection:
                        await rpc_connection.bind(
                            presentation_context_list=ContextList([
                                ContextElement(context_id=0, abstract_syntax=MS_SRVS_ABSTRACT_SYNTAX)
                            ])
                        )

                        share_info_container = (
                            await netr_share_enum(
                                rpc_connection=rpc_connection,
                                request=NetrShareEnumRequest(level=1)
                            )
                        ).info_struct.share_info

                        if not isinstance(share_info_container, ShareInfo1Container):
                            raise ValueError('Bad share info container type.')

                        return share_info_container.entries


# TODO: Support multiple targets.
# TODO: Support change of port number?
class EnumerateSMBShareArgumentParser(SmbSingleAuthenticationArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__()
        self.add_argument(
            'target_address',
            type=str,
            metavar='TARGET_ADDRESS'
        )

        self.add_argument(
            '--json',
            action='store_true'
        )


async def main():
    args: ArgparseNamespace = EnumerateSMBShareArgumentParser().parse_args()
    share_entries: Tuple[ShareInfo1, ...] = await enumerate_smb_shares(
        address=args.target_address,
        username=args.username,
        authentication_secret=args.password or bytes.fromhex(args.nt_hash)
    )

    if args.json:
        print(json_dumps(share_entries, default=default_json_serializer))
    else:
        print(
            '\n\n'.join([
                f'Name: {entry.netname}\n'
                f'Type: {entry.share_type}\n'
                f'Remark: {entry.remark}'
                for entry in share_entries
            ])
        )


if __name__ == '__main__':
    asyncio_run(main())
