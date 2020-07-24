#!/usr/bin/env python3

from asyncio import run as asyncio_run, gather as asyncio_gather
from typing import List, Union, Callable, Optional, Collection
from argparse import Action as ArgparseAction, ArgumentParser, Namespace as ArgparseNamespace
from pathlib import PureWindowsPath
from re import compile as re_compile, Pattern as RePattern, error as re_error
from ipaddress import IPv4Address, IPv6Address
from sys import stderr
from logging import getLogger, WARNING, StreamHandler

from msdsalgs.fscc.file_information import FileInformation
from smb.transport import TCPIPTransport
from smb.v2.connection import Connection as SMBv2Connection
from smb.v2.session import Session
from smb.v2.messages.query_directory import FileInformationClass, FileDirectoryInformation, QueryDirectoryFlag
from smb.contrib.argument_parsers import SmbSingleAuthenticationArgumentParser
from ms_srvs.structures.share_type import DiskTree
from msdsalgs.ntstatus_value import NTStatusValueError, StatusLogonFailureError

from enumerate_smb_shares import enumerate_smb_shares

LOG = getLogger(__name__)


async def enumerate_smb_share_files(
    smb_connection: SMBv2Connection,
    smb_session: Session,
    tree_id: int,
    root_path: Union[str, PureWindowsPath] = '',
    num_max_concurrent: int = 10,
    per_file_callback: Optional[Callable[[PureWindowsPath, FileInformation, SMBv2Connection, Session, int], bool]] = None
) -> None:
    """
    Enumerate files in an SMB share.

    By default, the the share is enumerated from its root and all descendant directories are enumerated recursively. The
    `per_file_callback` allows one to inspect each enumerated file as they are encountered and -- in the case of
    directories -- make a decision whether to enumerate it.

    :param smb_connection: An SMB connection with access to the share whose files are to be enumerated.
    :param smb_session: An SMB session with access to the share whose files are to be enumerated.
    :param tree_id: The tree id of the share whose files are to be enumerated.
    :param root_path: The root path from which to enumerate files.
    :param num_max_concurrent: The maximum number of concurrent tasks.
    :param per_file_callback: A callback function that inspects paths and determines whether to enumerate them.
    :return: None
    """

    async def scan_directory(path: PureWindowsPath) -> List[FileDirectoryInformation]:
        """
        Scan a directory in an SMB share and provide information about its contents.

        :param path: The path of the directory to be scanned.
        :return: A list of the path's file and directory information entries.
        """

        async with smb_connection.create_dir(path=path, session=smb_session, tree_id=tree_id) as create_response:
            return await smb_connection.query_directory(
                file_id=create_response.file_id,
                file_information_class=FileInformationClass.FileIdFullDirectoryInformation,
                query_directory_flag=QueryDirectoryFlag(),
                file_name_pattern='*',
                session=smb_session,
                tree_id=tree_id
            )

    def default_per_file_callback(entry_path: PureWindowsPath, *_) -> bool:
        """
        Print each encountered file's path and decide to enumerate an encountered directory.

        :param entry_path: The path of an encountered file in an SMB share.
        :return: Whether to enumerate an encountered directory. Always `True`.
        """
        print(entry_path)
        return True

    per_file_callback = per_file_callback or default_per_file_callback

    paths_to_scan: List[Union[PureWindowsPath, str]] = [root_path]

    while paths_to_scan:
        num_remaining_paths = len(paths_to_scan)
        paths_to_scan_in_iteration = [paths_to_scan.pop() for _ in range(min(num_remaining_paths, num_max_concurrent))]
        scan_results: List[Union[List[FileDirectoryInformation], Exception]] = await asyncio_gather(
            *[scan_directory(path) for path in paths_to_scan_in_iteration],
            return_exceptions=True
        )

        for directory_path, scan_result in zip(paths_to_scan_in_iteration, scan_results):
            if isinstance(scan_result, Exception):
                LOG.error(f'{scan_result} -- Directory path: {directory_path}.')
                continue

            file_directory_information_list: List[FileDirectoryInformation] = scan_result
            for entry in file_directory_information_list:
                if entry.file_name in {'.', '..'}:
                    continue

                entry_path: PureWindowsPath = PureWindowsPath(directory_path) / entry.file_name
                should_scan: bool = per_file_callback(
                    entry_path,
                    entry.file_information,
                    smb_connection,
                    smb_session,
                    tree_id
                )

                if entry.file_information.file_attributes.directory and should_scan:
                    paths_to_scan.append(entry_path)


async def pre_enumerate_smb_share_files(
    address: Union[str, IPv4Address, IPv6Address],
    username: str,
    authentication_secret: Union[str, bytes],
    share_names: Collection[str],
    root_path: Union[str, PureWindowsPath] = '',
    path_pattern: RePattern = re_compile(pattern='.*'),
    port_number: int = 445
):

    async with TCPIPTransport(address=address, port_number=port_number) as tcp_ip_transport:
        async with SMBv2Connection(tcp_ip_transport=tcp_ip_transport) as smb_connection:
            await smb_connection.negotiate()
            async with smb_connection.setup_session(username=username, authentication_secret=authentication_secret) as smb_session:

                if len(share_names) == 0:
                    share_names: List[str] = [
                        share_info_1_entry.netname
                        for share_info_1_entry in await enumerate_smb_shares(
                            smb_connection=smb_connection,
                            smb_session=smb_session
                        )
                        if isinstance(share_info_1_entry.share_type, DiskTree)
                    ]

                for share_name in share_names:
                    try:
                        async with smb_connection.tree_connect(share_name=share_name, session=smb_session) as (tree_id, _):

                            def print_paths(entry_path: PureWindowsPath, *_, **__) -> bool:
                                if path_pattern.search(string=str(entry_path)):
                                    print(f'\\\\{address}\\{share_name}\\{entry_path}')
                                return True

                            await enumerate_smb_share_files(
                                smb_connection=smb_connection,
                                smb_session=smb_session,
                                tree_id=tree_id,
                                root_path=root_path,
                                per_file_callback=print_paths
                            )
                    except NTStatusValueError as e:
                        LOG.error(f'{e} User: {username}. Share name: {share_name}.')


class _ParsePattern(ArgparseAction):
    def __call__(self, parser: ArgumentParser, namespace: ArgparseNamespace, pattern: str, option_string: str = None):

        try:
            re_pattern: RePattern = re_compile(pattern=pattern)
            setattr(namespace, self.dest, re_pattern)
        except re_error:
            parser.error(f'Bad regex pattern: {pattern}')


class EnumerateSMBShareFilesArgumentParser(SmbSingleAuthenticationArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__()
        self.add_argument(
            'target_address',
            type=str,
            metavar='TARGET_ADDRESS',
            help='The address of the SMB server whose share files to be enumerated.'
        )

        self.add_argument(
            'share_names',
            type=str,
            nargs='*',
            metavar='SHARE_NAME',
            help='A list of names of shares to enumerate. Defaults to all disk shares if none are specified.'
        )

        self.add_argument(
            '--root-path',
            type=str,
            metavar='ROOT_PATH',
            help='A path from where to start the enumeration in the shares',
            default=''
        )

        self.add_argument(
            '--pattern',
            action=_ParsePattern,
            metavar='PATTERN',
            help='A regular expression pattern that is tested on file names to determine whether they should be saved.',
            default=re_compile('.*')
        )


async def main():
    args = EnumerateSMBShareFilesArgumentParser().parse_args()

    LOG.setLevel(level=WARNING)
    LOG.addHandler(StreamHandler(stderr))

    try:
        await pre_enumerate_smb_share_files(
            address=args.target_address,
            username=args.username,
            authentication_secret=args.password or bytes.fromhex(args.nt_hash),
            share_names=args.share_names,
            root_path=args.root_path,
            path_pattern=args.pattern
        )
    except StatusLogonFailureError as e:
        LOG.error(f'{e} -- Username: {args.username}, Authentication secret: {args.password or args.nt_hash}.')

if __name__ == '__main__':
    asyncio_run(main())
