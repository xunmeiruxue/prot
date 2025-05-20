# Linux how to:
#   python3 -m venv proton-vpn-wireguard-downloader
#   pushd proton-vpn-wireguard-downloader
#   wget {{ zip url for this gist }} -O proton-vpn-wireguard-downloader.zip
#   wget "https://github.com/ProtonVPN/python-proton-core/archive/refs/tags/v0.2.0.zip" -O python-proton-core-0.2.0.zip
#   wget "https://github.com/ProtonVPN/python-proton-vpn-logger/archive/refs/tags/v0.2.1.zip" -O python-proton-vpn-logger.0.2.1.zip
#   wget "https://github.com/ProtonVPN/python-proton-vpn-api-core/archive/refs/tags/v0.32.2.zip" -O python-proton-vpn-api-core.0.32.2.zip
#   unzip -j proton-vpn-wireguard-downloader.zip
#   unzip python-proton-core-0.2.0.zip
#   unzip python-proton-vpn-logger.0.2.1.zip
#   unzip python-proton-vpn-api-core.0.32.2.zip
#   cp -a python-proton-core-0.2.0/proton  .
#   cp -a python-proton-vpn-logger-0.2.1/proton .
#   cp -a python-proton-vpn-api-core-0.32.2/proton .
#   rm proton-vpn-wireguard-downloader.zip python-proton-core-0.2.0.zip python-proton-vpn-api-core.0.32.2.zip python-proton-vpn-logger.0.2.1.zip
#   rm -rf python-proton-core-0.2.0 python-proton-vpn-logger-0.2.1 python-proton-vpn-api-core-0.32.2
#   source bin/activate
#   pip install bcrypt pynacl cryptography distro jinja2 aiohttp pyopenssl python-gnupg requests
#
#   TO CREATE A SINGLE EXECUTABLE:
#     pip install pyinstaller
#     pyinstaller --onefile ./proton-vpn-wireguard-downloader.py
#     EXECUTABLE FILE is at dist/proton-vpn-wireguard-downloader
#
#   deactivate
#   popd

import argparse
import asyncio
import logging
import re
import base64
import hashlib
import random
import distro
import logging
import sys
import traceback
from typing import cast
from pathlib import Path
from datetime import datetime, timezone

from proton.vpn.session.servers.types import ServerFeatureEnum
from proton.loader import Loader
from proton.session.transports.aiohttp import AiohttpTransport
from proton.keyring.textfile import KeyringBackendJsonFiles
from proton.session.environments import ProdEnvironment
from proton.vpn.session.session import VPNSession
from proton.sso import ProtonSSO


PROTONVPN_VERSION = "4.4.4"
PROTONVPN_APP_VERSION = f"LinuxVPN_{PROTONVPN_VERSION}"
USER_AGENT = (f"ProtonVPN/{PROTONVPN_VERSION} (Linux; {distro.name()}/{distro.version()})")


class InternalServerItem:
    name: str
    deviceName: str
    entryIp: str
    exitIp: str
    publicKey: str


class ProtonVpnConfigDownloader:
    async def login(self, username: str, password: str) -> VPNSession:
        self.logger.info("Logging in to ProtonVPN...")

        sso = ProtonSSO(user_agent = USER_AGENT, appversion = PROTONVPN_APP_VERSION)

        session = cast(VPNSession, sso.get_session(username, override_class = VPNSession))

        self.logger.info("Authenticating credentials with ProtonVPN")

        login_result = await session.login(username, password)
        if not login_result.authenticated:
            raise Exception("Authentication credentials are invalid")

        if login_result.twofa_required:
            twofa_code = input("Enter 2FA code for account: ")
            self.logger.info("Verifying 2FA code...")
            login_result = await session.provide_2fa(twofa_code)
            if login_result.twofa_required:
                raise Exception("Invalid 2FA code")

        if not login_result.success:
            raise Exception("Unable to authenticate to ProtonVPN")

        self.logger.info("Fetching client session data")

        await session.fetch_session_data()

        self.logger.info("Logged in to ProtonVPN")

        return session

    async def logout(self, session: VPNSession) -> None:
        if session.authenticated:
            self.logger.info("Logging out...")
            await session.async_logout()

        self.logger.info("Logged out from ProtonVPN")

    # async def revokeConfig(self, session: VPNSession, serialNumber: str):
    #     self.logger.info(f"Revoking config {serialNumber}...")
    #     response = await session.async_api_request(
    #         "/api/vpn/v1/certificate",
    #         jsondata = { "SerialNumber": serialNumber },
    #         method = "DELETE",
    #     )
    #     self.logger.debug(f"config revoke response: {response}")
    #     return (not "Count" in response)

    def getPrivateX25519(self, privateKey):
        hash__ = hashlib.sha512(base64.b64decode(privateKey)[-32:]).digest()
        hash_ = list(hash__)[:32]
        hash_[0] &= 0xf8
        hash_[31] &= 0x7f
        hash_[31] |= 0x40
        newKey = base64.b64encode(bytes(hash_)).decode()
        return newKey

    async def getKeyPair(self, session: VPNSession):
        self.logger.info("Getting key-pair...")

        response = await session.async_api_request("/api/vpn/v1/certificate/key/EC")

        self.logger.debug(f"key pair response: {response}")

        if ((not "PrivateKey" in response) or (not "PublicKey" in response)):
            return []

        privateKey = response["PrivateKey"].split("\n")[1]
        publicKey = response["PublicKey"].split("\n")[1]
        privateKeyWireguard = self.getPrivateX25519(privateKey)

        self.logger.debug(f"got private key: {privateKey} to wireguard format: {privateKeyWireguard}")
        self.logger.debug(f"got public key: {publicKey}")

        return [ publicKey,  privateKeyWireguard ]

    async def generateConfig(self, server, keys, serialNumber, args):
        configText = """[Interface]
# Key for {serverDeviceName}
# Session only = {session}
# Serial Number = {serialnumber}
# Non-standard ports = {safemode}
# NetShield = {netshieldlevel}
# Moderate NAT = {moderatenat}
# NAT-PMP (Port Forwarding) = {portforwarding}
# VPN Accelerator = {accelerator}
PrivateKey = {clientPrivateKey}
Address = 10.2.0.2/32
DNS = 10.2.0.1
[Peer]
# {servername}
PublicKey = {serverPublicKey}
AllowedIPs = 0.0.0.0/0
Endpoint = {serverEntryIp}:51820
""".format(
            serverDeviceName = server.deviceName,
            session = args.session,
            serialnumber = serialNumber,
            safemode = args.safemode,
            netshieldlevel = args.netshieldlevel,
            moderatenat = args.moderatenat,
            portforwarding = args.portforwarding,
            accelerator = args.accelerator,
            clientPrivateKey = keys[1],
            servername = server.name,
            serverPublicKey = server.publicKey,
            serverEntryIp = server.entryIp,
        )

        self.logger.debug(f"Config file contents: {configText}")

        # 创建配置目录
        config_dir = Path(args.dir) / "protonvpn_configs"
        config_dir.mkdir(exist_ok=True)
        
        # 写入文件
        path = config_dir / f"{server.deviceName}.conf"
        print(f"file: {path}")

        path.write_text(configText, encoding="utf-8")

    async def registerConfig(self, session: VPNSession, server, keys, args):
        body = {
            "ClientPublicKey": keys[0],
            "DeviceName": server.deviceName,
            "Features": {
                "peerName": server.name,
                "peerIp": server.entryIp,
                "peerPublicKey": server.publicKey,
                "platform": "Linux",
                "SafeMode": args.netshieldlevel,
                "SplitTCP": args.accelerator,
                "PortForwarding": args.portforwarding,
                "RandomNAT": not args.moderatenat,
                "NetShieldLevel": args.netshieldlevel
            }
        }

        if (args.session):
            body["Mode"] = "session"
        else:
            body["Mode"] = "persistent"
            body["ExpirationTime"] = (round(datetime.now(timezone.utc).timestamp()) + (args.expirehours * 60 * 60))

        self.logger.debug(f"Registration request: {body}")

        response = await session.async_api_request("/api/vpn/v1/certificate", jsondata = body)

        self.logger.debug(f"Registration response: {response}")

        if ("SerialNumber" in response):
            return response["SerialNumber"]

        return ""

    async def getServers(self, session: VPNSession, args):
        self.logger.info("Fetching available VPN servers for client...")

        client_config = session.client_config
        if (args.port not in client_config.wireguard_ports.udp):
            raise ValueError(f"Port {args.port} is not available in client config.")

        server_features = args.features or set()

        logicalServers = (
            server
            for server in session.server_list.logicals
            if server.enabled
            and (not args.freetier and server.tier > 0)
            and (server.tier <= session.server_list.user_tier)
            and (server.load <= args.threshold)
            and ((args.entrycountrycode is None or len(args.entrycountrycode) == 0) or
                 (server.entry_country in args.entrycountrycode))
            and ((args.exitcountrycode is None or len(args.exitcountrycode) == 0) or
                 (server.exit_country in args.exitcountrycode))
            and (len(server_features) <= len(server.features))
            and (len(server_features & set(server.features)) == len(server_features))
        )

        servers = list()
        for logicalServer in logicalServers:
            self.logger.debug(f"logical server: {vars(logicalServer)}")

            for physicalServer in logicalServer.physical_servers:
                self.logger.debug(f"physical server: {vars(logicalServer)}")

                newServer = InternalServerItem()
                newServer.name = logicalServer.name
                newServer.deviceName = f"{args.prefix}{re.sub(r'[^A-Za-z0-9]', '', newServer.name)}"
                newServer.entryIp = physicalServer.entry_ip
                newServer.exitIp = physicalServer.exit_ip
                newServer.publicKey = physicalServer.x25519_pk

                self.logger.debug(f"internal server info: {vars(newServer)}")

                servers.append(newServer)

        self.logger.info(f"Got {len(servers)} matching servers")

        # random list order
        if (args.random):
            self.logger.info("Servers to random order")
            random.shuffle(servers)

        # truncate to limit
        if (args.limit != -1):
            self.logger.info(f"Server list truncated to {args.limit}")
            servers = servers[:args.limit]

        return servers

    async def fetch_existing_certificates(self, session: VPNSession):
        """获取现有的证书列表"""
        self.logger.info("Fetching existing certificates...")
        response = await session.async_api_request(
            "/api/vpn/v1/certificate/all",
            params = {
                "Mode": "persistent",
                "Offset": 0,
                "Limit": 51
            }
        )
        self.logger.debug(f"Fetched certificates response: {response}")
        return response.get("Certificates", [])

    async def renew_certificate(self, session: VPNSession, cert, args):
        """续订证书"""
        self.logger.info(f"Renewing certificate for {cert['DeviceName']}...")
        
        # 生成新的密钥对
        keys = await self.getKeyPair(session)
        if len(keys) < 2:
            self.logger.error("Failed to generate new key pair")
            return False

        body = {
            "ClientPublicKey": keys[0],
            "Mode": "persistent",
            "DeviceName": cert["DeviceName"],
            "Features": {
                "peerName": cert["Features"]["peerName"],
                "peerIp": cert["Features"]["peerIp"],
                "peerPublicKey": cert["Features"]["peerPublicKey"],
                "platform": "Linux",
                "SafeMode": args.netshieldlevel,
                "SplitTCP": args.accelerator,
                "PortForwarding": args.portforwarding,
                "RandomNAT": not args.moderatenat,
                "NetShieldLevel": args.netshieldlevel
            },
            "Renew": True
        }

        if args.session:
            body["Mode"] = "session"
        else:
            body["ExpirationTime"] = (round(datetime.now(timezone.utc).timestamp()) + (args.expirehours * 60 * 60))

        self.logger.debug(f"Renewal request body: {body}")
        
        response = await session.async_api_request("/api/vpn/v1/certificate", jsondata=body)
        self.logger.debug(f"Renewal response: {response}")

        if "SerialNumber" in response:
            # 创建新的服务器对象
            server = InternalServerItem()
            server.name = cert["Features"]["peerName"]
            server.deviceName = cert["DeviceName"]
            server.entryIp = cert["Features"]["peerIp"]
            server.publicKey = cert["Features"]["peerPublicKey"]
            
            # 生成新的配置文件
            await self.generateConfig(server, keys, response["SerialNumber"], args)
            return True
        
        return False

    async def run(self, args):
        retVal = 0

        # if session-scoped configs is set, do not log out of session
        if (args.session):
            args.nologout = True

        session = await self.login(args.username, args.password)
        try:
            if args.extend:
                self.logger.info("Renewing existing certificates...")
                existing_certificates = await self.fetch_existing_certificates(session)
                
                for cert in existing_certificates:
                    if await self.renew_certificate(session, cert, args):
                        self.logger.info(f"Successfully renewed certificate for {cert['DeviceName']}")
                        # 添加60秒延迟以避免API限制
                        await asyncio.sleep(60)
                    else:
                        self.logger.error(f"Failed to renew certificate for {cert['DeviceName']}")
            elif (args.limit != 0):
                # revoke configs
                # unfortunately the https://vpn-api.proton.me api doesn't seem to give scope for revoking configs
                # if (len(args.revokeconfig) > 0):
                #     self.logger.info("Revoke configs")
                #     for serialNumber in args.revokeconfig:
                #         await self.revokeConfig(session, serialNumber)
                # else:
                    # provision configs
                    self.logger.info("Provision configs")
                    for server in await self.getServers(session, args):
                        if (args.list):
                            # listing only
                            print(f"config: {server.deviceName} {server.name} {server.entryIp} {server.exitIp} {server.publicKey}")
                        else:
                            # get unique keys for each server
                            keys = await self.getKeyPair(session)
                            if (len(keys) < 2):
                                self.logger.error("failed getting key pair")
                            else:
                                serialNumber = await self.registerConfig(session, server, keys, args)
                                if (serialNumber == ""):
                                    self.logger.error(f"failed to register server {server.name}")
                                else:
                                    await self.generateConfig(server, keys, serialNumber, args)
                                    # 添加60秒延迟以避免API限制
                                    await asyncio.sleep(60)
        except Exception as e:
            self.logger.error(f"exception: {e}")
            self.logger.error(traceback.format_exc())
            retVal = 2
        finally:
            if (not args.nologout):
                await self.logout(session)

        return retVal

    def parseFeatures(self, features: list[str]) -> set[ServerFeatureEnum]:
        if (features is None):
            return list()

        features_map = {
            "secure-core": ServerFeatureEnum.SECURE_CORE,
            "tor": ServerFeatureEnum.TOR,
            "p2p": ServerFeatureEnum.P2P,
            "streaming": ServerFeatureEnum.STREAMING,
            "ipv6": ServerFeatureEnum.IPV6,
        }

        try:
            return {
                features_map[feature.strip().lower()]
                for feature in features
            }
        except KeyError as e:
            raise ValueError(f"{e.args[0]} is not a supported feature.") from e

    def parseThreshold(self, threshold: str) -> int:
        try:
            score = int(threshold)
        except ValueError as e:
            raise TypeError(f"{e.args[0]} is not a valid number") from e

        if (score > 100):  # noqa: PLR2004
            raise ValueError("threshold cannot be greater than 100")

        return score

    def main(self):
        retVal = 0

        try:
            parser = argparse.ArgumentParser()

            parser.add_argument("-u", "--username", help = "Username for proton vpn account", required = True)
            parser.add_argument("-p", "--password", help = "Password for proton vpn account", required = True)
            parser.add_argument("-l", "--list", help = "List only", action = "store_true")
            parser.add_argument("-d", "--dir", help = "Directory to create config files in. Default is '.'", default = ".")
            parser.add_argument("-r", "--prefix", help = "Prefix to apply to wireguard config file names. Default is 'wg' ", default = "wg")
            parser.add_argument("-t", "--port", help = "Wireguard port. ie 443, 88, 1224, 51820 (default), 500 or 4500", default = 51820, type = int)
            parser.add_argument("-v", "--verbose", help = "Verbosity level. 0 = no info or debug (default), 1 = info, 2 = debug", default = 0, type = int)
            parser.add_argument("-f", "--feature", help = "Require a server feature. Secure-core, Tor, P2P, Ipv6 or Streaming. Can specify multiple", action = "append")
            parser.add_argument("-e", "--entrycountrycode", help = "Country code for entry server. Can specify multiple", action="append")
            parser.add_argument("-x", "--exitcountrycode", help = "Country code for exit server. Can specify multiple", action="append")
            parser.add_argument("-s", "--netshieldlevel", help = "Enable NetShield. 0 = No (default), 1 = Block malware, 2 = Block malware, ads and trackers", default = 0)
            parser.add_argument("-a", "--safemode", help = "Enable safe mode / non-standard ports", action = "store_true")
            parser.add_argument("-n", "--moderatenat", help = "Enable moderate NAT", action = "store_true")
            parser.add_argument("-o", "--portforwarding", help = "Enable natpmp port forwarding", action = "store_true")
            parser.add_argument("-c", "--accelerator", help = "Disable vpn accelerator", action = "store_false")
            parser.add_argument("-i", "--limit", help = "Maximum server configs to create. Use limit 0 to just deprovision session-scoped configs", default = -1, type = int)
            parser.add_argument("-m", "--random", help = "Randomly select servers from list", action = "store_true")
            parser.add_argument("-j", "--threshold", help = "Select servers where load is below the score (1-100)", type = self.parseThreshold, default = 100, metavar="score")
            parser.add_argument("-z", "--expirehours", help = "Config expiry in seconds. Default 365 x 24 hours", default = (24 * 365), type = int)
            parser.add_argument("-q", "--freetier", help = "Include free tier servers", action = "store_true")
            parser.add_argument("-b", "--session", help = "Create session-scoped configs. Implies --nologout so session-scoped configs stay active", action = "store_true")
            parser.add_argument("-g", "--nologout", help = "Do not log out of session. ie keep existing session-scoped configs active", action = "store_true")
            parser.add_argument("--extend", help = "Renew existing certificates", action = "store_true")
            # parser.add_argument("-k", "--revokeconfig", help = "Revoke configuration. Can specify multiple", action = "append", metavar="serialnumber")

            args = parser.parse_args()

            args.features = self.parseFeatures(args.feature)

            self.logger = logging.getLogger("proton-vpn-wireguard-downloader")

            if (args.verbose == 0):
                self.logger.setLevel(logging.ERROR)
            elif (args.verbose == 1):
                self.logger.setLevel(logging.INFO)
            else:
                self.logger.setLevel(logging.DEBUG)

            if not self.logger.hasHandlers():
                handler = logging.StreamHandler()
                handler.setFormatter(logging.Formatter("[%(asctime)s: %(levelname)s] %(message)s"))
                self.logger.addHandler(handler)

            self.logger.debug(f"args: {args}")

            Loader.set_all("transport", { "AiohttpTransport": AiohttpTransport })
            self.logger.debug("configured aiohttp as transport")
            Loader.set_all("keyring", { "KeyringBackendJsonFiles": KeyringBackendJsonFiles })
            self.logger.debug("configured keyringbackendjsonfiles as keyring")
            Loader.set_all("environment", { "prod": ProdEnvironment })
            self.logger.debug("configured prodenvironment as environment")

            retVal = asyncio.run(self.run(args))
        except Exception as e:
            print(f"exception: {e}")
            print(traceback.format_exc())
            retVal = 1

        return retVal


if __name__ == "__main__":
    sys.exit(ProtonVpnConfigDownloader().main())