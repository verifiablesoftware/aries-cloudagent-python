import asyncio
import base64
import binascii
import hashlib
import json
import logging
import os
import random
import requests
import sys
import time
from urllib.parse import urlparse

from qrcode import QRCode

from aiohttp import ClientError

from uuid import uuid4
from datetime import date

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # noqa

from runners.support.agent import DemoAgent, default_genesis_txns
from runners.support.utils import (
    log_json,
    log_msg,
    log_status,
    log_timer,
    prompt,
    prompt_loop,
    require_indy,
)

CRED_PREVIEW_TYPE = (
    "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/credential-preview"
)
SELF_ATTESTED = os.getenv("SELF_ATTESTED")

LOGGER = logging.getLogger(__name__)

TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))


class VSWAgent(DemoAgent):
    def __init__(
        self,
        http_port: int,
        admin_port: int,
        tails_server_base_url: str = None,
        **kwargs,
    ):
        super().__init__(
            "VSW.Agent",
            http_port,
            admin_port,
            prefix="VSW",
            tails_server_base_url=tails_server_base_url,
            extra_args=["--auto-accept-invites", "--auto-accept-requests"],
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = asyncio.Future()
        self.cred_state = {}
        self.cred_done = asyncio.Future()
        # TODO define a dict to hold credential attributes
        # based on credential_definition_id
        self.cred_attrs = {}
        self.proof_done = asyncio.Future()

    async def detect_connection(self):
        await self._connection_ready

    async def credential_complete(self):
        await self.cred_done

    async def proof_complete(self):
        await self.proof_done

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    async def handle_connections(self, message):
        if message["connection_id"] == self.connection_id:
            if message["state"] == "active" and not self._connection_ready.done():
                self.log("Connected")
                self._connection_ready.set_result(True)

    async def handle_present_proof(self, message):
        state = message["state"]

        presentation_exchange_id = message["presentation_exchange_id"]
        self.log(
            "Presentation: state =",
            state,
            ", presentation_exchange_id =",
            presentation_exchange_id,
        )

        if state == "presentation_received":
            log_status("#27 Process the proof provided by X")
            log_status("#28 Check if proof is valid")
            proof = await self.admin_POST(
                f"/present-proof/records/{presentation_exchange_id}/verify-presentation"
            )
            self.log("Proof =", proof["verified"])

            # if presentation is a vsw schema (app publication),
            # check the values received
            pres = message["presentation"]
            self.log("pres:", pres)
            name = pres['requested_proof']['revealed_attrs']['0_name_uuid']['raw']
            url = pres['requested_proof']['revealed_attrs']['0_url_uuid']['raw']
            digest = pres['requested_proof']['revealed_attrs']['0_digest_uuid']['raw']
            response = requests.get(url, allow_redirects=True)
            if response.status_code != 200:
                print("Failed to download file from URL")
                sys.exit(1)
            computed = hashlib.sha256(response.content).hexdigest()
            if computed != digest:
                print("SHA does not match")
                print(computed)
                sys.exit(1)
            else:
                open(f'vsw/{name}.wasm', 'wb').write(response.content)

            self.log("SUCCESS")
            self.proof_done.set_result(True)

    async def handle_basicmessages(self, message):
        self.log("Received message:", message["content"])


async def main(
    start_port: int,
    name: str,
    show_timing: bool = False,
):

    with open('/home/indy/vsw/.config.json') as f:
        config = json.load(f)

    genesis = await default_genesis_txns()
    if not genesis:
        print("Error retrieving ledger genesis transactions")
        sys.exit(1)

    agent = None

    try:
        log_status("#1 Provision an agent and wallet, get back configuration details")
        agent = VSWAgent(
            start_port,
            start_port + 1,
            genesis_data=genesis,
            timing=show_timing,
        )
        await agent.listen_webhooks(start_port + 2)
        # FIXME: This user should not have to publish their DID, but if I remove the next line it fails
        await agent.register_did()

        with log_timer("Startup duration:"):
            await agent.start_process()
        log_msg("Admin URL is at:", agent.admin_url)
        log_msg("Endpoint URL is at:", agent.endpoint)

        # Connect to repo
        log_status("#9 Connect to repo")
        connection = await agent.admin_POST("/connections/receive-invitation", config['invitation'])
        agent.connection_id = connection["connection_id"]
        log_json(connection, label="Invitation response:")

        await agent.detect_connection()

        log_status("#20 Request app credential from repo")
        req_attrs = [
            {
                "name": "name",
                "value": name,
                "restrictions": [{"schema_name": "vsw schema"}]
            },
            {
                "name": "url",
                "restrictions": [{"schema_name": "vsw schema"}]
            },
            {
                "name": "digest",
                "restrictions": [{"schema_name": "vsw schema"}]
            }
        ]
        req_preds = []
        indy_proof_request = {
            "name": "Retrieve by Name",
            "version": "1.0",
            "nonce": str(uuid4().int),
            "requested_attributes": {
                f"0_{req_attr['name']}_uuid": req_attr
                for req_attr in req_attrs
            },
            "requested_predicates": {}
        }
        proof_request_web_request = {
            "connection_id": agent.connection_id,
            "proof_request": indy_proof_request
        }

        # this sends the request to our agent, which forwards it to the repo
        # (based on the connection_id)
        await agent.admin_POST(
            "/present-proof/send-request",
            proof_request_web_request
        )

        await agent.proof_complete()

    finally:
        terminated = True
        try:
            if agent:
                await agent.terminate()
        except Exception:
            LOGGER.exception("Error terminating agent:")
            terminated = False

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Runs a VSW agent.")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8050,
        metavar=("<port>"),
        help="Choose the starting port number to listen on",
    )

    parser.add_argument(
        "--timing", action="store_true", help="Enable timing information"
    )

    parser.add_argument("name", type=str, help="name of app to install")

    args = parser.parse_args()

    ENABLE_PYDEVD_PYCHARM = os.getenv("ENABLE_PYDEVD_PYCHARM", "").lower()
    ENABLE_PYDEVD_PYCHARM = ENABLE_PYDEVD_PYCHARM and ENABLE_PYDEVD_PYCHARM not in (
        "false",
        "0",
    )
    PYDEVD_PYCHARM_HOST = os.getenv("PYDEVD_PYCHARM_HOST", "localhost")
    PYDEVD_PYCHARM_CONTROLLER_PORT = int(
        os.getenv("PYDEVD_PYCHARM_CONTROLLER_PORT", 5001)
    )

    if ENABLE_PYDEVD_PYCHARM:
        try:
            import pydevd_pycharm

            print(
                "VSW remote debugging to "
                f"{PYDEVD_PYCHARM_HOST}:{PYDEVD_PYCHARM_CONTROLLER_PORT}"
            )
            pydevd_pycharm.settrace(
                host=PYDEVD_PYCHARM_HOST,
                port=PYDEVD_PYCHARM_CONTROLLER_PORT,
                stdoutToServer=True,
                stderrToServer=True,
                suspend=False,
            )
        except ImportError:
            print("pydevd_pycharm library was not found")

    require_indy()

    try:
        asyncio.get_event_loop().run_until_complete(
            main(
                args.port,
                args.name,
                args.timing,
            )
        )
    except KeyboardInterrupt:
        os._exit(1)
