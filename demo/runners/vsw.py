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

    async def detect_connection(self):
        await self._connection_ready

    async def credential_complete(self):
        await self.cred_done

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    async def handle_connections(self, message):
        if message["connection_id"] == self.connection_id:
            if message["state"] == "active" and not self._connection_ready.done():
                self.log("Connected")
                self._connection_ready.set_result(True)

    async def handle_issue_credential(self, message):
        state = message["state"]
        credential_exchange_id = message["credential_exchange_id"]
        self.log(
            "Credential: state = {}, credential_exchange_id = {}".format(
                state, credential_exchange_id,
            )
        )
        prev_state = self.cred_state.get(credential_exchange_id)
        if prev_state == state:
            return  # ignore
        self.cred_state[credential_exchange_id] = state

        self.log(
            "Credential: state = {}, credential_exchange_id = {}".format(
                state, credential_exchange_id,
            )
        )

        if state == "request_received":
            log_status("#17 Issue credential to X")
            # issue credentials based on the credential_definition_id
            cred_attrs = self.cred_attrs[message["credential_definition_id"]]
            cred_preview = {
                "@type": CRED_PREVIEW_TYPE,
                "attributes": [
                    {"name": n, "value": v} for (n, v) in cred_attrs.items()
                ],
            }
            try:
                cred_ex_rec = await self.admin_POST(
                    f"/issue-credential/records/{credential_exchange_id}/issue",
                    {
                        "comment": (
                            f"Issuing credential, exchange {credential_exchange_id}"
                        ),
                        "credential_preview": cred_preview,
                    },
                )
                rev_reg_id = cred_ex_rec.get("revoc_reg_id")
                cred_rev_id = cred_ex_rec.get("revocation_id")
                if rev_reg_id:
                    self.log(f"Revocation registry ID: {rev_reg_id}")
                if cred_rev_id:
                    self.log(f"Credential revocation ID: {cred_rev_id}")
            except ClientError:
                pass
        if state == "credential_acked":
            self.cred_done.set_result(True)

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

    async def handle_basicmessages(self, message):
        self.log("Received message:", message["content"])


async def input_invitation(agent):
    async for details in prompt_loop("Repo invite details: "):
        b64_invite = None
        try:
            url = urlparse(details)
            query = url.query
            if query and "c_i=" in query:
                pos = query.index("c_i=") + 4
                b64_invite = query[pos:]
            else:
                b64_invite = details
        except ValueError:
            b64_invite = details

        if b64_invite:
            try:
                padlen = 4 - len(b64_invite) % 4
                if padlen <= 2:
                    b64_invite += "=" * padlen
                invite_json = base64.urlsafe_b64decode(b64_invite)
                details = invite_json.decode("utf-8")
            except binascii.Error:
                pass
            except UnicodeDecodeError:
                pass

        if details:
            try:
                json.loads(details)
                break
            except json.JSONDecodeError as e:
                log_msg("Invalid invitation:", str(e))

    with log_timer("Connect duration:"):
        connection = await agent.admin_POST("/connections/receive-invitation", details)
        agent.connection_id = connection["connection_id"]
        log_json(connection, label="Invitation response:")

        await agent.detect_connection()


async def register_creddef(
    agent,
    schema_id,
    support_revocation: bool = False,
    revocation_registry_size: int = None,
):
    # Create a cred def for the schema
    credential_definition_body = {
        "schema_id": schema_id,
        "support_revocation": support_revocation,
        "revocation_registry_size": revocation_registry_size,
    }
    credential_definition_response = await agent.admin_POST(
        "/credential-definitions", credential_definition_body
    )
    credential_definition_id = credential_definition_response[
        "credential_definition_id"
    ]
    log_msg("Cred def ID:", credential_definition_id)
    return credential_definition_id


async def main(
    name: str,
    start_port: int,
    revocation: bool = False,
    tails_server_base_url: str = None,
    show_timing: bool = False,
):

    with open('/home/indy/vsw/.config.json') as f:
        config = json.load(f)

    url = await prompt("URL: ")
    digest = await prompt("Digest: ")

    response = requests.get(url, allow_redirects=True)
    if response.status_code != 200:
        print("Failed to download file from URL")
        sys.exit(1)
    computed = hashlib.sha256(response.content).hexdigest()
    if computed != digest:
        print("SHA does not match")
        print(computed)
        sys.exit(1)

    genesis = await default_genesis_txns()
    if not genesis:
        print("Error retrieving ledger genesis transactions")
        sys.exit(1)

    agent = None
    exchange_tracing = False

    try:
        log_status("#1 Provision an agent and wallet, get back configuration details")
        agent = VSWAgent(
            start_port,
            start_port + 1,
            genesis_data=genesis,
            tails_server_base_url=tails_server_base_url,
            timing=show_timing,
        )
        await agent.listen_webhooks(start_port + 2)
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

        log_status("#13 Issue credential offer to repo")

        with log_timer("Publish cred def duration:"):
            log_status("* Create a new cred def on the ledger")
            credential_definition_id = await register_creddef(
                agent,
                f"{config['repo']}:2:vsw schema:0.2",
                support_revocation=revocation,
                revocation_registry_size=TAILS_FILE_COUNT,
            )

        agent.cred_attrs[credential_definition_id] = {
            "name": name,
            "url": url,
            "digest": digest,
            "timestamp": str(int(time.time())),
        }

        cred_preview = {
            "@type": CRED_PREVIEW_TYPE,
            "attributes": [
                {"name": n, "value": v}
                for (n, v) in agent.cred_attrs[credential_definition_id].items()
            ],
        }
        offer_request = {
            "connection_id": agent.connection_id,
            "cred_def_id": credential_definition_id,
            "comment": f"Offer on cred def id {credential_definition_id}",
            "auto_remove": False,
            "credential_preview": cred_preview,
            "trace": exchange_tracing,
        }
        await agent.admin_POST("/issue-credential/send-offer", offer_request)

        await agent.credential_complete()

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
        "--revocation", action="store_true", help="Enable credential revocation"
    )

    parser.add_argument(
        "--tails-server-base-url",
        type=str,
        metavar=("<tails-server-base-url>"),
        help="Tals server base url",
    )

    parser.add_argument(
        "--timing", action="store_true", help="Enable timing information"
    )

    parser.add_argument("name", type=str, help="App name to be published")

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

    tails_server_base_url = args.tails_server_base_url or os.getenv("PUBLIC_TAILS_URL")

    if args.revocation and not tails_server_base_url:
        raise Exception(
            "If revocation is enabled, --tails-server-base-url must be provided"
        )

    try:
        asyncio.get_event_loop().run_until_complete(
            main(
                args.name,
                args.port,
                args.revocation,
                tails_server_base_url,
                args.timing,
            )
        )
    except KeyboardInterrupt:
        os._exit(1)
